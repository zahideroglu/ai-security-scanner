package burp.ambient;

import burp.IHttpRequestResponse;

import java.io.PrintWriter;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the single passive-triage worker thread and the bounded hand-off queue.
 * {@link #onProxyResponse} is the only entry point from Burp's proxy thread and
 * MUST return in microseconds — it just offers the message to a bounded queue and
 * drops it if the queue is full (back-pressure under heavy browsing). All parsing,
 * scoring and model updates happen on the worker, never on the proxy thread, and
 * never call the network or the LLM.
 *
 * @author Zahid Eroglu
 */
public final class AmbientCoordinator {

    private final PassiveTriage triage;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final BlockingQueue<IHttpRequestResponse> work = new ArrayBlockingQueue<IHttpRequestResponse>(256);
    private final AtomicLong dropped = new AtomicLong();
    private volatile boolean running;
    private Thread worker;

    public AmbientCoordinator(PassiveTriage triage, PrintWriter stdout, PrintWriter stderr) {
        this.triage = triage;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public synchronized void start() {
        if (running) return;
        running = true;
        worker = new Thread(this::drain, "ambient-triage");
        worker.setDaemon(true);
        worker.start();
        if (stdout != null) stdout.println("[ambient] passive triage started");
    }

    public synchronized void stop() {
        running = false;
        if (worker != null) worker.interrupt();
        if (stdout != null) stdout.println("[ambient] passive triage stopped");
    }

    public boolean isRunning() {
        return running;
    }

    /** Called from Burp's proxy thread — non-blocking; drops under load. */
    public void onProxyResponse(IHttpRequestResponse msg) {
        if (!running || msg == null) return;
        if (!work.offer(msg)) {
            dropped.incrementAndGet();
        }
    }

    public long droppedCount() {
        return dropped.get();
    }

    private void drain() {
        while (running) {
            try {
                IHttpRequestResponse msg = work.poll(500, TimeUnit.MILLISECONDS);
                if (msg == null) continue;
                triage.consider(msg);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                if (stderr != null) stderr.println("[ambient] worker error: " + e.getMessage());
            }
        }
    }
}
