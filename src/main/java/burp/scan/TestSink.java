package burp.scan;

import burp.*;
import burp.ai.AITestingAgent;
import burp.engine.DetectionStage;
import burp.engine.StageListener;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Set;

/**
 * Shared probe-send loop: bounded parallel pool + rate limiter + dedup.
 * Reuses {@link AITestingAgent#buildModifiedRequest} for mutation and
 * {@code callbacks.makeHttpRequest} to send. Emits StageListener test events.
 *
 * @author Zahid Eroglu
 */
public class TestSink {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AITestingAgent mutator;
    private final StageListener listener;
    private final PrintWriter stderr;
    private final ExecutorService pool;
    private final int maxReqPerSec;
    // Shared site-wide throttle (per-minute budget + per-second smoothing). When present, ALL probe
    // sends go through it so the deterministic engine shares one global budget with agents/recon/matrix
    // instead of running its own independent RPS stream (the old WAF/FW burst source).
    private final burp.engine.SharedRateLimiter shared;

    // Wall-clock bound on each send so a WAF blackhole (silent drop → ~600s socket hang) can't tie up a
    // scan thread for 10 minutes. Daemon cached pool: a stalled native call expires in the background.
    private static final long BOUNDED_TIMEOUT_MS = 25_000L; // normal responses are <2s
    private static final ExecutorService BOUNDED = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "testsink-bounded-send");
        t.setDaemon(true);
        return t;
    });

    private final Set<String> seen = ConcurrentHashMap.newKeySet();
    private final Object rateLock = new Object();
    private long nextSlotNanos = 0L;

    // 429 circuit-breaker: once the target rate-limits, stop hammering it. Saves requests
    // and avoids FPs (e.g. timing probes seeing inflated latency from the rate limiter).
    private volatile boolean rateLimited = false;
    private final AtomicInteger seen429 = new AtomicInteger(0);
    private final AtomicInteger skipped = new AtomicInteger(0);

    public TestSink(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, AITestingAgent mutator,
                    StageListener listener, int parallelism, int maxReqPerSec,
                    burp.engine.SharedRateLimiter shared, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.mutator = mutator;
        this.listener = listener;
        this.stderr = stderr;
        this.maxReqPerSec = maxReqPerSec > 0 ? maxReqPerSec : 8;
        this.shared = shared;
        this.pool = Executors.newFixedThreadPool(Math.max(1, parallelism));
    }

    /** Send all probes in parallel (deduped, rate-limited), gather results. */
    public List<ProbeResult> sendAll(IHttpRequestResponse base, List<Probe> probes) {
        List<Future<ProbeResult>> futures = new ArrayList<>();
        for (Probe p : probes) {
            String key = p.rawRequest != null
                    ? "raw|" + p.description
                    : p.location + "|" + p.targetParameter + "|" + p.payload;
            if (!seen.add(key)) {
                continue; // dedup across modules
            }
            final Probe probe = p;
            futures.add(pool.submit(() -> sendOne(base, probe)));
        }
        List<ProbeResult> out = new ArrayList<>();
        for (Future<ProbeResult> f : futures) {
            try {
                ProbeResult r = f.get();
                if (r != null) out.add(r);
            } catch (Exception e) {
                if (stderr != null) stderr.println("[TestSink] " + e.getMessage());
            }
        }
        return out;
    }

    private ProbeResult sendOne(IHttpRequestResponse base, Probe probe) {
        ProbeResult r = new ProbeResult();
        r.probe = probe;
        burp.IHttpService svc = (probe.overrideService != null)
                ? probe.overrideService : base.getHttpService();
        String host = (svc != null) ? svc.getHost() : null;
        // Don't send into a target that is already rate-limiting (429) or WAF-blocking us — fast-fail so
        // we never pile blackholed (HTTP 0 / ~600s) requests and never escalate toward a firewall IP ban.
        if (rateLimited || (shared != null && shared.isHostBlocked(host))) {
            r.error = "atlandı: hedef engelliyor (rate-limit / WAF)";
            skipped.incrementAndGet();
            return r;
        }
        int rowId = -1;
        if (listener != null) {
            rowId = listener.onTestStarted2(probe.description, probe.location, probe.targetParameter, probe.payload);
        }
        try {
            rateLimit();
            byte[] req = (probe.rawRequest != null)
                    ? probe.rawRequest
                    : mutator.buildModifiedRequest(base, toPlannedTest(probe));
            if (req == null) {
                r.error = "build failed (location=" + probe.location + ")";
            } else {
                r.rawRequest = req;
                long t0 = System.nanoTime();
                IHttpRequestResponse rr = boundedRequest(svc, req); // null => stalled/blackholed (WAF drop)
                r.responseTimeMs = (System.nanoTime() - t0) / 1_000_000L;
                byte[] resp = (rr == null) ? null : rr.getResponse();
                r.rawResponse = resp;
                if (resp != null) {
                    IResponseInfo ri = helpers.analyzeResponse(resp);
                    r.statusCode = ri.getStatusCode();
                    int off = ri.getBodyOffset();
                    r.responseLength = Math.max(0, resp.length - off);
                    r.responseHeaders = String.join("\n", ri.getHeaders());
                    r.bodySnippet = new String(resp, off, Math.min(8192, resp.length - off));
                } else if (r.error == null) {
                    r.error = "yanıt yok (drop/timeout)"; // HTTP 0: WAF blackhole or network drop
                }
                // Feed the shared per-host WAF breaker (HTTP 0 / stall / block page / 403-429-503). It slows
                // on the first signal and trips (halts the host) on the threshold — across ALL engines.
                if (shared != null && host != null && shared.noteResult(host, r.statusCode, r.responseTimeMs, r.bodySnippet)) {
                    rateLimited = true; // stop this sink immediately too
                    if (listener != null) listener.onStageProgress(DetectionStage.EXECUTE,
                            "⛔ WAF " + host + " üzerinde istekleri düşürüyor/engelliyor — bu host için kalan "
                                    + "probe'lar atlanıyor (IP ban'ine tırmanmayı önlemek için).");
                }
            }
        } catch (Exception e) {
            r.error = e.getMessage();
            // A send exception (reset/timeout) is itself a block/network signal.
            if (shared != null && host != null) shared.noteResult(host, 0, r.responseTimeMs, null);
        }
        if (listener != null) {
            String status = r.error != null
                    ? ("error: " + r.error)
                    : ("HTTP " + r.statusCode + " · " + r.responseLength + "b · " + r.responseTimeMs + "ms");
            listener.onTestFinished2(rowId, status);
            listener.onTestResult(rowId, r.rawRequest, r.rawResponse);
        }
        return r;
    }

    /** Send with a hard wall-clock bound so a WAF blackhole (silent drop → ~600s socket hang) frees the
     *  scan thread in seconds and surfaces as HTTP 0. The underlying Burp request may finish later on the
     *  daemon pool; we just stop waiting. */
    private IHttpRequestResponse boundedRequest(burp.IHttpService svc, byte[] req) {
        Future<IHttpRequestResponse> f = BOUNDED.submit(() -> callbacks.makeHttpRequest(svc, req));
        try {
            return f.get(BOUNDED_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            f.cancel(true);   // abandon the wait (the native call may still be blackholed in the background)
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private void rateLimit() {
        // Prefer the shared site-wide throttle so the deterministic engine shares ONE global budget.
        if (shared != null) {
            shared.acquire();
            return;
        }
        synchronized (rateLock) {
            long interval = 1_000_000_000L / maxReqPerSec;
            long now = System.nanoTime();
            if (now < nextSlotNanos) {
                long waitMs = (nextSlotNanos - now) / 1_000_000L;
                if (waitMs > 0) {
                    try { Thread.sleep(waitMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                }
                now = System.nanoTime();
            }
            nextSlotNanos = Math.max(now, nextSlotNanos) + interval;
        }
    }

    private AITestingAgent.PlannedTest toPlannedTest(Probe p) {
        AITestingAgent.PlannedTest t = new AITestingAgent.PlannedTest();
        t.description = p.description;
        t.attackType = p.attackType;
        t.targetParameter = p.targetParameter;
        t.payload = p.payload;
        t.location = p.location;
        t.expectedBehavior = "";
        t.vulnerableIf = "";
        return t;
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
