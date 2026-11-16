package burp.ambient;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One endpoint the ambient copilot thinks is worth testing — produced by
 * {@link PassiveTriage}, surfaced in the Copilot "Fırsatlar" table, and popped by
 * the {@link BackgroundHunter}. Holds a byte-snapshot of the request (not a live
 * {@code IHttpRequestResponse}) so it survives the proxy thread; the engines need
 * only {@code makeHttpRequest(service, requestBytes)} anyway.
 *
 * @author Zahid Eroglu
 */
public final class Opportunity {

    public enum Status { NEW, QUEUED, RUNNING, DONE, IGNORED }

    private static final AtomicLong SEQ = new AtomicLong();

    public final long seq;          // stable FIFO tiebreak for the priority queue
    public final long createdAt;
    public final String host;
    public final String method;
    public final String path;
    public final String url;
    public final byte[] request;    // snapshot for re-dispatch
    public final IHttpService service;

    private final Set<String> suspectedClasses = Collections.synchronizedSet(new LinkedHashSet<String>());
    public volatile int score;
    public volatile String rationale = "";
    public volatile Status status = Status.NEW;
    public volatile int attempts = 0;   // hunter retries after an AI outage (requeue + retry later)

    public Opportunity(String host, String method, String path, String url,
                       byte[] request, IHttpService service) {
        this.seq = SEQ.incrementAndGet();
        this.createdAt = System.currentTimeMillis();
        this.host = host;
        this.method = method;
        this.path = path;
        this.url = url;
        this.request = request;
        this.service = service;
    }

    /**
     * Per-host merge key: the same endpoint TEMPLATE is the same opportunity. Dynamic path
     * segments (numeric ids, UUIDs, hashes) are normalized to {@code {id}} so the hunter runs
     * the AI once per endpoint shape instead of once per concrete id (e.g. {@code /accounts/1001},
     * {@code /accounts/1002}, … all collapse to {@code GET /accounts/{id}}).
     */
    public String dedupKey() {
        return burp.scan.EndpointKey.of(method, path);
    }

    public void addClasses(Collection<String> classes) {
        if (classes != null) {
            suspectedClasses.addAll(classes);
        }
    }

    public List<String> getSuspectedClasses() {
        synchronized (suspectedClasses) {
            return new ArrayList<String>(suspectedClasses);
        }
    }

    public boolean hasClass(String c) {
        return suspectedClasses.contains(c);
    }

    /** Rebuild a lightweight IHttpRequestResponse from the snapshot for engine dispatch. */
    public IHttpRequestResponse toRequestResponse() {
        return new IHttpRequestResponse() {
            private byte[] req = request;
            private byte[] resp = null;
            private IHttpService svc = service;
            private String comment;
            private String highlight;

            @Override public byte[] getRequest() { return req; }
            @Override public void setRequest(byte[] message) { this.req = message; }
            @Override public byte[] getResponse() { return resp; }
            @Override public void setResponse(byte[] message) { this.resp = message; }
            @Override public String getComment() { return comment; }
            @Override public void setComment(String comment) { this.comment = comment; }
            @Override public String getHighlight() { return highlight; }
            @Override public void setHighlight(String color) { this.highlight = color; }
            @Override public IHttpService getHttpService() { return svc; }
            @Override public void setHttpService(IHttpService httpService) { this.svc = httpService; }
        };
    }
}
