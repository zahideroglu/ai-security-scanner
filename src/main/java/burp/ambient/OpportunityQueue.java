package burp.ambient;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Priority queue of {@link Opportunity}s ordered by score (desc) then creation
 * order (asc). The hunter polls it; the Copilot table reads a snapshot. Endpoints
 * are deduped/merged per host via {@link TargetModel.HostInfo#endpoints}, so the
 * queue never holds two entries for the same method+path.
 *
 * @author Zahid Eroglu
 */
public final class OpportunityQueue {

    private static final int MAX = 500;

    private static final Comparator<Opportunity> ORDER =
            Comparator.<Opportunity>comparingInt(o -> -o.score).thenComparingLong(o -> o.seq);

    private final TargetModel model;
    private final PriorityBlockingQueue<Opportunity> pq =
            new PriorityBlockingQueue<Opportunity>(64, ORDER);

    public OpportunityQueue(TargetModel model) {
        this.model = model;
    }

    /**
     * Add a new opportunity, or merge it into the existing same-endpoint one
     * (take the max score, union the suspected classes). Newly-added items are
     * marked QUEUED and pushed onto the priority queue for the hunter.
     */
    public synchronized void offerOrMerge(Opportunity op) {
        TargetModel.HostInfo h = model.host(op.host);
        Opportunity existing = h.endpoints.get(op.dedupKey());
        if (existing != null) {
            if (op.score > existing.score) {
                existing.score = op.score;
            }
            existing.addClasses(op.getSuspectedClasses());
            if (op.rationale != null && !op.rationale.isEmpty()) {
                existing.rationale = op.rationale;
            }
            // Do not requeue an endpoint already RUNNING/DONE/IGNORED; merge is enough.
            return;
        }
        h.endpoints.put(op.dedupKey(), op);
        op.status = Opportunity.Status.QUEUED;
        pq.offer(op);
        enforceCap();
    }

    /** Hunter side: block up to {@code timeout} for the next highest-priority opportunity. */
    public Opportunity poll(long timeout, TimeUnit unit) throws InterruptedException {
        return pq.poll(timeout, unit);
    }

    /** EDT side: an ordered copy of ALL endpoints across hosts (every status) for the table. */
    public List<Opportunity> snapshot() {
        List<Opportunity> out = new ArrayList<Opportunity>();
        for (TargetModel.HostInfo h : model.hostsSnapshot()) {
            out.addAll(h.endpoints.values());
        }
        out.sort(ORDER);
        return out;
    }

    public void markIgnored(String host, String dedupKey) {
        TargetModel.HostInfo h = model.peek(host);
        if (h == null) return;
        Opportunity op = h.endpoints.get(dedupKey);
        if (op != null) {
            op.status = Opportunity.Status.IGNORED;
            pq.remove(op);
        }
    }

    public void markDone(Opportunity op) {
        if (op != null) op.status = Opportunity.Status.DONE;
    }

    /**
     * Hunter side: the AI back-end was unusable for this endpoint — put it back on the queue
     * (status → QUEUED) so it is retried later. The op is already in the host endpoint map, so
     * this only re-offers the same object to the priority queue (no duplicate entry).
     */
    public synchronized void requeue(Opportunity op) {
        if (op == null) return;
        op.status = Opportunity.Status.QUEUED;
        pq.offer(op);
        enforceCap();
    }

    public int queueDepth() {
        return pq.size();
    }

    /** Bound memory: keep only the top {@code MAX} queued items, drop the lowest-scoring. */
    private void enforceCap() {
        if (pq.size() <= MAX) return;
        List<Opportunity> all = new ArrayList<Opportunity>();
        pq.drainTo(all);
        all.sort(ORDER);
        for (int i = 0; i < Math.min(MAX, all.size()); i++) {
            pq.offer(all.get(i));
        }
    }
}
