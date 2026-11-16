package burp.ambient;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class OpportunityQueueTest {

    private Opportunity op(String host, String method, String path, int score, String... classes) {
        Opportunity o = new Opportunity(host, method, path, "https://" + host + path,
                ("GET " + path).getBytes(), null);
        o.score = score;
        o.addClasses(java.util.Arrays.asList(classes));
        return o;
    }

    @Test
    void mergesSameEndpointInsteadOfDuplicating() {
        TargetModel model = new TargetModel();
        OpportunityQueue q = new OpportunityQueue(model);

        q.offerOrMerge(op("h", "GET", "/api/x", 40, "IDOR/BOLA"));
        q.offerOrMerge(op("h", "GET", "/api/x", 70, "Auth/JWT")); // same endpoint, higher score + new class

        List<Opportunity> snap = q.snapshot();
        assertEquals(1, snap.size(), "same method+path must merge to one entry");
        Opportunity merged = snap.get(0);
        assertEquals(70, merged.score, "merge keeps the max score");
        assertTrue(merged.hasClass("IDOR/BOLA") && merged.hasClass("Auth/JWT"), "merge unions classes");
        assertEquals(1, q.queueDepth(), "queue holds a single item for the endpoint");
    }

    @Test
    void pollReturnsHighestScoreFirst() throws InterruptedException {
        TargetModel model = new TargetModel();
        OpportunityQueue q = new OpportunityQueue(model);
        q.offerOrMerge(op("h", "GET", "/low", 20));
        q.offerOrMerge(op("h", "GET", "/high", 90));
        q.offerOrMerge(op("h", "GET", "/mid", 50));

        assertEquals("/high", q.poll(1, TimeUnit.SECONDS).path);
        assertEquals("/mid", q.poll(1, TimeUnit.SECONDS).path);
        assertEquals("/low", q.poll(1, TimeUnit.SECONDS).path);
    }

    @Test
    void markIgnoredRemovesFromQueueButKeepsInSnapshot() {
        TargetModel model = new TargetModel();
        OpportunityQueue q = new OpportunityQueue(model);
        q.offerOrMerge(op("h", "POST", "/buy", 60));

        q.markIgnored("h", "POST /buy");
        assertEquals(0, q.queueDepth(), "ignored item leaves the poll queue");
        List<Opportunity> snap = q.snapshot();
        assertEquals(1, snap.size());
        assertEquals(Opportunity.Status.IGNORED, snap.get(0).status);
    }

    @Test
    void newItemIsMarkedQueued() {
        TargetModel model = new TargetModel();
        OpportunityQueue q = new OpportunityQueue(model);
        Opportunity o = op("h", "GET", "/a", 45);
        assertEquals(Opportunity.Status.NEW, o.status);
        q.offerOrMerge(o);
        assertEquals(Opportunity.Status.QUEUED, o.status);
    }
}
