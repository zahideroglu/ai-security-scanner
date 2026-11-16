package burp;

import org.json.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Process-wide AI/LLM usage counter. Records how many chat-completion calls were
 * actually sent to the API and how many tokens they consumed (from the response's
 * {@code usage} object). Cache hits are counted separately because they cost no
 * tokens. Totals are persisted via Burp's extension settings so they survive
 * extension reloads, and can be reset from the Settings panel.
 *
 * Thread-safe: scans run on bounded thread pools, so counters are atomic and the
 * persist step is synchronized.
 *
 * @author Zahid Eroglu
 */
public class AIUsageStats {

    private static final String KEY = "ai_usage_stats";
    private static final AIUsageStats INSTANCE = new AIUsageStats();

    public static AIUsageStats getInstance() {
        return INSTANCE;
    }

    private IBurpExtenderCallbacks callbacks;

    private final AtomicLong totalCalls = new AtomicLong();
    private final AtomicLong promptTokens = new AtomicLong();
    private final AtomicLong completionTokens = new AtomicLong();
    private final AtomicLong totalTokens = new AtomicLong();
    private final AtomicLong cacheHits = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private volatile long sinceMs = 0L; // when counting started (or last reset)
    private volatile long lastMs = 0L;  // last recorded API call

    private AIUsageStats() {
    }

    /** Wire up persistence and load any previously stored totals. Call once at startup. */
    public synchronized void init(IBurpExtenderCallbacks cb) {
        this.callbacks = cb;
        try {
            String s = cb.loadExtensionSetting(KEY);
            if (s != null && !s.isEmpty()) {
                JSONObject j = new JSONObject(s);
                totalCalls.set(j.optLong("totalCalls"));
                promptTokens.set(j.optLong("promptTokens"));
                completionTokens.set(j.optLong("completionTokens"));
                totalTokens.set(j.optLong("totalTokens"));
                cacheHits.set(j.optLong("cacheHits"));
                failures.set(j.optLong("failures"));
                sinceMs = j.optLong("since", 0L);
                lastMs = j.optLong("last", 0L);
            }
        } catch (Exception ignore) {
        }
    }

    /** Record one real (non-cached) API response, adding its token usage if present. */
    public void recordResponse(JSONObject response) {
        long p = 0, c = 0, t = 0;
        if (response != null) {
            JSONObject usage = findUsage(response);
            if (usage != null) {
                p = usage.optLong("prompt_tokens", 0);
                c = usage.optLong("completion_tokens", 0);
                t = usage.optLong("total_tokens", 0);
                if (t == 0) {
                    t = p + c;
                }
            }
        }
        totalCalls.incrementAndGet();
        promptTokens.addAndGet(p);
        completionTokens.addAndGet(c);
        totalTokens.addAndGet(t);
        stampAndPersist();
    }

    /** A prompt was served from the local cache — no tokens spent. */
    public void recordCacheHit() {
        cacheHits.incrementAndGet();
        persist();
    }

    /** An API call failed (network error, non-200, etc.). */
    public void recordFailure() {
        failures.incrementAndGet();
        stampAndPersist();
    }

    public synchronized void reset() {
        totalCalls.set(0);
        promptTokens.set(0);
        completionTokens.set(0);
        totalTokens.set(0);
        cacheHits.set(0);
        failures.set(0);
        sinceMs = 0L;
        lastMs = 0L;
        persist();
    }

    private synchronized void stampAndPersist() {
        long now = System.currentTimeMillis();
        if (sinceMs == 0L) {
            sinceMs = now;
        }
        lastMs = now;
        persist();
    }

    private synchronized void persist() {
        IBurpExtenderCallbacks cb = this.callbacks;
        if (cb == null) {
            return;
        }
        try {
            JSONObject j = new JSONObject();
            j.put("totalCalls", totalCalls.get());
            j.put("promptTokens", promptTokens.get());
            j.put("completionTokens", completionTokens.get());
            j.put("totalTokens", totalTokens.get());
            j.put("cacheHits", cacheHits.get());
            j.put("failures", failures.get());
            j.put("since", sinceMs);
            j.put("last", lastMs);
            cb.saveExtensionSetting(KEY, j.toString());
        } catch (Exception ignore) {
        }
    }

    /**
     * Locate the {@code usage} object: OpenAI-compatible responses carry it at the
     * top level; some provider wrappers nest it one level down.
     */
    private JSONObject findUsage(JSONObject root) {
        JSONObject u = root.optJSONObject("usage");
        if (u != null) {
            return u;
        }
        java.util.Iterator<String> it = root.keys();
        while (it.hasNext()) {
            JSONObject child = root.optJSONObject(it.next());
            if (child != null) {
                JSONObject cu = child.optJSONObject("usage");
                if (cu != null) {
                    return cu;
                }
            }
        }
        return null;
    }

    public long getTotalCalls() { return totalCalls.get(); }
    public long getPromptTokens() { return promptTokens.get(); }
    public long getCompletionTokens() { return completionTokens.get(); }
    public long getTotalTokens() { return totalTokens.get(); }
    public long getCacheHits() { return cacheHits.get(); }
    public long getFailures() { return failures.get(); }
    public long getSinceMs() { return sinceMs; }
    public long getLastMs() { return lastMs; }
}
