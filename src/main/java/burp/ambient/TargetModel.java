package burp.ambient;

import burp.ai.ContextInfo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Per-host knowledge the ambient copilot accumulates while the user browses:
 * endpoints seen, parameter names, auth scheme, roles, cached recon context, and
 * (Phase 7) per-vuln-class confirmed/false-positive counters used to learn what is
 * fruitful on this target. Thread-safe: written from the triage worker + hunter
 * threads, read from the EDT.
 *
 * @author Zahid Eroglu
 */
public final class TargetModel {

    public static final class HostInfo {
        public final String host;
        /** key = method+path → the opportunity (also the queue's dedup index). */
        public final ConcurrentMap<String, Opportunity> endpoints = new ConcurrentHashMap<String, Opportunity>();
        public final Set<String> paramNames = ConcurrentHashMap.newKeySet();
        public final Set<String> rolesSeen = ConcurrentHashMap.newKeySet();
        public volatile String authScheme;        // "Bearer" | "Cookie" | "ApiKey" | null
        public volatile ContextInfo context;       // cached recon (set lazily by the hunter)
        /** vulnClass → {confirmed, falsePositive}. */
        public final ConcurrentMap<String, int[]> classStats = new ConcurrentHashMap<String, int[]>();

        HostInfo(String host) {
            this.host = host;
        }

        public void recordConfirmed(String vulnClass) {
            int[] s = classStats.computeIfAbsent(vulnClass, k -> new int[2]);
            synchronized (s) { s[0]++; }
        }

        public void recordFp(String vulnClass) {
            int[] s = classStats.computeIfAbsent(vulnClass, k -> new int[2]);
            synchronized (s) { s[1]++; }
        }

        /** Fraction of reports for this class that turned out to be false positives (0 if unknown). */
        public double fpRatio(String vulnClass) {
            int[] s = classStats.get(vulnClass);
            if (s == null) return 0.0;
            synchronized (s) {
                int total = s[0] + s[1];
                return total == 0 ? 0.0 : (double) s[1] / total;
            }
        }

        public boolean wasConfirmed(String vulnClass) {
            int[] s = classStats.get(vulnClass);
            if (s == null) return false;
            synchronized (s) { return s[0] > 0; }
        }
    }

    private final ConcurrentMap<String, HostInfo> hosts = new ConcurrentHashMap<String, HostInfo>();

    /** Get-or-create the host record. */
    public HostInfo host(String h) {
        return hosts.computeIfAbsent(h, HostInfo::new);
    }

    /** Read-only peek: null if the host has not been seen yet. */
    public HostInfo peek(String h) {
        return hosts.get(h);
    }

    public Collection<HostInfo> hostsSnapshot() {
        return new ArrayList<HostInfo>(hosts.values());
    }

    public int hostCount() {
        return hosts.size();
    }
}
