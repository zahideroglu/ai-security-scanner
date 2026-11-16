package burp.engine;

import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Site-wide outbound request throttle shared by EVERY target-request path (deterministic probes,
 * agents, recon, auth-matrix, session replays). Enforces two limits together so the footprint stays
 * under both a firewall's per-minute session cap and a WAF's burst cap:
 *
 *   (1) a HARD per-minute budget  — sliding 60s window; the firewall guard (an IP that exceeds the
 *       firewall's sessions/min gets banned for a day, so this must never be crossed), and
 *   (2) per-second smoothing       — minimum spacing between grants, plus small random jitter,
 *
 * so requests spread evenly over time and never arrive in robotic, periodic bursts. {@link #acquire}
 * BLOCKS until a slot is free under BOTH limits (work is delayed, never dropped). A transient WAF
 * block signal can temporarily widen the spacing via {@link #enterSlowMode}.
 *
 * Grants are serialized on one monitor so the per-minute budget is exact across all concurrent
 * callers (the per-instance limiters it replaces would otherwise allow N×rate).
 *
 * @author Zahid Eroglu
 */
public final class SharedRateLimiter {

    private static final long ONE_MINUTE_NANOS = 60_000_000_000L;

    private final Object lock = new Object();
    private final int maxPerMinute;
    private final long minIntervalNanos;                          // per-second smoothing
    private final ArrayDeque<Long> window = new ArrayDeque<>();   // grant timestamps (nanos) within the last 60s
    private long nextSlotNanos = 0L;                              // earliest the next grant may happen
    private long slowModeUntilNanos = 0L;                         // while now < this, add slowModeExtraNanos
    private long slowModeExtraNanos = 0L;

    /** Back-compat: per-second only (per-minute derived as rps*60 so this limit alone binds). */
    public SharedRateLimiter(int requestsPerSecond) {
        this(requestsPerSecond > 0 ? requestsPerSecond * 60 : 300, requestsPerSecond);
    }

    public SharedRateLimiter(int requestsPerMinute, int requestsPerSecond) {
        int rpm = requestsPerMinute > 0 ? requestsPerMinute : 150;
        int rps = requestsPerSecond > 0 ? requestsPerSecond : 5;
        this.maxPerMinute = rpm;
        this.minIntervalNanos = 1_000_000_000L / rps;
    }

    /** Block until a slot is free under BOTH the per-minute budget and per-second spacing, then reserve it. */
    public void acquire() {
        synchronized (lock) {
            while (true) {
                long now = System.nanoTime();
                // Age out timestamps older than 60s from the sliding window.
                while (!window.isEmpty() && now - window.peekFirst() >= ONE_MINUTE_NANOS) {
                    window.pollFirst();
                }
                // (1) Per-minute budget: window full -> wait until the oldest grant ages out, then re-evaluate.
                if (window.size() >= maxPerMinute) {
                    sleepNanos(ONE_MINUTE_NANOS - (now - window.peekFirst()) + 1_000_000L);
                    continue;
                }
                // (2) Per-second smoothing (+ slow-mode + jitter scheduled into nextSlotNanos).
                if (now < nextSlotNanos) {
                    sleepNanos(nextSlotNanos - now);
                    continue;
                }
                // Grant: record it and schedule the earliest next grant.
                window.addLast(now);
                long extra = (now < slowModeUntilNanos) ? slowModeExtraNanos : 0L;
                long jitter = ThreadLocalRandom.current().nextLong((minIntervalNanos / 2) + 1); // 0..50% of interval
                nextSlotNanos = now + minIntervalNanos + extra + jitter;
                return;
            }
        }
    }

    /** Temporarily widen request spacing (e.g. after a WAF block signal). Additive and time-boxed. */
    public void enterSlowMode(long extraMillisPerRequest, long durationMillis) {
        synchronized (lock) {
            this.slowModeExtraNanos = Math.max(0L, extraMillisPerRequest) * 1_000_000L;
            this.slowModeUntilNanos = System.nanoTime() + Math.max(0L, durationMillis) * 1_000_000L;
        }
    }

    /** Configured per-minute ceiling (for logging/verification). */
    public int maxPerMinute() {
        return maxPerMinute;
    }

    // ===== Per-host WAF circuit breaker ==================================================
    // A WAF that silently DROPS requests (the Gateway case: HTTP 0 / 0-byte / ~600s hang, no
    // 403/429) will blackhole every probe once tripped. We watch responses per host: the FIRST block
    // signal widens spacing (proactive de-escalation), and after `wafThreshold` signals the host is
    // TRIPPED — all senders then fast-fail it (isHostBlocked) instead of piling 10-min hangs and
    // risking escalation to a firewall IP ban.

    private static final long STALL_NANOS = 20_000_000_000L;          // a response >=20s ≈ WAF blackhole
    private static final long WAF_COOLDOWN_NANOS = 15L * 60_000_000_000L; // halt a tripped host ~15 min

    private final Map<String, HostState> hosts = new ConcurrentHashMap<>();
    private volatile int wafThreshold = 3;
    private volatile long slowExtraMillis = 4000L;

    private static final class HostState {
        int blockSignals;
        long trippedUntilNanos;
    }

    /** Wire the WAF breaker from settings (wafDetectionThreshold, slowModeDelayMs). */
    public void configureWaf(int threshold, long slowExtraMillis) {
        this.wafThreshold = threshold > 0 ? threshold : 3;
        this.slowExtraMillis = slowExtraMillis > 0 ? slowExtraMillis : 4000L;
    }

    /** True once a host has tripped the breaker — senders MUST skip it (fast-fail, no blackhole). */
    public boolean isHostBlocked(String host) {
        if (host == null) return false;
        HostState st = hosts.get(host);
        return st != null && System.nanoTime() < st.trippedUntilNanos;
    }

    /**
     * Feed every target response here. Detects WAF block signals (no response / stall / block page /
     * 403-429-503), slows on the first and trips (halts) the host on the {@code wafThreshold}-th.
     * A clean response decays the counter so isolated blips don't accumulate.
     *
     * @return true iff THIS result just tripped the host (caller should log the halt once).
     */
    public boolean noteResult(String host, int status, long respTimeMs, String bodySnippet) {
        if (host == null) return false;
        boolean signal = status == 0 || status == 403 || status == 429 || status == 503
                || respTimeMs >= STALL_NANOS / 1_000_000L
                || (bodySnippet != null && burp.scan.Signals.looksLikeBlockPage(bodySnippet));
        HostState st = hosts.computeIfAbsent(host, k -> new HostState());
        synchronized (st) {
            if (!signal) {
                if (st.blockSignals > 0) st.blockSignals--;   // decay on healthy traffic
                return false;
            }
            st.blockSignals++;
            if (st.blockSignals == 1) {
                enterSlowMode(slowExtraMillis, 60_000L);        // proactive: widen spacing on first sign
            }
            if (st.blockSignals >= wafThreshold && System.nanoTime() >= st.trippedUntilNanos) {
                st.trippedUntilNanos = System.nanoTime() + WAF_COOLDOWN_NANOS; // halt this host
                return true;
            }
            return false;
        }
    }

    /** Sleep the given nanos while holding the monitor on purpose — grants stay serialized so the
     *  global per-minute budget is exact across all concurrent callers. */
    private void sleepNanos(long nanos) {
        if (nanos <= 0) return;
        try {
            Thread.sleep(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
