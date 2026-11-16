package burp.ambient;

import burp.AIUsageStats;
import burp.DetectionPanel;
import burp.DetectionRunView;
import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.MultiSessionTester;
import burp.QwenAPIClient;
import burp.ScanManager;
import burp.Settings;
import burp.engine.SharedRateLimiter;
import burp.scan.ActiveScanEngine;

import javax.swing.SwingUtilities;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The autonomous, budgeted background hunter. A single scheduler thread pops the
 * {@link OpportunityQueue} and dispatches each endpoint to the right engine —
 * deterministic {@link ActiveScanEngine} for signature classes, the agentic
 * {@link SiteAgentOrchestrator} (playbook-specialized, force-safe) for logic/authz.
 * A bounded pool runs up to {@code agentSiteConcurrency} endpoints at once; all
 * outbound HTTP shares one {@link SharedRateLimiter}. Hunting stops when the token
 * budget ({@code agentSiteTokenBudget}, measured as a delta of the global
 * {@link AIUsageStats} counter) or the time budget ({@code agentSiteTimeBudgetMin})
 * is exhausted, or on pause/kill.
 *
 * Safety: scope-only by default (fail-closed), force-safe-mode (never raw/state-
 * changing), and aggressive modules are never run autonomously.
 *
 * @author Zahid Eroglu
 */
public final class BackgroundHunter {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final QwenAPIClient ai;
    private final Settings settings;
    private final ScanManager scanManager;
    private final MultiSessionTester sessions;
    private final OpportunityQueue queue;
    private final TargetModel model;
    private final SharedRateLimiter limiter;
    private final DetectionPanel detectionPanel;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final Set<String> reportedKeys = Collections.synchronizedSet(new HashSet<String>());
    private final java.util.Map<String, burp.authz.AccessModel> accessModels =
            Collections.synchronizedMap(new java.util.HashMap<String, burp.authz.AccessModel>());
    private final AtomicLong tokenStart = new AtomicLong();
    private final AtomicInteger active = new AtomicInteger();
    private volatile long deadlineMs = Long.MAX_VALUE;
    private volatile boolean running;
    private volatile boolean paused;
    private Thread scheduler;
    private ThreadPoolExecutor pool;
    private volatile DetectionRunView view; // shared live listener (abort plumbing + visibility)

    // Requeue + retry-later when the AI back-end is unusable (per-turn timeout / infra / sustained 429).
    private static final int  MAX_RETRY_ATTEMPTS  = 5;        // per endpoint, then give up
    private static final long AI_BACKOFF_BASE_MS  = 30_000L;  // first cool-off; doubles per consecutive outage
    private static final long AI_BACKOFF_MAX_MS   = 300_000L; // capped at 5 min
    private volatile long aiBackoffUntilMs = 0L;              // scheduler pauses dispatch until this time
    private final AtomicInteger consecAiOutages = new AtomicInteger();

    public BackgroundHunter(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, QwenAPIClient ai,
                            Settings settings, ScanManager scanManager, MultiSessionTester sessions,
                            OpportunityQueue queue, TargetModel model, SharedRateLimiter limiter,
                            DetectionPanel detectionPanel, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.ai = ai;
        this.settings = settings;
        this.scanManager = scanManager;
        this.sessions = sessions;
        this.queue = queue;
        this.model = model;
        this.limiter = limiter;
        this.detectionPanel = detectionPanel;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public synchronized void start() {
        if (running) return;
        running = true;
        paused = false;
        tokenStart.set(AIUsageStats.getInstance().getTotalTokens());
        int mins = settings.getAgentSiteTimeBudgetMin();
        deadlineMs = mins > 0 ? System.currentTimeMillis() + mins * 60_000L : Long.MAX_VALUE;
        int conc = Math.max(1, settings.getAgentSiteConcurrency());
        pool = new ThreadPoolExecutor(conc, conc, 30, TimeUnit.SECONDS,
                new ArrayBlockingQueue<Runnable>(Math.max(2, conc * 2)),
                r -> {
                    Thread t = new Thread(r, "ambient-hunter-w");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.CallerRunsPolicy());
        openView();
        scheduler = new Thread(this::loop, "ambient-hunter-sched");
        scheduler.setDaemon(true);
        scheduler.start();
        if (stdout != null) {
            stdout.println("[hunter] started (conc=" + conc + ", tokenBudget="
                    + settings.getAgentSiteTokenBudget() + ", timeMin=" + mins + ")");
        }
    }

    private void openView() {
        try {
            final DetectionRunView[] holder = new DetectionRunView[1];
            Runnable r = () -> holder[0] = detectionPanel.beginSite("Ambient Hunter");
            if (SwingUtilities.isEventDispatchThread()) r.run();
            else SwingUtilities.invokeAndWait(r);
            view = holder[0];
            if (view != null) view.prepareSiteScan("Ambient Hunter (otonom)", 0);
        } catch (Exception ignore) {
            view = null;
        }
    }

    private void loop() {
        int seed = 0;
        while (running) {
            try {
                if (paused || overBudget()) {
                    Thread.sleep(500);
                    continue;
                }
                if (System.currentTimeMillis() < aiBackoffUntilMs) {
                    Thread.sleep(500); // AI cooling-off after an outage — don't hammer a down/slow back-end
                    continue;
                }
                Opportunity op = queue.poll(500, TimeUnit.MILLISECONDS);
                if (op == null) continue;
                if (op.status != Opportunity.Status.QUEUED && op.status != Opportunity.Status.NEW) continue;
                if (!inScope(op)) { op.status = Opportunity.Status.IGNORED; continue; }
                if (deprioritized(op)) { op.status = Opportunity.Status.IGNORED; continue; }
                op.status = Opportunity.Status.RUNNING;
                final int s = seed++;
                pool.submit(() -> runOne(op, s));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                if (stderr != null) stderr.println("[hunter] loop error: " + e.getMessage());
            }
        }
    }

    private void runOne(Opportunity op, int seed) {
        active.incrementAndGet();
        boolean aiDown = false;
        try {
            IHttpRequestResponse base = op.toRequestResponse();
            if (isSignatureOnly(op)) {
                // Deterministic signature/misconfig pass is opt-in (default OFF = AI-only). A signature-only
                // (no-input) endpoint has nothing for the AI playbooks either, so just skip it when off.
                if (!settings.isHeuristicScanEnabled()) {
                    if (stdout != null) stdout.println("[hunter] atlandı (sadece-AI modu · signature-only): " + op.path);
                    return;
                }
                ActiveScanEngine engine = new ActiveScanEngine(callbacks, helpers, ai, settings, stdout, stderr, limiter);
                List<Finding> fs = engine.scan(base, "ambient-hunt", view);
                if (fs != null) {
                    for (Finding f : fs) {
                        scanManager.reportFindingDeduped(base, f, "ambient-hunt", "Ambient Hunter", reportedKeys);
                    }
                }
            } else if (isMutatingBase(op.method)) {
                // Ambient hunting is strictly read-only (forceSafeMode below). A mutating-method base can't
                // be agentically tested — every send is rejected by the engine's read-only guard — so skip
                // it instead of spending a full agent-step budget on 0 requests / 0 findings.
                if (stdout != null) stdout.println("[hunter] atlandı (salt-okunur mod · mutasyon metodu): "
                        + op.method + " " + op.path);
            } else {
                SiteAgentOrchestrator orch = new SiteAgentOrchestrator(callbacks, helpers, ai, settings,
                        scanManager, sessions, limiter, reportedKeys, stdout, stderr);
                orch.setForceSafeMode(true); // autonomy never more aggressive than a human scan
                burp.authz.AccessModel am = accessModelFor(op.host); // Faz 3: ground-truth BOLA in ambient
                if (am != null && am.totalObjects() > 0) orch.setAccessModel(am);
                orch.huntEndpoint(base, seed, view);
                aiDown = orch.wasAiUnavailable();
            }
        } catch (Exception e) {
            if (stderr != null) stderr.println("[hunter] runOne error: " + e.getMessage());
        } finally {
            if (aiDown && op.attempts < MAX_RETRY_ATTEMPTS) {
                // AI back-end was unusable — do NOT drop the endpoint: requeue it and cool off before retrying.
                op.attempts++;
                int n = consecAiOutages.incrementAndGet();
                long backoff = Math.min(AI_BACKOFF_MAX_MS, AI_BACKOFF_BASE_MS * (1L << Math.min(4, n - 1)));
                aiBackoffUntilMs = System.currentTimeMillis() + backoff;
                queue.requeue(op);
                if (stdout != null) stdout.println("[hunter] AI yanıt vermedi — '" + op.method + " " + op.path
                        + "' yeniden sıraya alındı (deneme " + op.attempts + "/" + MAX_RETRY_ATTEMPTS
                        + ", ~" + (backoff / 1000) + "sn sonra tekrar denenecek).");
            } else {
                if (aiDown && stdout != null) {
                    stdout.println("[hunter] '" + op.method + " " + op.path + "' — AI " + MAX_RETRY_ATTEMPTS
                            + " denemede de yanıt vermedi; şimdilik bırakıldı.");
                }
                if (!aiDown) consecAiOutages.set(0); // a clean run — reset the backoff escalation
                op.status = Opportunity.Status.DONE;
            }
            active.decrementAndGet();
        }
    }

    private boolean overBudget() {
        long budget = settings.getAgentSiteTokenBudget();
        if (budget > 0 && (AIUsageStats.getInstance().getTotalTokens() - tokenStart.get()) >= budget) {
            return true;
        }
        return System.currentTimeMillis() >= deadlineMs;
    }

    private boolean isSignatureOnly(Opportunity op) {
        List<String> cs = op.getSuspectedClasses();
        if (cs.isEmpty()) return false;
        for (String c : cs) {
            if (!PassiveTriage.C_MISCONFIG.equals(c)) return false;
        }
        return true;
    }

    /**
     * True when the endpoint's base method is state-changing (not GET/HEAD/OPTIONS). Mirrors
     * {@code AgentPentestEngine.isReadOnlyMethod} so the hunter skips exactly those endpoints the
     * read-only safe-mode agent could never send. An unknown/blank method is NOT treated as mutating
     * (the engine defaults it to GET), so it still gets a normal agent run.
     */
    private static boolean isMutatingBase(String method) {
        if (method == null || method.trim().isEmpty()) return false;
        return !(method.equalsIgnoreCase("GET")
                || method.equalsIgnoreCase("HEAD")
                || method.equalsIgnoreCase("OPTIONS"));
    }

    /** Scope-only gate (fail-closed): autonomy must stay in the authorized target. */
    private boolean inScope(Opportunity op) {
        if (!settings.isAmbientScopeOnly() && !settings.isUseBurpScope()) return true;
        try {
            return callbacks.isInScope(new URL(op.url));
        } catch (Exception e) {
            return false; // scope-only => fail closed
        }
    }

    /** Skip endpoints whose every suspected class has proven FP-heavy on this host. */
    private boolean deprioritized(Opportunity op) {
        TargetModel.HostInfo h = model.peek(op.host);
        if (h == null) return false;
        List<String> cs = op.getSuspectedClasses();
        if (cs.isEmpty()) return false;
        for (String c : cs) {
            if (h.fpRatio(c) < 0.8) return false; // at least one class still worth trying
        }
        return true;
    }

    /** Faz 3: build (once per host, cached) the ground-truth ownership model from proxy-history identities. */
    private burp.authz.AccessModel accessModelFor(String host) {
        if (host == null || host.isEmpty()) return null;
        burp.authz.AccessModel cached = accessModels.get(host);
        if (cached != null) return cached;
        try {
            burp.authz.SessionHarvester h = new burp.authz.SessionHarvester(callbacks, helpers, stdout);
            List<burp.authz.SessionHarvester.DiscoveredRole> roles = h.harvest(host);
            burp.authz.AccessModel built = (roles == null || roles.isEmpty())
                    ? new burp.authz.AccessModel()
                    : new burp.authz.AccessModelBuilder(callbacks, helpers, stdout).build(roles, false, limiter, null);
            accessModels.put(host, built);
            return built;
        } catch (Exception e) {
            accessModels.put(host, new burp.authz.AccessModel());
            return null;
        }
    }

    public void pause() { paused = true; }
    public void resume() { paused = false; }
    public boolean isPaused() { return paused; }
    public boolean isRunning() { return running; }

    public synchronized void kill() {
        running = false;
        if (view != null) {
            try { view.requestAbort(); } catch (Exception ignore) {}
        }
        if (pool != null) pool.shutdownNow();
        if (scheduler != null) scheduler.interrupt();
        if (stdout != null) stdout.println("[hunter] killed");
    }

    // ----- budget meter getters (for the Phase 8 UI) -----------------------

    public long tokensUsed() {
        return Math.max(0, AIUsageStats.getInstance().getTotalTokens() - tokenStart.get());
    }

    public long tokenBudget() { return settings.getAgentSiteTokenBudget(); }

    /** Remaining ms, or -1 if no time budget set. */
    public long deadlineRemainingMs() {
        if (deadlineMs == Long.MAX_VALUE) return -1;
        long r = deadlineMs - System.currentTimeMillis();
        return r < 0 ? 0 : r;
    }

    public int activeCount() { return active.get(); }

    public int queueDepth() { return queue.queueDepth(); }
}
