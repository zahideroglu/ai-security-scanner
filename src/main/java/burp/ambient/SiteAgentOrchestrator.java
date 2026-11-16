package burp.ambient;

import burp.DetectionRunView;
import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.MultiSessionTester;
import burp.QwenAPIClient;
import burp.ScanManager;
import burp.Settings;
import burp.engine.AgentPentestEngine;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.playbook.Playbook;
import burp.playbook.PlaybookLibrary;
import burp.playbook.PlaybookRouter;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The (previously missing) orchestrator that finally wires the playbook system to
 * the agentic engine. For one endpoint it: loads the {@link PlaybookLibrary}, lets
 * {@link PlaybookRouter} pick the eligible playbooks (mode: all / heuristic / ai),
 * and runs a specialized {@link AgentPentestEngine} per chosen playbook — all
 * sharing one {@link SharedRateLimiter} and one site-wide {@code reportedKeys} set
 * so total RPS is bounded and site-wide issues are reported once.
 *
 * Used by both the manual "playbook-driven" menu action and the autonomous
 * {@link BackgroundHunter}; scheduling/budget is the caller's job, per-endpoint
 * engine wiring is ours.
 *
 * @author Zahid Eroglu
 */
public final class SiteAgentOrchestrator {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final QwenAPIClient ai;
    private final Settings settings;
    private final ScanManager scanManager;
    private final MultiSessionTester sessions; // may be null
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final SharedRateLimiter limiter;
    private final Set<String> reportedKeys;
    private final PlaybookLibrary library;
    private volatile boolean forceSafeMode = false;
    private volatile boolean aiUnavailable = false; // true => last huntEndpoint stopped because the AI back-end was unusable
    private burp.authz.AccessModel accessModel; // Faz 3: ground-truth ownership for provable BOLA (may be null)

    /** Standalone run (menu action): shares ScanManager's ONE global throttle + own dedup set. */
    public SiteAgentOrchestrator(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                 QwenAPIClient ai, Settings settings, ScanManager scanManager,
                                 MultiSessionTester sessions, PrintWriter stdout, PrintWriter stderr) {
        this(callbacks, helpers, ai, settings, scanManager, sessions,
                // Share the ONE global throttle (per-minute FW budget) instead of opening a second
                // independent RPS stream; fall back to a properly-configured limiter if needed.
                scanManager != null ? scanManager.getGlobalRateLimiter()
                        : new SharedRateLimiter(settings.getMaxRequestsPerMinute(), settings.getMaxRequestsPerSecond()),
                Collections.synchronizedSet(new HashSet<String>()), stdout, stderr);
    }

    /** Shared run (background hunter / whole-site): caller supplies the limiter + dedup set. */
    public SiteAgentOrchestrator(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                 QwenAPIClient ai, Settings settings, ScanManager scanManager,
                                 MultiSessionTester sessions, SharedRateLimiter limiter,
                                 Set<String> reportedKeys, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.ai = ai;
        this.settings = settings;
        this.scanManager = scanManager;
        this.sessions = sessions;
        this.stdout = stdout;
        this.stderr = stderr;
        this.limiter = limiter;
        this.reportedKeys = reportedKeys;
        this.library = PlaybookLibrary.load(settings, stderr);
    }

    public void setForceSafeMode(boolean v) { this.forceSafeMode = v; }

    /** Faz 3: provide ground-truth object ownership so the agent drives PROVABLE cross-owner BOLA. */
    public void setAccessModel(burp.authz.AccessModel m) { this.accessModel = m; }

    public Set<String> reportedKeys() { return reportedKeys; }

    /** True if the most recent {@link #huntEndpoint} stopped because the AI back-end was unusable (requeue + retry later). */
    public boolean wasAiUnavailable() { return aiUnavailable; }

    /** Run the agentic pentester on ONE endpoint, specialized by the routed playbook(s). */
    public List<Finding> huntEndpoint(IHttpRequestResponse base, int seedIndex, StageListener listener) {
        List<Finding> all = new ArrayList<Finding>();
        aiUnavailable = false;
        try {
            IRequestInfo ri = helpers.analyzeRequest(base);
            boolean haveSessions = sessions != null && sessions.getSessions() != null
                    && !sessions.getSessions().isEmpty();
            PlaybookRouter router = new PlaybookRouter(helpers, settings, haveSessions);

            List<Playbook> eligible = router.eligible(library, seedIndex);
            List<Playbook> chosen = route(router, eligible, ri, base);
            if (chosen.isEmpty()) {
                if (stdout != null) stdout.println("[orchestrator] no eligible playbook for "
                        + ri.getMethod() + " " + ri.getUrl().getPath());
                return all;
            }
            if (stdout != null) {
                List<String> ids = new ArrayList<String>();
                for (Playbook pb : chosen) ids.add(pb.id);
                stdout.println("[orchestrator] " + ri.getMethod() + " " + ri.getUrl().getPath()
                        + " → playbooks " + ids);
            }

            for (Playbook pb : chosen) {
                if (aborted(listener)) break;
                AgentPentestEngine engine = new AgentPentestEngine(
                        callbacks, helpers, ai, settings, scanManager, sessions, stdout, stderr);
                engine.setPlaybook(pb);
                engine.setSharedRateLimiter(limiter);
                engine.setSharedReportedKeys(reportedKeys);
                engine.setForceSafeMode(forceSafeMode);
                if (accessModel != null) engine.setAccessModel(accessModel);
                List<Finding> fs = engine.run(base, "ambient-hunt", listener);
                if (fs != null) all.addAll(fs);
                if (engine.wasAiUnavailable()) aiUnavailable = true; // surface to the hunter for requeue

            }
        } catch (Exception e) {
            if (stderr != null) stderr.println("[orchestrator] huntEndpoint error: " + e.getMessage());
        }
        return all;
    }

    // ----- routing ---------------------------------------------------------

    private List<Playbook> route(PlaybookRouter router, List<Playbook> eligible,
                                 IRequestInfo ri, IHttpRequestResponse msg) {
        String mode = settings.getAgentRouterMode();
        List<Playbook> chosen;
        if ("heuristic".equals(mode)) chosen = router.heuristicFilter(eligible, ri, msg);
        else if ("ai".equals(mode)) chosen = aiTriage(router, eligible, ri, msg);
        else chosen = eligible; // "all"
        // Hard, mode-independent preconditions: drop any playbook whose target signal is absent on THIS
        // (history/site-map) request — no JWT → no auth-jwt, no id → no IDOR/BOLA, no body|econ → no
        // business-logic/mass-assignment. A playbook with nothing to test never runs, in every mode.
        return router.applyPreconditions(chosen, ri, msg);
    }

    /** One cheap LLM call to pick 1-3 playbook ids; falls back to heuristicFilter on any failure. */
    private List<Playbook> aiTriage(PlaybookRouter router, List<Playbook> eligible,
                                    IRequestInfo ri, IHttpRequestResponse msg) {
        if (eligible.isEmpty()) return eligible;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("You are triaging which security playbooks to run on ONE HTTP endpoint.\n");
            sb.append("Endpoint: ").append(ri.getMethod()).append(" ").append(ri.getUrl()).append("\n");
            sb.append("Available playbooks (id — title):\n");
            for (Playbook pb : eligible) {
                sb.append("- ").append(pb.id).append(" — ").append(pb.title).append("\n");
            }
            sb.append("Return ONLY a JSON array of the 1-3 most relevant ids, e.g. [\"access-control-idor\"].");

            List<QwenAPIClient.Message> messages = new ArrayList<QwenAPIClient.Message>();
            messages.add(new QwenAPIClient.Message("system",
                    "You are a precise security triage assistant. Respond with a JSON array of ids only."));
            messages.add(new QwenAPIClient.Message("user", sb.toString()));

            JSONObject resp = ai.chatCompletion(messages, 0.2, settings.getEngineMaxTokens(),
                    settings.getAgentModel(), 1);
            String content = resp.getJSONArray("choices").getJSONObject(0)
                    .getJSONObject("message").getString("content");
            int s = content.indexOf('[');
            int e = content.lastIndexOf(']');
            if (s < 0 || e <= s) return router.heuristicFilter(eligible, ri, msg);
            JSONArray arr = new JSONArray(content.substring(s, e + 1));
            Set<String> want = new HashSet<String>();
            for (int i = 0; i < arr.length(); i++) want.add(arr.optString(i, ""));
            List<Playbook> chosen = new ArrayList<Playbook>();
            for (Playbook pb : eligible) {
                if (want.contains(pb.id)) chosen.add(pb);
            }
            return chosen.isEmpty() ? router.heuristicFilter(eligible, ri, msg) : chosen;
        } catch (Exception e) {
            return router.heuristicFilter(eligible, ri, msg);
        }
    }

    private boolean aborted(StageListener l) {
        return (l instanceof DetectionRunView) && ((DetectionRunView) l).isAborted();
    }
}
