package burp.scan;

import burp.*;
import burp.ai.AITestingAgent;
import burp.engine.DetectionStage;
import burp.engine.StageListener;
import burp.scan.modules.AccessControlModule;
import burp.scan.modules.BruteForceModule;
import burp.scan.modules.CaptchaBypassModule;
import burp.scan.modules.ContentDiscoveryModule;
import burp.scan.modules.ErrorForcingModule;
import burp.scan.modules.FileUploadModule;
import burp.scan.modules.HttpMethodModule;
import burp.scan.modules.IdorModule;
import burp.scan.modules.MassAssignmentModule;
import burp.scan.modules.MisconfigModule;
import burp.scan.modules.ParamGuessModule;
import burp.scan.modules.SsrfRedirectModule;
import burp.scan.modules.TransportModule;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fast, deterministic active-scan orchestrator. Captures one baseline, runs the
 * enabled {@link ScanModule}s' probes in parallel via {@link TestSink}, then lets
 * each module judge deterministically. AI is NOT used in this hot path.
 *
 * @author Zahid Eroglu
 */
public class ActiveScanEngine {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AiApiClient aiClient;
    private final Settings settings;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final boolean singleRequest;
    private final burp.engine.SharedRateLimiter rateLimiter; // site-wide throttle shared with agents/recon/matrix (may be null)
    private final List<ScanModule> modules;

    public ActiveScanEngine(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                            AiApiClient aiClient, Settings settings,
                            PrintWriter stdout, PrintWriter stderr, burp.engine.SharedRateLimiter rateLimiter) {
        this(callbacks, helpers, aiClient, settings, stdout, stderr, rateLimiter, false);
    }

    /**
     * @param singleRequest true = scanning ONE chosen request (host-level checks like
     * TRACE / HTTP-&gt;HTTPS / content-discovery run even on deep paths); false = site/bulk
     * scan (those run only on the site root to avoid repeating them per endpoint).
     */
    public ActiveScanEngine(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                            AiApiClient aiClient, Settings settings,
                            PrintWriter stdout, PrintWriter stderr,
                            burp.engine.SharedRateLimiter rateLimiter, boolean singleRequest) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.settings = settings;
        this.stdout = stdout;
        this.stderr = stderr;
        this.rateLimiter = rateLimiter;
        this.singleRequest = singleRequest;
        this.modules = Arrays.asList(
                new MisconfigModule(),
                new HttpMethodModule(),      // B06 TRACE/TRACK/OPTIONS (host-level)
                new TransportModule(),       // B04 HTTP->HTTPS redirect (host-level)
                new ContentDiscoveryModule(),// B05/B08 admin paths + plugin enumeration (host-level)
                new ErrorForcingModule(),    // B02 stack-trace / source-path disclosure
                new IdorModule(),
                new ParamGuessModule(),      // B03 access control via guessed parameters
                new AccessControlModule(),
                new SsrfRedirectModule(),
                new CaptchaBypassModule(),   // A07 CAPTCHA / auth-step bypass (AI-adjudicated)
                new BruteForceModule(),      // B01 weak/guessable password (intrusive)
                new MassAssignmentModule(),  // BOPLA / mass assignment (intrusive)
                new FileUploadModule()
        );
    }

    /**
     * Run all enabled/applicable modules against one request. Returns findings
     * (the caller is responsible for reporting them).
     */
    public List<Finding> scan(IHttpRequestResponse base, String tabId, StageListener listener) {
        List<Finding> findings = new ArrayList<>();
        Baseline b = Baseline.capture(callbacks, helpers, base, rateLimiter);
        b.singleRequestScan = singleRequest;
        if (listener != null) {
            listener.onStageProgress(DetectionStage.EXECUTE,
                    "Baseline: HTTP " + b.statusCode + " · " + b.responseLength + "b · "
                            + b.parameters.size() + " param");
        }

        AITestingAgent mutator = new AITestingAgent(callbacks, helpers, aiClient, stdout, stderr);
        TestSink sink = new TestSink(callbacks, helpers, mutator, listener,
                settings.getActiveScanParallelism(), settings.getMaxRequestsPerSecond(), rateLimiter, stderr);

        String baseReq = safeStr(base.getRequest());
        java.util.List<String> summary = new java.util.ArrayList<>();
        try {
            for (ScanModule m : modules) {
                if (!m.isEnabled(settings)) {
                    summary.add(m.id() + ":kapalı");
                    continue;
                }
                if (!m.appliesTo(b)) {
                    summary.add(m.id() + ":uygulanamaz");
                    continue;
                }
                List<Probe> probes;
                try {
                    probes = m.plan(b, settings);
                } catch (Exception e) {
                    summary.add(m.id() + ":hata");
                    if (stderr != null) stderr.println("[ActiveScan] plan " + m.id() + ": " + e.getMessage());
                    continue;
                }
                if (probes == null || probes.isEmpty()) {
                    summary.add(m.id() + ":0");
                    continue;
                }
                summary.add(m.id() + ":" + probes.size());
                List<ProbeResult> results = sink.sendAll(base, probes);
                List<Finding> fs;
                try {
                    fs = m.judge(b, results);
                } catch (Exception e) {
                    if (stderr != null) stderr.println("[ActiveScan] judge " + m.id() + ": " + e.getMessage());
                    continue;
                }
                if (fs != null) {
                    for (Finding f : fs) {
                        f.setAffectedUrl(b.url);
                        f.setHttpRequest(baseReq);
                        findings.add(f);
                    }
                }
            }
            if (listener != null) {
                listener.onStageProgress(DetectionStage.EXECUTE, "Modüller → " + String.join(" · ", summary));
            }
        } finally {
            sink.shutdown();
        }
        return dedup(findings);
    }

    /** Keep one finding per (type|url), highest severity. */
    private List<Finding> dedup(List<Finding> findings) {
        Map<String, Finding> best = new LinkedHashMap<>();
        for (Finding f : findings) {
            String key = f.getType() + "|" + f.getAffectedUrl();
            Finding cur = best.get(key);
            if (cur == null || rank(f.getSeverity()) > rank(cur.getSeverity())) {
                best.put(key, f);
            }
        }
        return new ArrayList<>(best.values());
    }

    private int rank(String sev) {
        if (sev == null) return 0;
        switch (sev.toLowerCase()) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    private String safeStr(byte[] b) {
        try {
            return b != null ? new String(b, "UTF-8") : "";
        } catch (Exception e) {
            return "";
        }
    }
}
