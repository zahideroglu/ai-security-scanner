package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;

/**
 * Scan Manager - Orchestrates all scanning operations
 * 
 * @author Zahid Eroglu
 */
public class ScanManager {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private AiApiClient aiClient;
    private DatabaseManager dbManager;
    private FilterEngine filterEngine;
    private Settings settings;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private ResponseAnalyzer responseAnalyzer;
    private burp.api.ChainAttackDetector chainDetector;
    private burp.businesslogic.WorkflowAnalyzer workflowAnalyzer;
    private ExecutorService executor;
    private Map<String, ScanStatus> activeScans;

    private List<ScanListener> listeners;
    private FindingsPanel findingsPanel; // Reference to findings panel for adding findings
    // Observer notified of every NON-suppressed reported finding (the Copilot's IDOR feed taps this).
    private volatile java.util.function.BiConsumer<Finding, IHttpRequestResponse> findingObserver;
    private MultiSessionTester multiSessionTester; // for the agentic pentester's session replay (may be null)
    private burp.session.SessionKeeper sessionKeeper; // session freshness / auto-relogin (may be null)
    private burp.engine.SharedRateLimiter globalRateLimiter; // shared by manual + autonomous agents
    /** Hosts already fingerprinted for exposed AI-app frameworks, so the probe runs once per host. */
    private final java.util.Set<String> aiFwProbedHosts = java.util.concurrent.ConcurrentHashMap.newKeySet();

    public ScanManager(IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            AiApiClient aiClient,
            DatabaseManager dbManager,
            FilterEngine filterEngine,
            Settings settings,
            PrintWriter stdout,
            PrintWriter stderr) {

        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.dbManager = dbManager;
        this.filterEngine = filterEngine;
        this.settings = settings;
        this.stdout = stdout;
        this.stderr = stderr;

        this.responseAnalyzer = new ResponseAnalyzer(settings.getMinConfidence());
        this.globalRateLimiter = new burp.engine.SharedRateLimiter(
                settings.getMaxRequestsPerMinute(), settings.getMaxRequestsPerSecond());
        this.globalRateLimiter.configureWaf(settings.getWafDetectionThreshold(), settings.getSlowModeDelayMs());
        stdout.println("[Throttle] Global request cap: " + settings.getMaxRequestsPerMinute()
                + "/min (" + settings.getMaxRequestsPerSecond() + "/s burst, jittered) — shared by all scan paths; "
                + "WAF breaker: trip @ " + settings.getWafDetectionThreshold() + " block-signals/host");
        this.chainDetector = new burp.api.ChainAttackDetector(callbacks, helpers, globalRateLimiter, stdout, stderr);
        this.workflowAnalyzer = new burp.businesslogic.WorkflowAnalyzer(aiClient, helpers, stdout, stderr);
        this.executor = Executors.newFixedThreadPool(settings.getMaxConcurrent());
        this.activeScans = new ConcurrentHashMap<>();
        this.listeners = new ArrayList<>();

    }

    // ===== AI adjudication at critical detection steps =====
    // Deterministic rules generate candidates fast; AI then decides on each one.
    // Auto-on when AI is configured; fail-open (AI down -> keep the deterministic verdict).

    private boolean aiReady() {
        try {
            return aiClient != null && settings.getApiUrl() != null && !settings.getApiUrl().trim().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /** AI verdict on ONE candidate finding (mutates it): confirm -> set AI confidence + reasoning;
     *  refute -> mark false-positive (kept, not dropped) + note; error/off -> leave unchanged. */
    private void aiJudge(Finding f, IHttpRequestResponse base) {
        if (f == null || !aiReady()) return;
        // Deterministic, FACTUAL passive findings (a header is literally absent, a banner is literally
        // present, a cookie flag is literally missing) are not a matter of opinion — the AI must not be
        // allowed to "refute" them (it wrongly marked real CSP/HSTS findings as false positives). Leave
        // them on their deterministic verdict; only inferential/active findings get AI adjudication.
        if (isFactualPassiveType(f.getType())) return;
        try {
            burp.ai.AIFalsePositiveFilter filter =
                    new burp.ai.AIFalsePositiveFilter(aiClient, helpers, stdout, stderr);
            burp.ai.AIFalsePositiveFilter.ValidationResult r;
            if (isAccessControlType(f.getType()) && f.getHttpResponse() != null && !f.getHttpResponse().isEmpty()) {
                // BOLA/IDOR: AI compares baseline (owner) vs manipulated (other id/identity) responses.
                r = filter.judgeAccessControlConsensus(f.getType(), f.getEvidence(), bodyOf(base),
                        f.getHttpResponse(), f.getControlResponse(), null);
            } else if (isHighSeverity(f.getSeverity())) {
                // Faz 1: every high-severity claim gets adversarial multi-lens verification (not single-vote).
                r = filter.verifyConsensus(f, base, null, null);
            } else {
                r = filter.verifyFinding(f, base, null, null);
            }
            applyVerdict(f, r);
        } catch (Exception e) {
            // fail-open: bulguya dokunma
        }
    }

    /** Explicit two-body BOLA judgment (authz matrix V3, where bodies come from role replays). */
    private void aiJudgeAccess(Finding f, String manipulation, String baselineBody, String manipulatedBody,
                               String negativeControlBody) {
        if (f == null || !aiReady()) return;
        try {
            burp.ai.AIFalsePositiveFilter filter =
                    new burp.ai.AIFalsePositiveFilter(aiClient, helpers, stdout, stderr);
            applyVerdict(f, filter.judgeAccessControlConsensus(f.getType(), manipulation, baselineBody,
                    manipulatedBody, negativeControlBody, null));
        } catch (Exception e) {
            // fail-open
        }
    }

    private void applyVerdict(Finding f, burp.ai.AIFalsePositiveFilter.ValidationResult r) {
        String why = (r.reasoning == null) ? "" : r.reasoning;
        if (r.verificationUnavailable) {
            // A finding already PROVEN deterministically (oracle CONFIRMED — e.g. ground-truth cross-owner
            // BOLA) stands on its own evidence: an unavailable/timed-out AI is a missing bonus check, not
            // grounds to downgrade it. Mark it directly; only an ACTIVE refutation may weaken it.
            if (f.getOracleVerdict() == burp.Finding.OracleVerdict.CONFIRMED) {
                appendAiNote(f, "AI doğrulanamadı — bulgu deterministik kanıta dayanıyor, olduğu gibi bırakıldı.");
                return;
            }
            // Otherwise fail-CLOSED: don't let an unverified high-severity claim stand.
            f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            f.setConfidence(Math.min(f.getConfidence(), 0.49)); // effective-severity caps it down
            f.addVerificationStep("AI doğrulaması yapılamadı — bu bulguyu manuel doğrula.");
            appendAiNote(f, "AI doğrulanamadı (fail-closed): " + why);
            return;
        }
        if (!r.isValidVulnerability) {
            if (r.needsManualReview) {
                // Split / uncertain verdict (e.g. votes tied with one lens unavailable) — do NOT hard-drop a
                // possibly-real finding; keep it flagged for manual review instead of marking it a FP.
                f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
                f.setConfidence(Math.min(f.getConfidence(), 0.45));
                appendAiNote(f, "AI kararsız (bölünmüş oy) — manuel inceleme önerilir: " + why);
                return;
            }
            f.setFalsePositive(true);
            f.setOracleVerdict(burp.Finding.OracleVerdict.REFUTED);
            if (r.confidence > 0) f.setConfidence(Math.min(f.getConfidence(), r.confidence));
            appendAiNote(f, "AI: olası FALSE POSITIVE — " + why);
            if (stdout != null) stdout.println("[AI] FP işaretlendi: " + f.getType() + " — " + why);
        } else {
            f.setOracleVerdict(burp.Finding.OracleVerdict.CONFIRMED);
            if (r.confidence > 0) f.setConfidence(r.confidence);
            appendAiNote(f, "AI doğrulaması: " + why
                    + (r.exploitability != null && !r.exploitability.isEmpty()
                    ? " (exploitability: " + r.exploitability + ")" : ""));
            if (r.needsManualReview) appendAiNote(f, "AI: manuel inceleme önerilir");
        }
    }

    /** Deterministic, factual passive findings the AI must NOT be allowed to flip to false-positive. */
    private boolean isFactualPassiveType(String type) {
        if (type == null) return false;
        String t = type.toLowerCase();
        return t.contains("security misconfiguration")     // missing headers / cookie flags
                || t.contains("information disclosure")     // server/x-powered-by banner, stack trace
                || t.contains("transport security")         // http->https
                || t.contains("component disclosure")       // technology/component enumeration
                || t.contains("http method")                // TRACE/OPTIONS verb misconfig
                || t.contains("content-security") || t.contains("content security") || t.contains("hsts")
                || t.contains("strict-transport") || t.contains("x-frame") || t.contains("clickjack")
                || t.contains("x-content-type") || t.contains("missing security header")
                || t.contains("missing header") || t.contains("insecure cookie"); // header/cookie hygiene = facts
    }

    /**
     * ACTIVELY verify a single IDOR/BOLA candidate before anything files it. Runs the hardened, ownership-
     * aware {@link burp.scan.modules.IdorModule} (id swap + invalid-id negative control + anonymous public
     * probe + foreign-owner-token check) on the candidate request, then the AI judge. Returns a reportable
     * Finding ONLY if it survives the full pipeline (deterministic discriminators + AI CONFIRM); otherwise
     * null. Used by the Copilot "IDOR'u açıkla" deep-dive so it can no longer file a finding on a bare AI
     * opinion about un-tampered observed traffic (which still produced public-product / own-data FPs).
     * Sends a few extra requests — call it on explicit user action only, never passively.
     */
    public Finding verifyIdorCandidate(IHttpRequestResponse seed) {
        if (seed == null) return null;
        try {
            burp.scan.Baseline b = burp.scan.Baseline.capture(callbacks, helpers, seed, globalRateLimiter);
            burp.scan.modules.IdorModule mod = new burp.scan.modules.IdorModule();
            if (!mod.appliesTo(b)) return null;            // no numeric path seg / id param → nothing to test
            java.util.List<burp.scan.Probe> probes = mod.plan(b, settings);
            if (probes == null || probes.isEmpty()) return null;
            burp.ai.AITestingAgent mutator =
                    new burp.ai.AITestingAgent(callbacks, helpers, aiClient, stdout, stderr);
            burp.scan.TestSink sink = new burp.scan.TestSink(callbacks, helpers, mutator, null,
                    settings.getActiveScanParallelism(), settings.getMaxRequestsPerSecond(), globalRateLimiter, stderr);
            java.util.List<burp.scan.ProbeResult> results;
            try {
                results = sink.sendAll(seed, probes);
            } finally {
                sink.shutdown();
            }
            java.util.List<Finding> fs = mod.judge(b, results);
            if (fs == null || fs.isEmpty()) return null;   // deterministic guards dropped it (public / own data)
            Finding f = fs.get(0);
            f.setAffectedUrl(b.url);
            try { f.setHttpRequest(new String(seed.getRequest(), "UTF-8")); } catch (Exception ignore) {}
            aiJudge(f, seed);                              // AI confirm/refute + suppress-unless-confirmed flag
            if (shouldSuppress(f)) return null;            // AI refuted / unavailable / undecided → not proven
            independentSecondPass(f);                      // decoupled re-verification: CONFIRMED vs NEEDS-REVIEW
            return f;
        } catch (Exception e) {
            if (stderr != null) stderr.println("[verifyIdorCandidate] " + e.getMessage());
            return null;
        }
    }

    /**
     * Run the INDEPENDENT second verification pass on a finding that already passed the first gate, then
     * fold its three-way outcome into the finding:
     *   REPRODUCED      → keep CONFIRMED (independent sample agrees);
     *   NOT_REPRODUCED  → flag NEEDS-REVIEW (surface it, but cap severity — not silently confirmed/dropped);
     *   UNAVAILABLE     → first-pass result stands (host blocked / no replayable bundle).
     * Best-effort: never throws into the caller.
     */
    private void independentSecondPass(Finding f) {
        try {
            if (f == null || !f.hasReproBundle()) return;
            burp.scan.IndependentVerifier iv = new burp.scan.IndependentVerifier(
                    callbacks, helpers, aiReady() ? aiClient : null, globalRateLimiter, stdout, stderr);
            burp.scan.IndependentVerifier.Outcome o = iv.verify(f);
            switch (o) {
                case REPRODUCED:
                    f.addVerificationStep(burp.i18n.I18n.t("indep.reproduced"));
                    break;
                case NOT_REPRODUCED:
                    f.setNeedsReview(true);
                    f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
                    f.setConfidence(Math.min(f.getConfidence(), 0.5)); // caps effective severity to Medium
                    f.addVerificationStep(burp.i18n.I18n.t("indep.needsReview"));
                    break;
                case UNAVAILABLE:
                default:
                    f.addVerificationStep(burp.i18n.I18n.t("indep.unavailable"));
                    break;
            }
        } catch (Exception e) {
            if (stderr != null) stderr.println("[independentSecondPass] " + e.getMessage());
        }
    }

    private boolean isAccessControlType(String type) {
        if (type == null) return false;
        String t = type.toLowerCase();
        return t.contains("idor") || t.contains("bola") || t.contains("access control")
                || t.contains("broken access") || t.contains("object");
    }

    private boolean isHighSeverity(String sev) {
        if (sev == null) return false;
        String s = sev.trim().toLowerCase();
        return s.equals("critical") || s.equals("high");
    }

    private String bodyOf(IHttpRequestResponse m) {
        try {
            if (m == null || m.getResponse() == null) return "";
            byte[] resp = m.getResponse();
            IResponseInfo ri = helpers.analyzeResponse(resp);
            int off = ri.getBodyOffset();
            return new String(resp, off, Math.min(4096, Math.max(0, resp.length - off)), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    private void appendAiNote(Finding f, String note) {
        String ex = (f.getExploitation() == null || f.getExploitation().isEmpty()) ? "" : f.getExploitation() + "\n";
        f.setExploitation(ex + note);
    }

    /** AI-judge a batch sharing one base request (single-request scan), with a progress line. */
    private void aiJudgeAll(IHttpRequestResponse base, List<Finding> findings, String label,
                            burp.engine.StageListener l) {
        if (findings == null || findings.isEmpty() || !aiReady()) return;
        int fp = 0;
        for (Finding f : findings) {
            aiJudge(f, base);
            if (f.isFalsePositive()) fp++;
        }
        if (l != null) l.onStageProgress(burp.engine.DetectionStage.VERIFY,
                "AI kararı (" + label + "): " + (findings.size() - fp) + " doğrulandı · " + fp + " olası FP işaretlendi");
    }

    /**
     * Scan a message with optional custom prompt
     */
    public void scanMessage(String tabId, IHttpRequestResponse message, String customPrompt,
            List<Conversation> conversationHistory) {

        String url = helpers.analyzeRequest(message).getUrl().toString();
        String scanId = tabId != null ? tabId : UUID.randomUUID().toString();

        // Check if already scanning
        if (activeScans.containsKey(url)) {
            stdout.println("[!] Scan already in progress for: " + url);
            return;
        }

        // Create scan status
        ScanStatus status = new ScanStatus(scanId, url, ScanStatus.State.QUEUED);
        status.setTabId(tabId);
        activeScans.put(url, status);
        notifyListeners("scan_started", scanId, url, tabId, null);

        // Submit scan task
        executor.submit(() -> {
            try {
                performScan(message, customPrompt, conversationHistory, status);
            } catch (Exception e) {
                stderr.println("[✗] Scan error for " + url + ": " + e.getMessage());
                status.setState(ScanStatus.State.FAILED);
                status.setError(e.getMessage());
                notifyListeners("scan_failed", scanId, url, tabId, null);
            } finally {
                activeScans.remove(url);
            }
        });
    }

    /**
     * Perform actual scan
     */
    private void performScan(IHttpRequestResponse message, String customPrompt,
            List<Conversation> history, ScanStatus status) throws Exception {

        status.setState(ScanStatus.State.RUNNING);
        notifyListeners("scan_progress", status.getScanId(), status.getUrl(), status.getTabId(), null);

        // Get request and response
        byte[] requestBytes = message.getRequest();
        byte[] responseBytes = message.getResponse();

        String httpRequest = new String(requestBytes, "UTF-8");
        String httpResponse = responseBytes != null ? new String(responseBytes, "UTF-8") : "";

        String ragContext = buildLocalRagContext(status.getUrl(), httpRequest, httpResponse);

        // Build prompt
        List<AiApiClient.Message> messages;

        if (customPrompt != null && !customPrompt.trim().isEmpty()) {
            messages = PromptBuilder.buildConversationPrompt(
                    history, customPrompt, httpRequest, httpResponse);
        } else {
            messages = PromptBuilder.buildSimplePrompt(httpRequest, httpResponse);
        }

        if (ragContext != null && !ragContext.isEmpty()) {
            insertSystemMessageAfterFirst(messages, ragContext);
        }

        // Call AI API
        long startTime = System.currentTimeMillis();
        JSONObject apiResponse = aiClient.chatCompletion(messages);
        long duration = System.currentTimeMillis() - startTime;

        // Parse response
        ScanResult result = responseAnalyzer.parseResponse(apiResponse, httpRequest, httpResponse);

        // Filter findings
        List<Finding> filteredFindings = new ArrayList<>();
        for (Finding finding : result.getFindings()) {
            if (isDisabledVulnType(finding)) continue; // SQLi/XSS disabled extension-wide
            if (responseAnalyzer.isTypeEnabled(finding, settings.getEnabledVulnTypes())) {
                filteredFindings.add(finding);
            }
        }

        result = new ScanResult(filteredFindings, result.getSummary(), result.getRawResponse());

        // Save to database
        dbManager.saveScanResult(
                status.getUrl(),
                helpers.analyzeRequest(message).getMethod(),
                httpRequest,
                httpResponse,
                customPrompt,
                result,
                duration);

        // Save each finding to database and create Burp issues
        String tabId = status.getTabId() != null ? status.getTabId() : "default";
        for (Finding finding : filteredFindings) {
            try {
                // Set affected URL and request/response for the finding
                finding.setAffectedUrl(status.getUrl());
                finding.setHttpRequest(httpRequest);
                finding.setHttpResponse(httpResponse);

                // Save to database with request/response
                dbManager.saveFinding(tabId, finding, httpRequest, httpResponse);

                // Faz 0: keep FP in the DB (RAG/FP store) but don't surface it to Burp/panel.
                if (finding.isFalsePositive()) {
                    continue;
                }

                // Create Burp issue
                createBurpIssue(message, finding);

                // Add to FindingsPanel if available
                if (findingsPanel != null) {
                    try {
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            findingsPanel.addFinding(finding, message);
                        });
                    } catch (Exception e) {
                        stderr.println("[!] Error adding finding to panel: " + e.getMessage());
                    }
                }

                stdout.println("[+] Finding saved: " + finding.getType() +
                        " (Severity: " + finding.getSeverity() + ")" +
                        " - Request: " + (httpRequest != null ? httpRequest.length() + " bytes" : "null") +
                        " - Response: " + (httpResponse != null ? httpResponse.length() + " bytes" : "null"));
            } catch (Exception e) {
                stderr.println("[!] Error saving finding: " + e.getMessage());
            }
        }

        // Update status
        status.setState(ScanStatus.State.COMPLETED);
        status.setResult(result);

        stdout.println("[✓] Scan completed: " + status.getUrl() +
                " (" + filteredFindings.size() + " findings, " + duration + "ms)");

        notifyListeners("scan_completed", status.getScanId(), status.getUrl(), status.getTabId(), result);
    }

    private void insertSystemMessageAfterFirst(List<AiApiClient.Message> messages, String content) {
        if (messages == null || content == null || content.isEmpty()) {
            return;
        }
        int insertIndex = Math.min(1, messages.size());
        messages.add(insertIndex, new AiApiClient.Message("system", content));
    }

    private String buildLocalRagContext(String url, String httpRequest, String httpResponse) {
        try {
            List<Finding> truePositives = dbManager.getRecentFindings(80);
            List<Finding> falsePositives = dbManager.getRecentFalsePositives(40);

            Set<String> queryTokens = buildQueryTokens(url, httpRequest, httpResponse);

            List<ScoredFinding> tpRanked = rankFindings(queryTokens, truePositives, 6);
            List<ScoredFinding> fpRanked = rankFindings(queryTokens, falsePositives, 6);

            if (tpRanked.isEmpty() && fpRanked.isEmpty()) {
                return "";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("You also have access to a LOCAL knowledge base from previous scans of this target.\n");
            sb.append("Use it ONLY to prioritize tests and reduce false positives. It is NOT proof by itself.\n\n");
            sb.append("=== LOCAL KB (MOST RELEVANT) ===\n");

            if (!tpRanked.isEmpty()) {
                sb.append("Previously confirmed findings (similar context):\n");
                for (ScoredFinding sf : tpRanked) {
                    sb.append("- ");
                    sb.append(sanitizeOneLine(sf.finding.getType()));
                    sb.append(" | ");
                    sb.append(sanitizeOneLine(sf.finding.getSeverity()));
                    String p = normalizeUrlPath(sf.finding.getAffectedUrl());
                    if (!p.isEmpty()) {
                        sb.append(" | path: ").append(p);
                    }
                    String desc = compactSnippet(sf.finding.getDescription(), 240);
                    if (!desc.isEmpty()) {
                        sb.append(" | ").append(desc);
                    }
                    String ev = compactSnippet(sf.finding.getEvidence(), 160);
                    if (!ev.isEmpty()) {
                        sb.append(" | evidence: ").append(ev);
                    }
                    sb.append("\n");
                }
                sb.append("\n");
            }

            if (!fpRanked.isEmpty()) {
                sb.append("Previously marked false positives (be extra strict with evidence):\n");
                for (ScoredFinding sf : fpRanked) {
                    sb.append("- ");
                    sb.append(sanitizeOneLine(sf.finding.getType()));
                    String p = normalizeUrlPath(sf.finding.getAffectedUrl());
                    if (!p.isEmpty()) {
                        sb.append(" | path: ").append(p);
                    }
                    String desc = compactSnippet(sf.finding.getDescription(), 240);
                    if (!desc.isEmpty()) {
                        sb.append(" | ").append(desc);
                    }
                    sb.append("\n");
                }
                sb.append("\n");
            }

            sb.append("Instructions:\n");
            sb.append("- Prefer findings with concrete request/response evidence.\n");
            sb.append(
                    "- If something matches prior false positives, require stronger proof or mark as manual review.\n");

            return clamp(sb.toString(), 2500);
        } catch (Exception e) {
            return "";
        }
    }

    private List<ScoredFinding> rankFindings(Set<String> queryTokens, List<Finding> findings, int limit) {
        if (findings == null || findings.isEmpty() || queryTokens == null || queryTokens.isEmpty()) {
            return Collections.emptyList();
        }

        List<ScoredFinding> scored = new ArrayList<>();
        for (Finding f : findings) {
            if (f == null)
                continue;
            Set<String> docTokens = tokenize(
                    safeString(f.getType()) + " " +
                            safeString(f.getSeverity()) + " " +
                            safeString(f.getAffectedUrl()) + " " +
                            safeString(f.getDescription()) + " " +
                            safeString(f.getEvidence()));
            double s = overlapScore(queryTokens, docTokens);
            if (s > 0.08) {
                scored.add(new ScoredFinding(f, s));
            }
        }

        scored.sort((a, b) -> Double.compare(b.score, a.score));
        if (scored.size() > limit) {
            return new ArrayList<>(scored.subList(0, limit));
        }
        return scored;
    }

    private Set<String> buildQueryTokens(String url, String httpRequest, String httpResponse) {
        StringBuilder q = new StringBuilder();
        String path = normalizeUrlPath(url);
        if (!path.isEmpty())
            q.append(path).append(' ');
        q.append(extractRequestLine(httpRequest)).append(' ');
        q.append(extractParamNames(httpRequest)).append(' ');
        q.append(extractSignalKeywords(httpResponse)).append(' ');
        return tokenize(q.toString());
    }

    private String normalizeUrlPath(String url) {
        if (url == null)
            return "";
        try {
            URL u = new URL(url);
            String path = u.getPath();
            if (path == null)
                return "";
            return path.trim();
        } catch (Exception e) {
            int scheme = url.indexOf("://");
            String rest = scheme >= 0 ? url.substring(scheme + 3) : url;
            int slash = rest.indexOf('/');
            if (slash < 0)
                return "";
            int q = rest.indexOf('?', slash);
            String path = q >= 0 ? rest.substring(slash, q) : rest.substring(slash);
            return path.trim();
        }
    }

    private String extractRequestLine(String httpRequest) {
        if (httpRequest == null)
            return "";
        int nl = httpRequest.indexOf('\n');
        String firstLine = nl >= 0 ? httpRequest.substring(0, nl) : httpRequest;
        return sanitizeOneLine(firstLine);
    }

    private String extractParamNames(String httpRequest) {
        if (httpRequest == null)
            return "";
        String lower = httpRequest.toLowerCase(Locale.ROOT);
        int qIndex = lower.indexOf("?");
        if (qIndex < 0)
            return "";
        int end = lower.indexOf(' ', qIndex);
        if (end < 0)
            end = Math.min(lower.length(), qIndex + 500);
        String query = lower.substring(qIndex + 1, end);
        String[] parts = query.split("&");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            int eq = p.indexOf('=');
            String name = (eq >= 0 ? p.substring(0, eq) : p).trim();
            if (name.length() >= 2 && name.length() <= 40) {
                sb.append(name).append(' ');
            }
        }
        return sb.toString();
    }

    private String extractSignalKeywords(String httpResponse) {
        if (httpResponse == null || httpResponse.isEmpty())
            return "";
        String lower = httpResponse.toLowerCase(Locale.ROOT);
        String[] keywords = new String[] {
                "sql", "syntax error", "exception", "stack trace", "oracle", "mysql", "postgres",
                "mongodb", "redis", "csrf", "invalid token", "unauthorized", "forbidden",
                "cors", "access-control-allow-origin", "x-powered-by", "traceback", "nullpointer",
                "jwt", "algorithm", "deserialize", "xxe"
        };
        StringBuilder sb = new StringBuilder();
        for (String k : keywords) {
            if (lower.contains(k)) {
                sb.append(k).append(' ');
            }
        }
        return sb.toString();
    }

    private Set<String> tokenize(String text) {
        if (text == null)
            return Collections.emptySet();
        String normalized = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", " ");
        String[] parts = normalized.split("\\s+");
        Set<String> tokens = new HashSet<>();
        for (String p : parts) {
            if (p.length() < 3 || p.length() > 30)
                continue;
            if (STOPWORDS.contains(p))
                continue;
            tokens.add(p);
        }
        return tokens;
    }

    private double overlapScore(Set<String> queryTokens, Set<String> docTokens) {
        if (queryTokens == null || docTokens == null || queryTokens.isEmpty() || docTokens.isEmpty()) {
            return 0.0;
        }
        int common = 0;
        for (String t : queryTokens) {
            if (docTokens.contains(t))
                common++;
        }
        return common / Math.sqrt((double) queryTokens.size() * (double) docTokens.size());
    }

    private String compactSnippet(String text, int maxLen) {
        if (text == null)
            return "";
        String s = text.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
        s = s.replaceAll("(?i)authorization\\s*:\\s*bearer\\s+[a-z0-9\\-\\._~\\+\\/]+=*",
                "Authorization: Bearer [REDACTED]");
        s = s.replaceAll("(?i)cookie\\s*:\\s*[^;\\s]+", "Cookie: [REDACTED]");
        s = s.replaceAll("[A-Za-z0-9+/=_\\-]{30,}", "[REDACTED]");
        if (s.length() > maxLen) {
            s = s.substring(0, maxLen).trim();
        }
        return s;
    }

    private String sanitizeOneLine(String text) {
        if (text == null)
            return "";
        return text.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
    }

    private String clamp(String text, int maxLen) {
        if (text == null)
            return "";
        if (text.length() <= maxLen)
            return text;
        return text.substring(0, maxLen);
    }

    private String safeString(String s) {
        return s == null ? "" : s;
    }

    private static final Set<String> STOPWORDS = new HashSet<>(Arrays.asList(
            "the", "and", "for", "with", "from", "this", "that", "have", "has", "are",
            "http", "https", "www", "com", "api", "json", "html", "true", "false",
            "null", "undefined", "error", "errors", "request", "response"));

    private static class ScoredFinding {
        final Finding finding;
        final double score;

        ScoredFinding(Finding finding, double score) {
            this.finding = finding;
            this.score = score;
        }
    }

    /**
     * Background scan (for auto-scan feature)
     */
    public void backgroundScan(IHttpRequestResponse message) {
        // Check filters
        if (!filterEngine.shouldScan(message)) {
            return;
        }

        // Scan with simple prompt
        scanMessage(null, message, null, new ArrayList<>());
    }

    /** Wire the multi-session tester so the agentic pentester can replay as other identities. */
    public void setMultiSessionTester(MultiSessionTester m) {
        this.multiSessionTester = m;
    }

    /** Wire the session keeper so engines can keep identities fresh and auto re-login on logout. */
    public void setSessionKeeper(burp.session.SessionKeeper k) {
        this.sessionKeeper = k;
    }

    public burp.session.SessionKeeper getSessionKeeper() {
        return sessionKeeper;
    }

    /** The single site-wide rate limiter; the background hunter shares this so total RPS stays bounded. */
    public burp.engine.SharedRateLimiter getGlobalRateLimiter() {
        return globalRateLimiter;
    }

    /**
     * Playbook-driven agentic hunt on a single endpoint: the orchestrator loads the
     * playbook library, routes the best-matching playbook(s) for this endpoint, and
     * runs a specialized AgentPentestEngine for each. Verification surface for the
     * playbook wiring before the autonomous hunter uses the same orchestrator.
     */
    public void runPlaybookHunt(IHttpRequestResponse message, burp.engine.StageListener listener) {
        String url = helpers.analyzeRequest(message).getUrl().toString();
        stdout.println("======================================");
        stdout.println("[*] AI PENTESTER (playbook-driven)");
        stdout.println("[*] URL: " + url);
        stdout.println("======================================");

        Thread t = new Thread(() -> {
            // One endpoint, but the orchestrator runs SEVERAL playbooks, each ending with its own REPORT
            // stage. Mark the view multi-run so a per-playbook REPORT doesn't mark the tab "finished"
            // (which would let "Bitenleri Kapat" close it mid-hunt); only siteDone() below finishes it.
            DetectionRunView view = (listener instanceof DetectionRunView) ? (DetectionRunView) listener : null;
            if (view != null) view.setMultiRun(true);
            int found = 0;
            try {
                burp.ambient.SiteAgentOrchestrator orch = settings.isAmbientShareRateLimiterWithManual()
                        ? new burp.ambient.SiteAgentOrchestrator(callbacks, helpers, aiClient, settings, this,
                                multiSessionTester, globalRateLimiter,
                                java.util.Collections.synchronizedSet(new java.util.HashSet<String>()), stdout, stderr)
                        : new burp.ambient.SiteAgentOrchestrator(callbacks, helpers, aiClient, settings, this,
                                multiSessionTester, stdout, stderr);
                List<Finding> fs = orch.huntEndpoint(message, 0, listener);
                found = (fs == null) ? 0 : fs.size();
            } catch (Exception e) {
                stderr.println("[✗] Playbook hunt error: " + e.getMessage());
                e.printStackTrace(stderr);
            } finally {
                if (view != null) view.siteDone(found, view.isAborted());
            }
        }, "playbook-hunt");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Fast deterministic active scan (no AI in the hot path). Drives the
     * DetectionRunView stage strip, runs the module engine, reports findings.
     */
    public void runActiveScan(IHttpRequestResponse message, burp.engine.StageListener listener) {
        String url = helpers.analyzeRequest(message).getUrl().toString();
        stdout.println("======================================");
        stdout.println("[*] FAST ACTIVE SCAN (deterministic)");
        stdout.println("[*] URL: " + url);
        stdout.println("======================================");

        final burp.engine.StageListener l = (listener != null)
                ? listener : new burp.engine.LoggingStageListener(stdout);

        Thread t = new Thread(() -> {
            try {
                // AI stages are skipped in fast mode.
                burp.engine.DetectionStage[] skipped = {
                        burp.engine.DetectionStage.RECON,
                        burp.engine.DetectionStage.HYPOTHESIS,
                        burp.engine.DetectionStage.TEST_PLAN };
                for (burp.engine.DetectionStage st : skipped) {
                    l.onStageStart(st);
                    l.onStageComplete(st, burp.engine.StageResult.ok(st, "atlandı (hızlı mod)"));
                }

                l.onStageStart(burp.engine.DetectionStage.EXECUTE);
                long t0 = System.currentTimeMillis();
                burp.scan.ActiveScanEngine engine = new burp.scan.ActiveScanEngine(
                        callbacks, helpers, aiClient, settings, stdout, stderr, globalRateLimiter, true); // single request: full host-level checks
                List<Finding> findings = engine.scan(message, "active-scan", l);
                burp.engine.StageResult exec = burp.engine.StageResult.ok(
                        burp.engine.DetectionStage.EXECUTE, findings.size() + " aday bulgu");
                exec.durationMs = System.currentTimeMillis() - t0;
                l.onStageComplete(burp.engine.DetectionStage.EXECUTE, exec);

                l.onStageStart(burp.engine.DetectionStage.ANALYZE);
                l.onStageComplete(burp.engine.DetectionStage.ANALYZE,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.ANALYZE, "modül tabanlı"));
                l.onStageStart(burp.engine.DetectionStage.VERIFY);
                aiJudgeAll(message, findings, "hızlı tarama", l);
                l.onStageComplete(burp.engine.DetectionStage.VERIFY,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.VERIFY,
                                aiReady() ? "AI her bulguda karar verdi" : "deterministik (AI yapılandırılmamış)"));

                l.onStageStart(burp.engine.DetectionStage.REPORT);
                for (Finding f : findings) {
                    reportFinding(message, f, "active-scan", "Fast Active Scan");
                }
                burp.engine.StageResult rep = burp.engine.StageResult.ok(
                        burp.engine.DetectionStage.REPORT, "Raporlandı: " + findings.size());
                rep.findings = findings;
                l.onStageComplete(burp.engine.DetectionStage.REPORT, rep);

                // For business-logic endpoints: generate AI-driven attack chains via WorkflowAnalyzer
                runWorkflowAnalysis(message, "active-scan", l);
            } catch (Exception e) {
                stderr.println("[✗] Fast active scan error: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }, "fast-active-scan");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Autonomous variant: instead of manually-added roles, harvest the distinct
     * sessions for the target host from proxy history, validate each in the background
     * (expired ones dropped), then run the matrix over the discovered roles. No setup.
     */
    public void runAutoAuthMatrix(IHttpRequestResponse seed, String source, boolean includeMutating,
                                  MultiSessionTester mtester, burp.authz.AuthMatrixPanel panel,
                                  burp.engine.StageListener listener) {
        final burp.engine.StageListener l = (listener != null)
                ? listener : new burp.engine.LoggingStageListener(stdout);
        Thread t = new Thread(() -> {
            try {
                l.onStageStart(burp.engine.DetectionStage.RECON);
                refreshLoginSessions(mtester, l);
                java.util.List<MultiSessionTester.UserSession> roles = discoverRoles(seed, mtester, panel, l);
                l.onStageComplete(burp.engine.DetectionStage.RECON,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.RECON, roles.size() + " geçerli rol"));

                List<IHttpRequestResponse> targets = selectSiteTargets(seed, source);
                executeMatrix(seed, targets, roles, includeMutating, mtester, panel, l);
            } catch (Exception e) {
                stderr.println("[✗] Auto auth matrix error: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }, "auto-auth-matrix");
        t.setDaemon(true);
        t.start();
    }

    /** Run configured auto-login profiles (if any) to add FRESH sessions before access-control tests. */
    // Login sessions are minted ONCE per campaign. runAutoAuthMatrix + runScenarioAccessHunt +
    // runAgenticAccessHunt EACH call refreshLoginSessions, so without this guard 3 profiles logged in
    // 3× = 9 logins ("aynı kullanıcı 3 kere"). The 3 hunts fire near-simultaneously in parallel threads,
    // so the guard is under a lock: the first mints, the rest (within TTL) reuse the fresh sessions in the
    // shared mtester. Fewer logins = less WAF exposure ("min istek maks bulgu").
    private final Object loginMintLock = new Object();
    private volatile long lastLoginMintNanos = 0L;
    private static final long LOGIN_MINT_TTL_NANOS = 5L * 60 * 1_000_000_000L; // 5 min (gateway SessionKey ~20 min)

    /** The freshest session minted from a login profile (description marks it "login-profili"), or null. */
    private MultiSessionTester.UserSession firstLoginProfileSession(MultiSessionTester mtester) {
        if (mtester == null || mtester.getSessions() == null) return null;
        MultiSessionTester.UserSession best = null;
        for (MultiSessionTester.UserSession s : mtester.getSessions()) {
            if (s == null || s.description == null || !s.description.contains("login-profili")) continue;
            if (best == null || (s.createdAt != null && best.createdAt != null && s.createdAt.after(best.createdAt))) best = s;
        }
        return best;
    }

    private void refreshLoginSessions(MultiSessionTester mtester, burp.engine.StageListener l) {
        if (mtester == null) return;
        java.util.List<burp.authz.LoginProfile> profiles = settings.getLoginProfiles();
        if (profiles.isEmpty()) return;
        synchronized (loginMintLock) {
            // Skip ONLY when minted recently AND the sessions are actually still present in the shared
            // mtester — otherwise (mtester cleared / new campaign) a stale timestamp would wrongly skip and
            // leave the auth matrix / BOLA with no identities.
            if (lastLoginMintNanos != 0L && (System.nanoTime() - lastLoginMintNanos) < LOGIN_MINT_TTL_NANOS
                    && mtester.hasLoginProfileSessions()) {
                if (l != null) l.onStageProgress(burp.engine.DetectionStage.RECON,
                        "🔑 Login oturumları güncel — yeniden giriş atlandı (kampanyada tekrar login önlendi)");
                return;
            }
            lastLoginMintNanos = System.nanoTime(); // mark inside the lock so parallel hunts don't all mint
            l.onStageProgress(burp.engine.DetectionStage.RECON,
                    profiles.size() + " login profili çalıştırılıyor (taze oturum)…");
            int n = new burp.authz.LoginManager(callbacks, helpers, stdout, stderr).loginAll(profiles, mtester, l);
            l.onStageProgress(burp.engine.DetectionStage.RECON, n + " taze oturum eklendi (login profillerinden)");
        }
    }

    /** True when {@code cand} is a fresher identity for a role than {@code cur}: a login-profile (freshly
     *  minted) session beats a manual one; between same-kind sessions the later createdAt wins. Stops the
     *  auth matrix from replaying a stale manual token that a fresh login already invalidated server-side
     *  (the gateway "Oturumunuz sonlanmıştır" cause). */
    private boolean fresherSession(MultiSessionTester.UserSession cand, MultiSessionTester.UserSession cur) {
        boolean candLogin = cand.description != null && cand.description.contains("login-profili");
        boolean curLogin = cur.description != null && cur.description.contains("login-profili");
        if (candLogin != curLogin) return candLogin;           // login-profile (fresh) session wins
        if (cand.createdAt != null && cur.createdAt != null) return cand.createdAt.after(cur.createdAt);
        return false;
    }

    /**
     * Roles for the auto matrix = one session per role, FRESHEST first (login-profile session over a stale
     * manual one, then latest createdAt), MERGED with sessions harvested+validated from proxy history
     * (expired dropped, deduped by role). Preferring the freshest avoids replaying a manual token that a
     * fresh login already invalidated server-side; still falls back to the manual/harvested session for
     * roles that have no login profile, so a user who added roles never sees an anonymous-only matrix.
     */
    private java.util.List<MultiSessionTester.UserSession> discoverRoles(IHttpRequestResponse seed,
                                                                         MultiSessionTester mtester,
                                                                         burp.authz.AuthMatrixPanel panel,
                                                                         burp.engine.StageListener l) {
        String host = helpers.analyzeRequest(seed).getUrl().getHost();
        java.util.List<MultiSessionTester.UserSession> roles = new java.util.ArrayList<>();
        java.util.Set<String> seenRoleNames = new java.util.HashSet<>();
        java.util.List<burp.authz.AuthMatrixPanel.IdentityInfo> display = new java.util.ArrayList<>();

        // 1) One session per role — pick the FRESHEST deterministically. A manual session and a freshly
        //    minted login-profile session BOTH live under the same roleName in mtester (a HashMap keyed by
        //    random UUID → nondeterministic iteration order). Preferring "whichever the map yields first"
        //    could hand the matrix the STALE manual session, whose body-carried token (e.g. gateway sessionToken)
        //    the login itself already invalidated server-side (single-session-per-user) → every replay comes
        //    back "Oturumunuz sonlanmıştır" and the whole matrix is garbage. So prefer the login-profile
        //    (fresh) session, then the later createdAt — mirroring firstLoginProfileSession(), which already
        //    fixed the single-session IDOR path.
        if (mtester != null && mtester.getSessions() != null) {
            java.util.Map<String, MultiSessionTester.UserSession> bestByRole = new java.util.LinkedHashMap<>();
            for (MultiSessionTester.UserSession s : mtester.getSessions()) {
                if (s == null || s.roleName == null) continue;
                String key = s.roleName.toLowerCase();
                MultiSessionTester.UserSession cur = bestByRole.get(key);
                if (cur == null || fresherSession(s, cur)) bestByRole.put(key, s);
            }
            for (MultiSessionTester.UserSession s : bestByRole.values()) {
                if (seenRoleNames.add(s.roleName.toLowerCase())) {
                    roles.add(s);
                    boolean fromLogin = s.description != null && s.description.contains("login-profili");
                    l.onStageProgress(burp.engine.DetectionStage.RECON,
                            "✓ " + s.roleName + (fromLogin ? " (taze login oturumu)" : " (elle eklenen oturum)")
                                    + " kullanılıyor");
                }
            }
        }

        // 2) Augment with sessions harvested from proxy history. Validation is fail-open: a token that
        //    is explicitly REJECTED (401/403/login) is dropped as expired, but one we cannot confirm
        //    because the target is down / 5xx / unreachable is KEPT (UNKNOWN) and flagged — otherwise a
        //    flaky or offline target silently collapses the matrix to anonymous-only.
        burp.authz.SessionHarvester harvester = new burp.authz.SessionHarvester(callbacks, helpers, stdout);
        java.util.List<burp.authz.SessionHarvester.DiscoveredRole> found = harvester.harvest(host);
        l.onStageProgress(burp.engine.DetectionStage.RECON,
                found.size() + " aday oturum history'den çıkarıldı (host=" + host + ")");
        for (burp.authz.SessionHarvester.DiscoveredRole dr : found) {
            if (dr.session == null || dr.session.roleName == null) continue;
            if (seenRoleNames.contains(dr.session.roleName.toLowerCase())) continue; // a manual role wins
            globalRateLimiter.acquire();
            burp.authz.SessionHarvester.Validity v = harvester.checkValidity(dr, mtester);
            dr.validity = v;
            int toks = dr.session.authTokens == null ? 0 : dr.session.authTokens.size();
            if (v == burp.authz.SessionHarvester.Validity.EXPIRED) {
                display.add(new burp.authz.AuthMatrixPanel.IdentityInfo(dr.session.roleName, toks,
                        "history · süresi dolmuş (token reddedildi) · " + dr.backing + " istek", false, false));
                l.onStageProgress(burp.engine.DetectionStage.RECON,
                        "✗ " + dr.session.roleName + " süresi dolmuş (token reddedildi) — atlandı");
                continue;
            }
            roles.add(dr.session);
            seenRoleNames.add(dr.session.roleName.toLowerCase());
            boolean verified = (v == burp.authz.SessionHarvester.Validity.VALID);
            display.add(new burp.authz.AuthMatrixPanel.IdentityInfo(dr.session.roleName, toks,
                    "history · " + (verified ? "doğrulandı" : "doğrulanamadı (hedef yanıt vermedi/5xx)")
                            + " · " + dr.backing + " istek · " + dr.detail, true, verified));
            if (verified) {
                l.onStageProgress(burp.engine.DetectionStage.RECON,
                        "✓ " + dr.session.roleName + " geçerli (" + dr.backing + " istek · " + dr.detail + ")");
            } else {
                l.onStageProgress(burp.engine.DetectionStage.RECON,
                        "⚠ " + dr.session.roleName + " doğrulanamadı — hedef yanıt vermedi/5xx; yine de matrise eklendi ("
                                + dr.backing + " istek)");
            }
        }
        if (panel != null) panel.setDiscoveredIdentities(display);
        if (roles.isEmpty()) {
            l.onStageProgress(burp.engine.DetectionStage.RECON,
                    "ⓘ History'de bu host için kimlik bulunamadı; matris yalnız anonim olarak çalışacak. "
                            + "Giriş yapılmış istekleri proxy'den geçirin ya da 'Rol Ekle' ile token ekleyin.");
        }
        return roles;
    }

    /**
     * Ground-truth BOLA hunt: harvest identities from history, build the object-ownership
     * {@link burp.authz.AccessModel} (history + silent active validation), then test
     * cross-owner access (replay each victim object as every other identity), judged by AI
     * with a negative control. The object is KNOWN to belong to a different identity → provable.
     */
    public void runScenarioAccessHunt(IHttpRequestResponse seed, boolean includeMutating,
                                      MultiSessionTester mtester, burp.engine.StageListener listener) {
        runScenarioAccessHunt(seed, includeMutating, mtester, listener, false);
    }

    /**
     * Merged BOLA/BAC campaign. {@code alsoAgentic=true} folds the former separate "agentic BOLA/BAC" and
     * "AI yüzey keşfi" runs into THIS pipeline: AI-discovered endpoints join the id-endpoint pool, and after
     * the deterministic ground-truth passes the AI agent runs over the SAME ownership model — so harvest +
     * validate + AccessModel are built ONCE, not three times across three concurrent campaigns.
     */
    public void runScenarioAccessHunt(IHttpRequestResponse seed, boolean includeMutating,
                                      MultiSessionTester mtester, burp.engine.StageListener listener,
                                      boolean alsoAgentic) {
        final burp.engine.StageListener l = (listener != null)
                ? listener : new burp.engine.LoggingStageListener(stdout);
        Thread t = new Thread(() -> {
            try {
                String host = helpers.analyzeRequest(seed).getUrl().getHost();
                l.onStageStart(burp.engine.DetectionStage.RECON);

                // #7: mint FRESH sessions from configured login profiles so cross-owner BOLA can run even
                // when proxy history has <2 identities. They land in mtester and become attacker roles below.
                refreshLoginSessions(mtester, l);

                burp.authz.SessionHarvester harvester =
                        new burp.authz.SessionHarvester(callbacks, helpers, stdout);
                java.util.List<burp.authz.SessionHarvester.DiscoveredRole> found = harvester.harvest(host);
                java.util.List<burp.authz.SessionHarvester.DiscoveredRole> valid = new java.util.ArrayList<>();
                java.util.List<MultiSessionTester.UserSession> sessions = new java.util.ArrayList<>();
                java.util.Set<String> seenRole = new java.util.HashSet<>();
                // (a) history-harvested identities carry OWNED OBJECTS (from their 200 traffic) → can be victims.
                for (burp.authz.SessionHarvester.DiscoveredRole dr : found) {
                    if (dr.session == null || dr.session.roleName == null) continue;
                    globalRateLimiter.acquire();
                    if (harvester.validate(dr, mtester) && seenRole.add(dr.session.roleName.toLowerCase())) {
                        valid.add(dr); sessions.add(dr.session);
                    }
                }
                // (b) manual + login-profile-minted sessions (fresh tokens; attacker-capable even without
                //     owned objects — they attack the history identities' objects).
                java.util.List<String> extraAttackers = new java.util.ArrayList<>();
                if (mtester != null && mtester.getSessions() != null) {
                    for (MultiSessionTester.UserSession s : mtester.getSessions()) {
                        if (s == null || s.roleName == null) continue;
                        if (seenRole.add(s.roleName.toLowerCase())) { sessions.add(s); extraAttackers.add(s.roleName); }
                    }
                }

                burp.authz.AccessModelBuilder builder =
                        new burp.authz.AccessModelBuilder(callbacks, helpers, stdout);
                burp.authz.AccessModel model = builder.build(valid, true, globalRateLimiter, l);
                // Register manual/minted sessions as attacker-only roles (own nothing, but can attack others).
                for (String r : extraAttackers) if (!model.roles.contains(r)) model.roles.add(r);
                l.onStageProgress(burp.engine.DetectionStage.RECON, "\n" + model.summary());
                l.onStageComplete(burp.engine.DetectionStage.RECON,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.RECON,
                                model.totalObjects() + " sahip-nesne / " + model.roles.size() + " kimlik"));

                l.onStageStart(burp.engine.DetectionStage.EXECUTE);
                java.util.Set<String> seen = new java.util.HashSet<>();
                int real = 0, fp = 0;

                // ALWAYS: endpoint-parameter → single-session IDOR across the HOST's id-bearing endpoints
                // (the visible "IDOR testi: gizli 'X'" steps; deterministic + ownership-aware, AI-INDEPENDENT).
                // Runs even with ≥2 accounts so parameter→IDOR coverage is NEVER skipped by the cross-owner
                // branch — the two are complementary (single-session finds IDOR with one identity; cross-owner
                // proves BOLA between two). Previously this was the else-branch, so 3 accounts hid these steps.
                {
                    // Candidate endpoints: seed + owned objects + the host's REAL proxy-history surface.
                    // The ownership model is often empty for body-carried sessions like gateway (SessionHarvester
                    // finds 0 identities), so without the history surface we'd only ever test the single seed
                    // → "no parameters detected". selectSiteTargets brings the id-bearing endpoints in.
                    java.util.List<IHttpRequestResponse> idEndpoints = new java.util.ArrayList<>();
                    idEndpoints.add(seed);
                    for (java.util.List<burp.authz.AccessModel.OwnedObject> objs : model.ownedByRole.values()) {
                        for (burp.authz.AccessModel.OwnedObject o : objs) {
                            if (o.request != null) idEndpoints.add(o.request);
                        }
                    }
                    try { idEndpoints.addAll(selectSiteTargets(seed, "both")); } catch (Exception ignore) {}
                    // Fold AI surface discovery in (was a separate concurrent "AI yüzey keşfi" run): the
                    // AI-proposed endpoints join the id-endpoint pool so newly-found surface gets the
                    // ownership-aware IDOR/BOLA treatment here instead of a 6th parallel campaign.
                    if (alsoAgentic) {
                        try {
                            idEndpoints.addAll(new burp.recon.AiEndpointDiscoverer(
                                    callbacks, helpers, aiClient, stdout, stderr)
                                    .discover(seed, globalRateLimiter, l));
                        } catch (Exception ignore) {}
                    }

                    // Inject the freshest minted login-profile session so we DON'T test on the seed's DEAD
                    // session (gateway SessionKey expires ~20 min; the body-carried sessionToken is swapped in).
                    // Without this the server answers "oturum sonlandı" to every replay and nothing is found.
                    MultiSessionTester.UserSession attacker = firstLoginProfileSession(mtester);
                    l.onStageProgress(burp.engine.DetectionStage.EXECUTE,
                            "Endpoint parametreleri → tek-oturum IDOR (" + idEndpoints.size() + " aday"
                                    + (attacker != null ? ", taze oturum: " + attacker.roleName : "") + ").");

                    java.util.Set<String> epSeen = new java.util.HashSet<>();
                    int scanned = 0;
                    for (IHttpRequestResponse ep0 : idEndpoints) {
                        if (scanned >= 40) break; // cap (each verify ~5-8 requests; throttle + WAF breaker apply)
                        String epKey;
                        try {
                            IRequestInfo eri = helpers.analyzeRequest(ep0);
                            epKey = burp.scan.EndpointKey.of(eri.getMethod(), eri.getUrl().getPath());
                        } catch (Exception ex) { continue; }
                        if (!epSeen.add(epKey)) continue; // one test per endpoint TEMPLATE (collapse id-variants)
                        IHttpRequestResponse ep = ep0;
                        if (attacker != null) {           // run on a fresh session, not the captured dead one
                            try {
                                byte[] fresh = mtester.applySession(ep0.getRequest(), attacker);
                                if (fresh != null) ep = new burp.spec.SyntheticHttpRequestResponse(fresh, ep0.getHttpService());
                            } catch (Exception ignore) {}
                        }
                        scanned++;
                        Finding f = verifyIdorCandidate(ep);
                        if (f != null && reportFindingDeduped(seed, f, "scenario-bola", "Single-Session IDOR", seen)) real++;
                    }
                    l.onStageProgress(burp.engine.DetectionStage.EXECUTE,
                            scanned + " uç tarandı · " + real + " tek-oturum IDOR bulgusu");
                    stdout.println("[✓] Single-session IDOR: " + scanned + " endpoints, " + real + " findings");
                }

                // ADDITIONALLY: cross-owner ground-truth BOLA when we have ≥2 identities AND shareable objects
                // (replay each victim's object as every other identity; read + write-IDOR). The strong path.
                if (model.roles.size() >= 2 && model.totalObjects() > 0) {
                    burp.authz.ScenarioAccessTester tester = new burp.authz.ScenarioAccessTester(
                            callbacks, helpers, mtester, aiClient, globalRateLimiter, stdout, stderr);
                    java.util.List<Finding> findings = tester.run(model, sessions, includeMutating, l);
                    for (Finding f : findings) {
                        if (f.isFalsePositive()) fp++; else real++;
                        reportFindingDeduped(seed, f, "scenario-bola", "Ground-Truth BOLA", seen);
                    }
                    l.onStageComplete(burp.engine.DetectionStage.EXECUTE,
                            burp.engine.StageResult.ok(burp.engine.DetectionStage.EXECUTE,
                                    findings.size() + " çapraz-sahip aday (" + model.roles.size() + " kimlik)"));
                    stdout.println("[✓] Ground-truth BOLA hunt: " + findings.size() + " candidates, " + real + " real");
                } else {
                    l.onStageComplete(burp.engine.DetectionStage.EXECUTE,
                            burp.engine.StageResult.ok(burp.engine.DetectionStage.EXECUTE,
                                    "tek-oturum IDOR tamam · çapraz-sahip için ≥2 kimlik + paylaşılır nesne gerekir ("
                                            + model.roles.size() + " kimlik / " + model.totalObjects() + " nesne)"));
                }

                // Multi-step CHAINED BOLA (slice 1): a real id VALUE produced by one endpoint's response,
                // injected into a DIFFERENT endpoint as another identity. Reaches non-guessable-id BOLA
                // (CustomerId/AccountNumber/IBAN/GUID) that single-step neighbour-walking cannot. Reuses the
                // same sessions + ownership machinery; bounded + rate-limited. Read-only unless aggressive.
                if (!sessions.isEmpty()) {
                    try {
                        java.util.List<IHttpRequestResponse> chainTargets = new java.util.ArrayList<>();
                        chainTargets.add(seed);
                        for (java.util.List<burp.authz.AccessModel.OwnedObject> objs : model.ownedByRole.values())
                            for (burp.authz.AccessModel.OwnedObject o : objs)
                                if (o.request != null) chainTargets.add(o.request);
                        try { chainTargets.addAll(selectSiteTargets(seed, "both")); } catch (Exception ignore) {}
                        burp.authz.ChainBolaTester chain = new burp.authz.ChainBolaTester(
                                callbacks, helpers, mtester, aiClient, globalRateLimiter, stdout, stderr);
                        for (Finding f : chain.run(chainTargets, sessions, host, includeMutating, l)) {
                            if (f.isFalsePositive()) fp++; else real++;
                            reportFindingDeduped(seed, f, "chain-bola", "Chain BOLA", seen);
                        }
                    } catch (Exception ex) {
                        stderr.println("[✗] Chain BOLA error: " + ex.getMessage());
                    }
                }

                // Merged agentic BOLA/BAC pass over the SAME ownership model (was a separate concurrent run
                // that rebuilt harvest+validate+AccessModel). A separate logging listener keeps the agent's
                // own stage lifecycle off this run's view; its findings still flow to the panel.
                if (alsoAgentic) {
                    l.onStageProgress(burp.engine.DetectionStage.EXECUTE,
                            "Agentic BOLA/BAC pass — aynı ownership modeli üzerinde (AI çok-adım/çapraz-sahip)…");
                    try {
                        runAgentPentestOverModel(seed, model, mtester, includeMutating,
                                new burp.engine.LoggingStageListener(stdout));
                    } catch (Exception ex) {
                        stderr.println("[✗] Merged agentic pass error: " + ex.getMessage());
                    }
                }

                l.onStageStart(burp.engine.DetectionStage.REPORT);
                l.onStageComplete(burp.engine.DetectionStage.REPORT,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.REPORT,
                                "Raporlandı: " + real + (fp > 0 ? " gerçek, " + fp + " FP" : "")));
            } catch (Exception e) {
                stderr.println("[✗] Scenario BOLA error: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }, "scenario-bola");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Copilot entry point for a whole-application IDOR/BAC/BOLA scenario. Uses the extension's own saved
     * identities ({@link #multiSessionTester}) so the Copilot can launch it with just (seed, view):
     *   1) ground-truth cross-owner BOLA over the whole host (needs >=2 identities — logs + bails if not),
     *   2) per-endpoint deterministic IDOR + Broken-Access-Control across the host (works with one identity;
     *      covers request-BODY ids like {@code customerId}, not just the URL).
     * Read-only cross-owner by default (GET replays only). All findings flow to the Copilot IDOR feed.
     */
    public void runIdorBolaScenario(IHttpRequestResponse seed, DetectionRunView crossOwnerView,
                                    DetectionRunView perEndpointView) {
        // (1) cross-owner ground-truth BOLA (its own daemon thread + view)
        runScenarioAccessHunt(seed, false, multiSessionTester, crossOwnerView);
        // (2) whole-host per-endpoint IDOR/BAC (its own daemon thread + view)
        runSiteScan(seed, perEndpointView);
    }

    /**
     * Agentic access-control hunt (the user's chosen "AI driver" mode): build the object-
     * ownership {@link burp.authz.AccessModel} and feed it to {@link burp.engine.AgentPentestEngine}
     * so the LLM drives PROVABLE cross-owner / multi-step BOLA/BAC scenarios grounded in real ownership.
     */
    public void runAgenticAccessHunt(IHttpRequestResponse seed, boolean includeMutating,
                                     MultiSessionTester mtester, burp.engine.StageListener listener) {
        Thread t = new Thread(() -> {
            try {
                String host = helpers.analyzeRequest(seed).getUrl().getHost();
                // #7: mint fresh sessions from login profiles so the agent has ≥2 identities for cross-session BOLA.
                if (listener != null) refreshLoginSessions(mtester, listener);
                burp.authz.SessionHarvester harvester =
                        new burp.authz.SessionHarvester(callbacks, helpers, stdout);
                java.util.List<burp.authz.SessionHarvester.DiscoveredRole> found = harvester.harvest(host);
                java.util.List<burp.authz.SessionHarvester.DiscoveredRole> valid = new java.util.ArrayList<>();
                for (burp.authz.SessionHarvester.DiscoveredRole dr : found) {
                    globalRateLimiter.acquire();
                    if (harvester.validate(dr, mtester)) valid.add(dr);
                }
                // Register discovered identities so the agent's replay_as_session can use them.
                java.util.Set<String> existing = new java.util.HashSet<>();
                for (MultiSessionTester.UserSession s : mtester.getSessions()) existing.add(s.roleName);
                for (burp.authz.SessionHarvester.DiscoveredRole dr : valid) {
                    if (existing.add(dr.session.roleName)) {
                        mtester.addSession(dr.session.roleName, "auto (history)", dr.session.authTokens);
                    }
                }
                burp.authz.AccessModel model = new burp.authz.AccessModelBuilder(callbacks, helpers, stdout)
                        .build(valid, false, globalRateLimiter, null); // history-only (fast) for the agentic context
                stdout.println("[AccessModel] " + model.totalObjects() + " owned objects / " + model.roles.size()
                        + " identities for " + host);
                stdout.println(model.summary());

                runAgentPentestOverModel(seed, model, mtester, includeMutating, listener);
            } catch (Exception e) {
                stderr.println("[✗] Agentic access hunt error: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }, "agentic-access");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Run the AI-driven cross-owner / multi-step BOLA/BAC agent over an ALREADY-BUILT ownership model.
     * Extracted so the merged BOLA/BAC campaign reuses the same {@link burp.authz.AccessModel} the
     * ground-truth pass just built (instead of the old separate 6th run that rebuilt harvest+validate+
     * AccessModel from scratch — 2× the setup requests). The agent reports its findings via
     * {@code reportFinding} independently of {@code listener}, so a caller may pass a separate logging
     * listener to keep the agent's stage lifecycle from fighting the ground-truth run's view.
     */
    private void runAgentPentestOverModel(IHttpRequestResponse seed, burp.authz.AccessModel model,
                                          MultiSessionTester mtester, boolean includeMutating,
                                          burp.engine.StageListener listener) {
        burp.engine.AgentPentestEngine agent = new burp.engine.AgentPentestEngine(
                callbacks, helpers, aiClient, settings, this, mtester, stdout, stderr);
        agent.setAccessModel(model);
        agent.setSharedRateLimiter(globalRateLimiter);
        agent.setForceSafeMode(!includeMutating);
        try {
            burp.playbook.PlaybookLibrary lib = burp.playbook.PlaybookLibrary.load(settings, stderr);
            burp.playbook.Playbook pb = lib.byId("bola-multisession");
            if (pb == null) pb = lib.byId("access-control-idor");
            if (pb != null) agent.setPlaybook(pb);
        } catch (Exception ignore) {
        }
        agent.run(seed, "scenario-agent", listener); // owns its stage lifecycle + reports internally
    }

    /**
     * Host-level fingerprint for exposed AI-application frameworks (Langflow/Flowise/LangServe/
     * Ollama) — an emerging, high-value surface Burp's scanner does not cover. Runs once per host
     * (guarded by {@link #aiFwProbedHosts}); SAFE benign identification GETs only, no exploit
     * payloads. Wired into the "everything" campaign as its own lightweight step.
     */
    public void runAiFrameworkProbe(IHttpRequestResponse seed, DetectionRunView ui) {
        final int[] found = {0};
        final boolean[] aborted = {false};
        Thread t = new Thread(() -> {
            try {
                String host = helpers.analyzeRequest(seed).getUrl().getHost();
                if (ui != null) ui.prepareSiteScan((host == null ? "?" : host) + " · AI uygulama yüzeyi", 1);
                burp.engine.StageListener l = (ui != null) ? ui : new burp.engine.LoggingStageListener(stdout);
                l.onStageStart(burp.engine.DetectionStage.RECON);
                if (host != null && aiFwProbedHosts.add(host.toLowerCase())) {
                    burp.recon.AiFrameworkProbe fwp = new burp.recon.AiFrameworkProbe(callbacks, helpers, stdout);
                    java.util.Set<String> seen = new java.util.HashSet<>();
                    for (Finding f : fwp.probe(seed, globalRateLimiter, l)) {
                        aiJudge(f, seed);
                        if (reportFindingDeduped(seed, f, "ai-framework", "AI Framework Exposure", seen)) found[0]++;
                    }
                }
                l.onStageComplete(burp.engine.DetectionStage.RECON,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.RECON,
                                found[0] > 0 ? (found[0] + " AI uygulama çatısı ifşası")
                                             : "AI uygulama çatısı tespit edilmedi"));
            } catch (Exception e) {
                stderr.println("[ai-framework] error: " + e.getMessage());
                aborted[0] = true;
            } finally {
                if (ui != null) ui.siteDone(found[0], aborted[0]);
            }
        }, "ai-framework");
        t.setDaemon(true);
        t.start();
    }

    /**
     * AI-assisted surface discovery + scan: the AI proposes hidden endpoints in the RECON
     * stage (sibling/admin/debug/internal variants) from observed traffic + JS, we verify
     * which exist, then run the full deterministic engine (AI-judged) on the NEW surface.
     * More AI in recon => more attack surface => more findings.
     */
    public void runSurfaceScan(IHttpRequestResponse seed, burp.engine.StageListener listener) {
        final burp.engine.StageListener l = (listener != null)
                ? listener : new burp.engine.LoggingStageListener(stdout);
        Thread t = new Thread(() -> {
            try {
                l.onStageStart(burp.engine.DetectionStage.RECON);
                // AI mode focuses on IDOR/BOLA/BAC: mine hidden params (IDOR fuel) but SKIP the /logs,/api
                // directory brute-forcing unless content discovery is explicitly enabled (default OFF).
                final boolean contentDisc = settings.isContentDiscoveryEnabled();
                burp.recon.AiEndpointDiscoverer disc = new burp.recon.AiEndpointDiscoverer(
                        callbacks, helpers, aiClient, stdout, stderr);
                List<IHttpRequestResponse> discovered = disc.discover(seed, globalRateLimiter, l, contentDisc);
                burp.recon.ForcedBrowser fb = null;
                if (contentDisc) {
                    // Forced browsing (wordlist) merged into the discovered surface (deduped by path).
                    fb = new burp.recon.ForcedBrowser(callbacks, helpers, stdout);
                    List<IHttpRequestResponse> wordlist = fb.discover(seed, globalRateLimiter, l);
                    java.util.Set<String> dpaths = new java.util.HashSet<>();
                    for (IHttpRequestResponse e : discovered) dpaths.add(pathOf(e));
                    for (IHttpRequestResponse e : wordlist) if (dpaths.add(pathOf(e))) discovered.add(e);
                }
                l.onStageComplete(burp.engine.DetectionStage.RECON,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.RECON,
                                contentDisc ? discovered.size() + " endpoint (AI + JS + wordlist)"
                                        : "dizin taraması kapalı — IDOR/BOLA/BAC odağı (gizli param madenciliği açık)"));

                l.onStageStart(burp.engine.DetectionStage.EXECUTE);
                burp.scan.ActiveScanEngine engine = new burp.scan.ActiveScanEngine(
                        callbacks, helpers, aiClient, settings, stdout, stderr, globalRateLimiter, false);
                java.util.Set<String> seen = new java.util.HashSet<>();
                int total = 0;

                // Forced-browsing findings (exposed sensitive files/dirs) — only when content discovery ran.
                if (fb != null) {
                    for (Finding f : fb.findings()) {
                        aiJudge(f, seed);
                        if (reportFindingDeduped(seed, f, "surface-scan", "Forced Browsing", seen)) total++;
                    }
                }

                // Feed AI-mined hidden parameters into the test engine (on the seed's real context).
                List<String> minedParams = disc.minedParams();
                if (minedParams != null && !minedParams.isEmpty()) {
                    burp.recon.ParamMiningTester pm = new burp.recon.ParamMiningTester(callbacks, helpers, stdout);
                    for (Finding f : pm.mine(seed, minedParams, globalRateLimiter, l)) {
                        aiJudge(f, seed);
                        if (reportFindingDeduped(seed, f, "surface-scan", "AI Param Mining", seen)) total++;
                    }
                    // Real IDOR/BOLA test on the honored id-like params: add the param to the request and run
                    // the ownership-aware IDOR engine (value-swap + public/own-data discrimination), so a
                    // hidden customerId/accountId that exposes another owner's record is PROVEN — not just
                    // "honored". Only surfaces when the deterministic discriminators + AI confirm it.
                    for (String idParam : pm.honoredIdParams()) {
                        if (l != null) l.onStageProgress(burp.engine.DetectionStage.EXECUTE,
                                "IDOR testi: gizli '" + idParam + "' parametresi (değer-swap + sahiplik)");
                        try {
                            byte[] req = helpers.addParameter(seed.getRequest(),
                                    helpers.buildParameter(idParam, "1", burp.IParameter.PARAM_URL));
                            IHttpRequestResponse synth =
                                    new burp.spec.SyntheticHttpRequestResponse(req, seed.getHttpService());
                            Finding idor = verifyIdorCandidate(synth); // ownership-aware IDOR + AI confirm, or null
                            if (idor != null) {
                                try { idor.setHttpRequest(new String(req, "UTF-8")); } catch (Exception ignore) {}
                                if (reportFindingDeduped(seed, idor, "surface-scan", "AI Param Mining → IDOR", seen)) total++;
                            }
                        } catch (Exception ignore) { }
                    }
                }

                for (IHttpRequestResponse ep : discovered) {
                    List<Finding> fs;
                    try {
                        fs = engine.scan(ep, "surface-scan", l);
                    } catch (Exception ex) {
                        continue;
                    }
                    for (Finding f : fs) {
                        aiJudge(f, ep);
                        if (reportFindingDeduped(ep, f, "surface-scan", "AI Surface Discovery", seen)) total++;
                    }
                }
                l.onStageComplete(burp.engine.DetectionStage.EXECUTE,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.EXECUTE,
                                discovered.size() + " endpoint tarandı, " + total + " bulgu"));
                l.onStageStart(burp.engine.DetectionStage.REPORT);
                l.onStageComplete(burp.engine.DetectionStage.REPORT,
                        burp.engine.StageResult.ok(burp.engine.DetectionStage.REPORT, "Raporlandı: " + total));
                stdout.println("[✓] AI surface scan done: " + discovered.size() + " endpoint, " + total + " finding");
            } catch (Exception e) {
                stderr.println("[✗] Surface scan error: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }, "surface-scan");
        t.setDaemon(true);
        t.start();
    }

    private String pathOf(IHttpRequestResponse m) {
        try { return helpers.analyzeRequest(m).getUrl().getPath(); }
        catch (Exception e) { return ""; }
    }

    private String respBody(byte[] resp) {
        try {
            if (resp == null) return "";
            IResponseInfo ri = helpers.analyzeResponse(resp);
            int off = ri.getBodyOffset();
            return new String(resp, off, Math.min(8192, Math.max(0, resp.length - off)), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    private int respStatus(byte[] resp) {
        try { return resp == null ? 0 : helpers.analyzeResponse(resp).getStatusCode(); }
        catch (Exception e) { return 0; }
    }

    /** Shared matrix run + report path used by both the manual and autonomous variants. */
    private void executeMatrix(IHttpRequestResponse seed, List<IHttpRequestResponse> targets,
                               java.util.List<MultiSessionTester.UserSession> roles, boolean includeMutating,
                               MultiSessionTester mtester, burp.authz.AuthMatrixPanel panel,
                               burp.engine.StageListener l) {
        l.onStageStart(burp.engine.DetectionStage.EXECUTE);
        l.onStageProgress(burp.engine.DetectionStage.EXECUTE,
                targets.size() + " endpoint × " + (roles.size() + 1) + " rol"
                        + (includeMutating ? " (durum-değiştiren dahil)" : " (yalnız GET/HEAD/OPTIONS)"));

        burp.authz.AuthMatrixEngine engine = new burp.authz.AuthMatrixEngine(
                callbacks, helpers, mtester, globalRateLimiter,
                settings.getActiveScanParallelism(), stdout, stderr);
        engine.setSessionKeeper(sessionKeeper); // #7: keep roles fresh / auto-relogin before the matrix
        burp.authz.AuthMatrix matrix = engine.run(targets, roles, includeMutating, l);

        l.onStageComplete(burp.engine.DetectionStage.EXECUTE,
                burp.engine.StageResult.ok(burp.engine.DetectionStage.EXECUTE,
                        matrix.rows.size() + " satır, " + matrix.violations.size() + " ihlal"));

        java.util.Set<String> seen = new java.util.HashSet<>();
        l.onStageStart(burp.engine.DetectionStage.REPORT);
        for (burp.authz.AuthMatrix.Violation v : matrix.violations) {
            Finding f = new Finding(v.type, v.severity, v.confidence, v.description,
                    v.url, v.evidence, burp.i18n.I18n.t("f.sm.authzmatrix.exp"), v.remediation);
            f.setAffectedUrl(v.url);
            IHttpRequestResponse fb = v.base != null ? v.base : seed;
            if (v.manipulatedBody != null && v.baselineBody != null) {
                f.setHttpResponse(v.manipulatedBody);
                aiJudgeAccess(f, v.evidence, v.baselineBody, v.manipulatedBody, v.controlBody); // BOLA: AI 3 yanıt (negatif kontrol dahil)
            } else {
                aiJudge(f, fb); // V1/V2 tek-yanıt
            }
            reportFindingDeduped(fb, f, "authz-matrix", "Authorization Matrix", seen);
        }
        l.onStageComplete(burp.engine.DetectionStage.REPORT,
                burp.engine.StageResult.ok(burp.engine.DetectionStage.REPORT,
                        "Raporlandı: " + matrix.violations.size()));
        l.onStageProgress(burp.engine.DetectionStage.REPORT, "\n" + matrix.renderText());
        if (panel != null) panel.setMatrix(matrix);

        stdout.println("[✓] Authorization matrix done: " + matrix.rows.size() + " endpoint, "
                + matrix.violations.size() + " violation");
    }

    /**
     * Public wrapper over the proven target-selection logic (host filter, static-asset
     * drop, method+path dedup, input-bearing priority, endpoint cap). Source is "site"
     * (site map) or "history" (proxy history). Reused by the autonomous whole-site hunt.
     */
    public List<IHttpRequestResponse> selectSiteTargets(IHttpRequestResponse seed, String source) {
        URL seedUrl = helpers.analyzeRequest(seed).getUrl();
        String host = seedUrl.getHost();
        return selectTargets(enumerateRaw(seedUrl, host, source), host);
    }

    /** Raw candidate entries from the chosen source: "site" (site map), "history" (proxy history), or "both" (merged). */
    private IHttpRequestResponse[] enumerateRaw(URL seedUrl, String host, String source) {
        if ("history".equals(source)) {
            return callbacks.getProxyHistory();
        }
        if ("both".equals(source)) {
            // Site map + proxy history merged; selectTargets dedups by method+path.
            List<IHttpRequestResponse> merged = new ArrayList<>();
            IHttpRequestResponse[] sm = callbacks.getSiteMap(seedUrl.getProtocol() + "://" + host);
            IHttpRequestResponse[] ph = callbacks.getProxyHistory();
            if (sm != null) merged.addAll(Arrays.asList(sm));
            if (ph != null) merged.addAll(Arrays.asList(ph));
            return merged.toArray(new IHttpRequestResponse[0]);
        }
        return callbacks.getSiteMap(seedUrl.getProtocol() + "://" + host);
    }

    /**
     * Autonomous whole-site hunt: enumerate the host's input-bearing endpoints, then
     * run the playbook-specialized agentic engine on each within a global budget
     * (concurrency / token / time), all sharing one rate limiter + site-wide dedup.
     * The batch driver; per-endpoint engine wiring is the {@code SiteAgentOrchestrator}'s.
     */
    public void runSiteHunt(IHttpRequestResponse seed, String source, DetectionRunView ui) {
        Thread t = new Thread(() -> {
            int conc = Math.max(1, settings.getAgentSiteConcurrency());
            long tokenStart = AIUsageStats.getInstance().getTotalTokens();
            long tokenBudget = settings.getAgentSiteTokenBudget();
            int mins = settings.getAgentSiteTimeBudgetMin();
            long deadline = mins > 0 ? System.currentTimeMillis() + mins * 60_000L : Long.MAX_VALUE;

            java.util.Set<String> reportedKeys = java.util.Collections.synchronizedSet(new HashSet<String>());
            burp.ambient.SiteAgentOrchestrator orch = new burp.ambient.SiteAgentOrchestrator(
                    callbacks, helpers, aiClient, settings, this, multiSessionTester,
                    globalRateLimiter, reportedKeys, stdout, stderr);
            orch.setForceSafeMode(true); // autonomous batch: never more aggressive than a human scan

            java.util.concurrent.ThreadPoolExecutor pool = new java.util.concurrent.ThreadPoolExecutor(
                    conc, conc, 30, TimeUnit.SECONDS,
                    new java.util.concurrent.ArrayBlockingQueue<Runnable>(Math.max(2, conc * 2)),
                    r -> { Thread th = new Thread(r, "site-hunt-w"); th.setDaemon(true); return th; },
                    new java.util.concurrent.ThreadPoolExecutor.CallerRunsPolicy());

            java.util.concurrent.atomic.AtomicInteger seedCounter = new java.util.concurrent.atomic.AtomicInteger();
            try {
                String host = helpers.analyzeRequest(seed).getUrl().getHost();
                List<IHttpRequestResponse> targets = selectSiteTargets(seed, source);
                if (ui != null) ui.prepareSiteScan(host + " · otonom av (" + targets.size() + " uç)", targets.size());
                stdout.println("[site-hunt] " + host + " - " + targets.size() + " endpoint(s), conc=" + conc
                        + ", tokenBudget=" + tokenBudget + ", timeMin=" + mins);

                int dispatched = 0;
                for (IHttpRequestResponse msg : targets) {
                    boolean over = (tokenBudget > 0
                            && AIUsageStats.getInstance().getTotalTokens() - tokenStart >= tokenBudget)
                            || System.currentTimeMillis() >= deadline;
                    if (over) { stdout.println("[site-hunt] bütçe doldu, durduruluyor"); break; }
                    if (ui != null && ui.isAborted()) break;
                    final int s = seedCounter.getAndIncrement();
                    pool.submit(() -> {
                        if (ui == null || !ui.isAborted()) orch.huntEndpoint(msg, s, ui);
                    });
                    dispatched++;
                }
                pool.shutdown();
                while (!pool.awaitTermination(500, TimeUnit.MILLISECONDS)) {
                    if (ui != null && ui.isAborted()) { pool.shutdownNow(); break; }
                }
                stdout.println("[site-hunt] done. dispatched=" + dispatched);
                if (ui != null) ui.siteDone(0, ui.isAborted());
            } catch (Exception e) {
                stderr.println("[site-hunt] error: " + e.getMessage());
                e.printStackTrace(stderr);
                pool.shutdownNow();
                if (ui != null) ui.siteDone(0, true);
            }
        }, "site-hunt");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Whole-site deterministic scan: enumerate the host's input-bearing endpoints from
     * Burp's site map AND proxy history (merged + deduped by method+path), then run the
     * deterministic engine on each. Progress is shown live in the DetectionPanel.
     */
    public void runSiteScan(IHttpRequestResponse seed, DetectionRunView ui) {
        runTargetsScan(seed, ui, "both");
    }

    private void runTargetsScan(IHttpRequestResponse seed, DetectionRunView ui, String source) {
        final int[] dupCounter = {0};
        Thread t = new Thread(() -> {
            int totalFindings = 0;
            boolean abortedEarly = false;
            try {
                URL seedUrl = helpers.analyzeRequest(seed).getUrl();
                String host = seedUrl.getHost();

                IHttpRequestResponse[] all = enumerateRaw(seedUrl, host, source);
                List<IHttpRequestResponse> targets = selectTargets(all, host);
                int withInput = countWithInput(targets);

                stdout.println("[" + source + "] " + host + " - " + targets.size() + " endpoint(s) ("
                        + withInput + " girdili) from " + (all == null ? 0 : all.length) + " entries");
                if (ui != null) {
                    ui.prepareSiteScan(host + " · " + source + " (" + withInput + " girdili)", targets.size());
                }
                if (targets.isEmpty()) {
                    if (ui != null) ui.siteLog("Bu host için taranacak uç yok. "
                            + "Önce siteyi Burp'tan gezin / istek atın.");
                    return;
                }

                burp.scan.ActiveScanEngine engine =
                        new burp.scan.ActiveScanEngine(callbacks, helpers, aiClient, settings, stdout, stderr, globalRateLimiter);

                // Run-level dedup: collapse site-wide repeats (e.g. missing headers
                // reported on every page) to a single finding per scan.
                Set<String> reportedKeys = new HashSet<>();

                int idx = 0;
                for (IHttpRequestResponse msg : targets) {
                    if (ui != null && ui.isAborted()) {
                        abortedEarly = true;
                        break;
                    }
                    idx++;
                    IRequestInfo ri = helpers.analyzeRequest(msg);
                    String url = ri.getUrl().toString();
                    if (ui != null) {
                        ui.siteStatus(idx + " / " + targets.size() + " uç taranıyor");
                        ui.siteLog("[" + idx + "/" + targets.size() + "] " + ri.getMethod() + " " + url);
                    }

                    int epFindings = 0;
                    int epDup = 0;
                    try {
                        List<Finding> fs = engine.scan(msg, source + "-scan", ui);
                        for (Finding f : fs) {
                            aiJudge(f, msg); // AI her bulguda karar verir (FP'leri işaretler)
                            if (reportedKeys.add(findingDedupKey(f))) {
                                reportFinding(msg, f, source + "-scan",
                                        "history".equals(source) ? "History Scan" : "Site Scan");
                                epFindings++;
                            } else {
                                epDup++;
                                dupCounter[0]++;
                            }
                        }
                    } catch (Exception e) {
                        if (ui != null) ui.siteLog("    hata: " + e.getMessage());
                    }

                    // Feed endpoint to chain detector for cross-request attack chain analysis
                    try { chainDetector.analyzeEndpoint(msg); } catch (Exception ignored) {}

                    totalFindings += epFindings;
                    if (ui != null) {
                        ui.siteLog("    -> " + epFindings + " bulgu"
                                + (epDup > 0 ? " (" + epDup + " tekrar atlandı)" : ""));
                    }
                }

                // After all endpoints scanned: discover and execute attack chains
                if (!abortedEarly) {
                    int chainCount = runChainDetection(targets, reportedKeys, source + "-scan", ui);
                    totalFindings += chainCount;
                }
            } catch (Exception e) {
                stderr.println("[" + source + "] error: " + e.getMessage());
                e.printStackTrace(stderr);
            } finally {
                if (ui != null && dupCounter[0] > 0) {
                    ui.siteLog("(" + dupCounter[0] + " tekrarlı bulgu birleştirildi — site geneli yapılandırma sorunları bir kez raporlandı)");
                }
                if (ui != null) ui.siteDone(totalFindings, abortedEarly);
                stdout.println("[" + source + "] done. findings=" + totalFindings
                        + ", duplicates suppressed=" + dupCounter[0]);
            }
        }, source + "-scan");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Pattern-based attack chain discovery across all scanned endpoints.
     * ChainAttackDetector was already fed via analyzeEndpoint() inside the scan loop;
     * here we run discoverChains() + executeChain() and report successful chains.
     * Returns the number of new findings reported.
     */
    private int runChainDetection(List<IHttpRequestResponse> targets, Set<String> reportedKeys,
                                   String tabId, DetectionRunView ui) {
        int found = 0;
        try {
            List<burp.api.ChainAttackDetector.APIChain> chains = chainDetector.discoverChains();
            if (chains.isEmpty()) return 0;
            if (ui != null) ui.siteLog("[zincir] " + chains.size() + " saldırı zinciri pattern'i tespit edildi — çalıştırılıyor...");

            // Build url→msg map for finding the IHttpRequestResponse to attach to reports
            Map<String, IHttpRequestResponse> urlIndex = new HashMap<>();
            for (IHttpRequestResponse msg : targets) {
                try { urlIndex.put(helpers.analyzeRequest(msg).getUrl().toString(), msg); } catch (Exception ignore) {}
            }

            for (burp.api.ChainAttackDetector.APIChain chain : chains) {
                if (chain.steps == null || chain.steps.isEmpty()) continue;
                try {
                    burp.api.ChainAttackDetector.ChainAttackResult result = chainDetector.executeChain(chain);
                    if (!result.successful) continue;

                    String severity = chain.severity != null ? chain.severity : "High";
                    Finding f = new Finding(
                            "Business Logic: " + chain.name,
                            severity, 0.80,
                            chain.description,
                            result.evidence,
                            chain.attackScenario != null ? chain.attackScenario : "",
                            result.remediation != null ? result.remediation : "");

                    // Find best matching IHttpRequestResponse (first step's URL)
                    String firstUrl = chain.steps.get(0).url;
                    IHttpRequestResponse anchor = urlIndex.getOrDefault(firstUrl, targets.isEmpty() ? null : targets.get(0));
                    if (anchor == null) continue;

                    aiJudge(f, anchor);
                    if (reportedKeys.add(findingDedupKey(f))) {
                        reportFinding(anchor, f, tabId, "Chain Attack");
                        found++;
                        if (ui != null) ui.siteLog("[zincir] Bulgu: " + f.getType());
                    }
                } catch (Exception e) {
                    stderr.println("[zincir] zincir çalıştırma hatası: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            stderr.println("[zincir] chain detection hatası: " + e.getMessage());
        }
        return found;
    }

    /**
     * AI-driven workflow attack chain generation for business-logic relevant endpoints.
     * Only runs if the URL matches auth/payment/user patterns AND AI is configured.
     * Generated chains are executed via ChainAttackDetector and reported.
     */
    private void runWorkflowAnalysis(IHttpRequestResponse message, String tabId, burp.engine.StageListener listener) {
        if (!aiReady()) return;
        try {
            String path = helpers.analyzeRequest(message).getUrl().getPath().toLowerCase();
            boolean isBusinessLogic = path.contains("/auth") || path.contains("/login") ||
                    path.contains("/user") || path.contains("/profile") ||
                    path.contains("/cart") || path.contains("/order") || path.contains("/checkout") ||
                    path.contains("/payment") || path.contains("/product") || path.contains("/price") ||
                    path.contains("/password") || path.contains("/reset") || path.contains("/register");
            if (!isBusinessLogic) return;

            stdout.println("[workflow] İş mantığı ucu — AI saldırı zinciri üretiyor: " + path);
            List<burp.api.ChainAttackDetector.APIChain> chains = workflowAnalyzer.generateAttackChains(message);
            if (chains == null || chains.isEmpty()) return;
            stdout.println("[workflow] " + chains.size() + " AI zinciri üretildi — çalıştırılıyor...");

            for (burp.api.ChainAttackDetector.APIChain chain : chains) {
                if (chain.steps == null || chain.steps.isEmpty()) continue;
                try {
                    burp.api.ChainAttackDetector.ChainAttackResult result = chainDetector.executeChain(chain);
                    if (!result.successful) continue;

                    String severity = chain.severity != null ? chain.severity : "High";
                    Finding f = new Finding(
                            "Business Logic (AI): " + chain.name,
                            severity, 0.75,
                            chain.description,
                            result.evidence,
                            chain.attackScenario != null ? chain.attackScenario : "",
                            result.remediation != null ? result.remediation : "");
                    aiJudge(f, message);
                    reportFinding(message, f, tabId, "Workflow Analysis");
                } catch (Exception e) {
                    stderr.println("[workflow] zincir çalıştırma hatası: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            stderr.println("[workflow] workflow analysis hatası: " + e.getMessage());
        }
    }

    private int countWithInput(List<IHttpRequestResponse> targets) {
        int n = 0;
        for (IHttpRequestResponse m : targets) {
            try {
                if (hasInput(helpers.analyzeRequest(m))) n++;
            } catch (Exception ignore) {
            }
        }
        return n;
    }

    /**
     * Static assets (images, fonts, css, js, media...) have no injectable attack
     * surface, so they are skipped entirely in bulk scans. Detected by file
     * extension AND by the response's inferred MIME type (covers extensionless
     * assets like /img?id=).
     */
    private boolean isStaticAsset(IRequestInfo ri, byte[] response) {
        String path = ri.getUrl().getPath();
        if (path == null) path = "/";
        if (path.toLowerCase().matches(
                ".*\\.(js|mjs|css|png|jpg|jpeg|gif|bmp|tif|tiff|svg|ico|webp|avif|vsf|"
                + "woff|woff2|ttf|otf|eot|map|mp4|mp3|wav|ogg|avi|mov|webm|pdf|zip|gz|rar)$")) {
            return true;
        }
        if (response != null) {
            try {
                String mime = helpers.analyzeResponse(response).getInferredMimeType();
                if (mime != null) {
                    String mm = mime.toLowerCase();
                    if (mm.contains("image") || mm.equals("jpeg") || mm.equals("png") || mm.equals("gif")
                            || mm.equals("css") || mm.equals("script") || mm.equals("font")
                            || mm.equals("video") || mm.equals("sound")) {
                        return true;
                    }
                }
            } catch (Exception ignore) {
            }
        }
        return false;
    }

    /**
     * Dedup key for run-level collapsing. Host-scoped issues (missing headers,
     * banners, insecure cookies, info/version disclosure, CORS, transport, and a
     * token/credential carried in the URL) are keyed by type+host+evidence so they
     * report once per host, not per URL. Per-endpoint issues (IDOR, injection,
     * broken auth on a specific endpoint, ...) include the full URL.
     * See {@link Finding#isHostScopedType}.
     */
    private String findingDedupKey(Finding f) {
        String type = f.getType() == null ? "" : f.getType();
        if (isHostWideType(type)) {
            // Include host so the same host-wide finding (misconfig/disclosure) on DIFFERENT domains
            // is NOT collapsed into one when a single campaign spans multiple hosts. Use a volatile-
            // insensitive evidence SIGNATURE (not the raw text) so an AI re-wording or a per-request
            // token/timestamp in the evidence doesn't defeat the "once per host" collapse.
            return type + "|" + hostOf(f.getAffectedUrl()) + "|" + Finding.evidenceSignature(f.getEvidence());
        }
        // Per-endpoint: strip volatile query params (socket.io t/sid, cache busters) so the same
        // endpoint polled with a fresh token each request is not reported again and again.
        String ev = f.getEvidence() == null ? "" : f.getEvidence().trim();
        return type + "|" + Finding.normalizeUrlForDedup(f.getAffectedUrl()) + "|" + ev;
    }

    /** Host (authority) portion of a URL string, lower-cased, or "" if unparseable. */
    private String hostOf(String url) {
        if (url == null || url.isEmpty()) return "";
        try {
            String h = new java.net.URI(url).getHost();
            return h == null ? "" : h.toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    private boolean isHostWideType(String type) {
        // Shared classifier so the run-level dedup and the Findings panel agree on
        // what "one per host" means (config/transport/session/disclosure + token-in-URL).
        return Finding.isHostScopedType(type);
    }

    /** A request has attack surface if it's non-GET/HEAD or carries url/body/json params. */
    private boolean hasInput(IRequestInfo ri) {
        String method = ri.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            return true;
        }
        for (IParameter p : ri.getParameters()) {
            byte tt = p.getType();
            if (tt == IParameter.PARAM_URL || tt == IParameter.PARAM_BODY || tt == IParameter.PARAM_JSON) {
                return true;
            }
        }
        return false;
    }

    /**
     * Select scan targets from a site map OR proxy history: filter by host, drop
     * static assets, dedup by method+path, and PRIORITIZE input-bearing requests
     * (POST/PUT/params) so they are never dropped by the endpoint cap.
     */
    private List<IHttpRequestResponse> selectTargets(IHttpRequestResponse[] all, String hostFilter) {
        int cap = settings.getSiteScanMaxEndpoints();
        if (cap <= 0) cap = 40; // safety fallback
        List<IHttpRequestResponse> withInput = new ArrayList<>();
        List<IHttpRequestResponse> noInput = new ArrayList<>();
        if (all == null) {
            return new ArrayList<>();
        }
        Set<String> seen = new HashSet<>();
        for (IHttpRequestResponse m : all) {
            if (m == null || m.getRequest() == null) {
                continue;
            }
            try {
                IRequestInfo ri = helpers.analyzeRequest(m);
                if (hostFilter != null && !hostFilter.equalsIgnoreCase(ri.getUrl().getHost())) {
                    continue;
                }
                if (isStaticAsset(ri, m.getResponse())) {
                    continue;
                }
                String path = ri.getUrl().getPath();
                if (path == null) path = "/";
                // Dedup by endpoint TEMPLATE (ids/uuids/hashes → {id}) so duplicate history requests
                // that differ only in a resource id collapse to one AI run instead of many.
                String key = burp.scan.EndpointKey.of(ri.getMethod(), path);
                if (!seen.add(key)) {
                    continue;
                }
                if (hasInput(ri)) {
                    withInput.add(m);
                } else {
                    noInput.add(m);
                }
            } catch (Exception ignore) {
            }
        }
        // Input-bearing requests first, then fill with the rest, capped.
        List<IHttpRequestResponse> out = new ArrayList<>(withInput);
        for (IHttpRequestResponse m : noInput) {
            if (out.size() >= cap) break;
            out.add(m);
        }
        if (out.size() > cap) {
            out = new ArrayList<>(out.subList(0, cap));
        }
        return out;
    }



    // OLD CODE REMOVED - Keeping only AI-powered testing
    // businessLogicTester, idorTester, jwtTester are no longer called
    // Everything goes through AI now


    /**
     * Save dynamic test finding to database
     */
    private void saveDynamicTestFinding(String testType, String findingType, String severity,
            String description, String evidence, String exploitation,
            String remediation, String url) {
        try {
            dbManager.saveDynamicTestFinding(
                    url,
                    testType,
                    findingType,
                    severity,
                    description != null ? description : "",
                    evidence != null ? evidence : "",
                    exploitation != null ? exploitation : "",
                    remediation != null ? remediation : "",
                    0 // duration - will be calculated per test later
            );
        } catch (Exception e) {
            stderr.println("[✗] Failed to save dynamic test finding to database: " + e.getMessage());
        }
    }

    // ============================================================
    // Reusable services consumed by the staged DetectionPipeline
    // ============================================================

    /**
     * Expose the local RAG/knowledge-base context for the detection engine.
     */
    public String getRagContext(String url, String httpRequest, String httpResponse) {
        return buildLocalRagContext(url, httpRequest, httpResponse);
    }

    /**
     * Like {@link #reportFinding}, but with site-wide dedup against a shared key set: only reports if the
     * finding's dedup key is fresh. Returns true only if the finding was actually SURFACED (fresh AND not
     * suppressed as an FP), so callers that count "findings" report the visible total, not suppressed FPs.
     * Used by parallel agents that share one {@code reportedKeys} set so a site-wide issue is raised once.
     */
    public boolean reportFindingDeduped(IHttpRequestResponse message, Finding finding,
            String tabId, String testType, java.util.Set<String> reportedKeys) {
        String key = findingDedupKey(finding); // reuse existing private keyer
        synchronized (reportedKeys) {
            if (!reportedKeys.add(key)) {
                return false; // already reported in this run/site
            }
        }
        return reportFinding(message, finding, tabId, testType); // true only if surfaced (not a suppressed FP)
    }

    /**
     * Persist a finding, raise a Burp issue, and push it to the Findings panel.
     * Consolidated reporting path used by the detection engine.
     */
    public boolean reportFinding(IHttpRequestResponse message, Finding finding, String tabId, String testType) {
        try {
            // SQL Injection and XSS are intentionally NOT scanned/reported by this extension (covered by
            // Burp's own scanner). Drop any such finding from EVERY source — deterministic engine, agentic
            // pentester, autonomous hunter, AI adjudication — before it reaches Burp/DB/panel/observer.
            if (isDisabledVulnType(finding)) return false;

            // Faz 0: AI-flagged false positives are still persisted (RAG/FP store reads them)
            // but never surfaced to Burp's issue list or the Findings panel.
            boolean suppress = shouldSuppress(finding);

            // Persist a one-line audit record of EVERY filed finding (incl. site-scan findings that
            // siteDone() only counts) — type, claimed vs effective severity, confidence, oracle verdict,
            // suppression — so runs can be reviewed for false positives after the fact.
            logFindingAudit(finding, testType, suppress);

            if (!suppress) {
                createBurpIssue(message, finding);
            }

            saveDynamicTestFinding(
                    testType,
                    finding.getType(),
                    finding.getSeverity(),
                    finding.getDescription(),
                    finding.getEvidence(),
                    finding.getExploitation(),
                    finding.getRemediation(),
                    finding.getAffectedUrl() != null ? finding.getAffectedUrl() : "");

            // Persist to the findings table too (RAG + FP store read from here) and capture the row id.
            try {
                String req = finding.getHttpRequest();
                String resp = finding.getHttpResponse();
                if ((req == null || req.isEmpty()) && message != null && message.getRequest() != null) {
                    req = new String(message.getRequest(), "UTF-8");
                }
                int id = dbManager.saveFindingReturningId(tabId, finding, req, resp);
                if (id > 0) finding.setDbId(id);
            } catch (Exception e) {
                stderr.println("[!] saveFindingReturningId error: " + e.getMessage());
            }

            if (!suppress && findingsPanel != null) {
                final Finding ff = finding;
                javax.swing.SwingUtilities.invokeLater(() -> findingsPanel.addFinding(ff, message));
            }

            // Push to any registered observer (e.g. the Copilot IDOR feed). Non-suppressed only, so
            // AI-flagged false positives never raise a Copilot IDOR alert. Must never break reporting.
            if (!suppress) {
                java.util.function.BiConsumer<Finding, IHttpRequestResponse> obs = findingObserver;
                if (obs != null) {
                    try { obs.accept(finding, message); } catch (Exception ignore) { }
                }
            }
            return !suppress; // surfaced to Burp/panel? (suppressed FPs are persisted but not shown)
        } catch (Exception e) {
            stderr.println("[!] reportFinding error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Register an observer notified of every NON-suppressed reported finding, from any source
     * (deterministic active scan, agentic pentester, autonomous hunter). The Copilot uses this to
     * surface confirmed IDOR/BOLA the moment it is reported. Fail-safe: observer errors are swallowed.
     */
    public void setFindingObserver(java.util.function.BiConsumer<Finding, IHttpRequestResponse> obs) {
        this.findingObserver = obs;
    }

    /** Faz 0 gate: suppress surfacing (Burp issue + panel) for AI-flagged false positives.
     *  Findings are still written to the DB so the RAG/FP store keeps learning.
     *  (Faz 1 extends this to high-severity findings lacking deterministic evidence.) */
    /** SQL Injection and XSS are disabled extension-wide: never scanned, never reported, from any source.
     *  Matched on the canonical finding type so AI-named variants ("Blind SQL Injection", "Reflected XSS",
     *  "Cross-Site Scripting (XSS)") are caught too. NOTE: "Cross-Site Tracing"/"Cross-Site Request Forgery"
     *  are deliberately NOT matched. */
    private static boolean isDisabledVulnType(Finding f) {
        if (f == null || f.getType() == null) return false;
        String t = f.getType().toLowerCase(java.util.Locale.ROOT);
        return t.contains("sql injection")
                || t.contains("xss")
                || t.contains("cross-site scripting")
                || t.contains("cross site scripting");
    }

    private boolean shouldSuppress(Finding f) {
        if (f == null) return false;
        if (f.isFalsePositive()) return true;
        // A finding the first gate CONFIRMED but the INDEPENDENT second pass could not reproduce is NOT a
        // false positive — it is genuinely uncertain. Surface it flagged for human review (severity capped
        // elsewhere) rather than silently dropping it. This is the only case that overrides the gate below.
        if (f.isNeedsReview()) return false;
        // Suppress-unless-confirmed: a candidate worth reporting only if the AI CONFIRMS it (a single-session
        // IDOR with foreign owner tokens but no ownership ground truth). If the verdict is anything other than
        // CONFIRMED — AI refuted / unavailable / undecided / not configured — it stays unproven → hide it.
        if (f.needsAiConfirmation() && f.getOracleVerdict() != burp.Finding.OracleVerdict.CONFIRMED) return true;
        return false;
    }

    /** One-line FP-audit record of a filed finding, written to ~/.appsechunter/logs/. Never throws. */
    private void logFindingAudit(Finding f, String testType, boolean suppressed) {
        try {
            if (f == null) return;
            String url = f.getAffectedUrl() == null ? "" : f.getAffectedUrl();
            String host = url;
            try { host = new java.net.URL(url).getHost(); } catch (Exception ignore) {}
            String claim = f.getSeverity();
            String eff = f.getEffectiveSeverity();
            String sevPart = claim != null && claim.equalsIgnoreCase(eff) ? eff : claim + "→" + eff;
            ScanLogger.get().log(host,
                    "[FINDING] " + f.getType()
                            + " | sev=" + sevPart
                            + " | conf=" + String.format("%.0f%%", f.getConfidence() * 100)
                            + " | verdict=" + f.getOracleVerdict()
                            + " | P=" + f.getEffectivePriority()
                            + (suppressed ? " | SUPPRESSED(FP)" : "")
                            + " | via=" + testType
                            + " | " + url);
        } catch (Exception ignore) {
            // auditing must never break reporting
        }
    }

    /**
     * Create Burp issue from finding
     */
    private void createBurpIssue(IHttpRequestResponse message, Finding finding) {
        try {
            IScanIssue issue = new CustomScanIssue(
                    message.getHttpService(),
                    helpers.analyzeRequest(message).getUrl(),
                    new IHttpRequestResponse[] { message },
                    finding,
                    helpers);

            callbacks.addScanIssue(issue);
        } catch (Exception e) {
            stderr.println("[✗] Failed to create Burp issue: " + e.getMessage());
        }
    }

    /**
     * Get active scans
     */
    public Map<String, ScanStatus> getActiveScans() {
        return new HashMap<>(activeScans);
    }

    /**
     * Set findings panel for adding findings from scans
     */
    public void setFindingsPanel(FindingsPanel findingsPanel) {
        this.findingsPanel = findingsPanel;
    }

    /**
     * Add listener
     */
    public void addListener(ScanListener listener) {
        listeners.add(listener);
    }

    /**
     * Notify listeners
     */
    private void notifyListeners(String event, String scanId, String url, String tabId, ScanResult result) {
        for (ScanListener listener : listeners) {
            try {
                listener.onScanEvent(event, scanId, url, tabId, result);
            } catch (Exception e) {
                stderr.println("[✗] Listener error: " + e.getMessage());
            }
        }
    }

    /**
     * Shutdown
     */
    public void shutdown() {
        executor.shutdown();
        try {
            executor.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    /**
     * Scan status class
     */
    public static class ScanStatus {
        public enum State {
            QUEUED, RUNNING, COMPLETED, FAILED
        }

        private String scanId;
        private String tabId;
        private String url;
        private State state;
        private ScanResult result;
        private String error;
        private long startTime;

        public ScanStatus(String scanId, String url, State state) {
            this.scanId = scanId;
            this.url = url;
            this.state = state;
            this.startTime = System.currentTimeMillis();
        }

        public String getScanId() {
            return scanId;
        }

        public String getTabId() {
            return tabId;
        }

        public void setTabId(String tabId) {
            this.tabId = tabId;
        }

        public String getUrl() {
            return url;
        }

        public State getState() {
            return state;
        }

        public void setState(State state) {
            this.state = state;
        }

        public ScanResult getResult() {
            return result;
        }

        public void setResult(ScanResult result) {
            this.result = result;
        }

        public String getError() {
            return error;
        }

        public void setError(String error) {
            this.error = error;
        }

        public long getStartTime() {
            return startTime;
        }
    }

    /**
     * Scan listener interface
     */
    public interface ScanListener {
        void onScanEvent(String event, String scanId, String url, String tabId, ScanResult result);
    }
}
