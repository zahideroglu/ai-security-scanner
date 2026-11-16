package burp.ai;

import burp.*;
import burp.authz.OwnershipOracle;
import org.json.*;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI-Powered False Positive Filter
 * Uses AI to verify vulnerability findings and reduce false positives
 *
 * This is a MAJOR DIFFERENTIATING feature!
 * Burp Scanner has HIGH false positive rate and requires manual triage.
 * We use AI to automatically validate findings with high accuracy.
 *
 * @author Zahid Eroglu
 */
public class AIFalsePositiveFilter {

    private QwenAPIClient aiClient;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public static class ValidationResult {
        public boolean isValidVulnerability;
        public double confidence;          // 0.0 - 1.0
        public String exploitability;      // "High", "Medium", "Low", "None"
        public String reasoning;
        public List<String> recommendations;
        public boolean needsManualReview;
        public boolean verificationUnavailable; // AI down / unparseable -> verification could not run (fail-closed)

        public ValidationResult() {
            this.recommendations = new ArrayList<>();
        }
    }

    public AIFalsePositiveFilter(QwenAPIClient aiClient,
                                IExtensionHelpers helpers,
                                PrintWriter stdout,
                                PrintWriter stderr) {
        this.aiClient = aiClient;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * Verify a finding using AI
     */
    public ValidationResult verifyFinding(Finding finding,
                                         IHttpRequestResponse baseRequest,
                                         IHttpRequestResponse testRequest,
                                         ContextInfo context) {
        return verifyFinding(finding, baseRequest, testRequest, context, null);
    }

    public ValidationResult verifyFinding(Finding finding,
                                         IHttpRequestResponse baseRequest,
                                         IHttpRequestResponse testRequest,
                                         ContextInfo context,
                                         String localKbContext) {
        try {
            stdout.println("[*] AI verification for: " + finding.getType());

            // Build verification prompt
            String prompt = buildVerificationPrompt(finding, baseRequest,
                                                   testRequest, context, localKbContext);

            // Send to AI
            List<QwenAPIClient.Message> messages = new ArrayList<>();
            messages.add(new QwenAPIClient.Message("system", getSystemPrompt()));
            messages.add(new QwenAPIClient.Message("user", prompt));

            JSONObject aiResponse = aiClient.chatCompletion(messages);

            // Parse AI response
            ValidationResult result = parseAIResponse(aiResponse);

            if (result.isValidVulnerability) {
                stdout.println("[+] AI confirmed vulnerability (confidence: " +
                             String.format("%.2f", result.confidence * 100) + "%)");
            } else {
                stdout.println("[-] AI marked as false positive");
            }

            return result;

        } catch (Exception e) {
            stderr.println("[!] AI verification error: " + e.getMessage());
            e.printStackTrace(stderr);

            // Fail-CLOSED: verification could not run. Keep the finding but mark it unverified so the
            // caller downgrades a high-severity claim instead of letting it stand.
            ValidationResult result = new ValidationResult();
            result.isValidVulnerability = true;  // don't hard-delete (low findings still survive)
            result.confidence = 0.0;
            result.needsManualReview = true;
            result.verificationUnavailable = true;
            result.reasoning = "AI verification failed: " + e.getMessage();
            return result;
        }
    }

    private static final String[] GENERIC_LENSES = {
        "Be a STRICT skeptic: default to FALSE POSITIVE unless the evidence DIRECTLY proves exploitation.",
        "Require DIRECT evidence: a reflected payload must be unencoded/executed; an 'error' must be a real "
            + "stack/DB error, not a generic or expected message.",
        "Consider benign explanations: could this be intended behavior, a WAF block, caching, or network "
            + "latency rather than a real vulnerability?"
    };

    /**
     * Adversarial multi-lens verification for high-severity (non-access-control) findings: runs the
     * single-finding verifier once per diverse lens and confirms only on a STRICT majority. Reduces
     * false positives without relying on raw model intelligence.
     */
    public ValidationResult verifyConsensus(Finding finding, IHttpRequestResponse baseRequest,
                                            ContextInfo context, String localKbContext) {
        int votes = GENERIC_LENSES.length, yes = 0, unavail = 0;
        double confSum = 0; boolean manual = false; String exploit = "Medium";
        StringBuilder reasons = new StringBuilder();
        for (int i = 0; i < votes; i++) {
            ValidationResult r = verifyFindingLensed(finding, baseRequest, context, localKbContext, GENERIC_LENSES[i]);
            if (r.verificationUnavailable) unavail++;
            if (r.isValidVulnerability) yes++;
            confSum += r.confidence;
            if (r.needsManualReview) manual = true;
            if (r.exploitability != null && !r.exploitability.isEmpty()) exploit = r.exploitability;
            if (r.reasoning != null && !r.reasoning.isEmpty())
                reasons.append("v").append(i + 1).append(": ").append(trunc(r.reasoning, 160)).append("  ");
        }
        ValidationResult agg = new ValidationResult();
        // Exclude fail-open votes (AI down/unparseable force isValidVulnerability=true) from the majority,
        // and fail CLOSED when most lenses couldn't verify — a 503 storm must not manufacture a CONFIRMED.
        agg.isValidVulnerability = ((yes - unavail) * 2 > votes); // strict majority of ACTUALLY-verified yes
        agg.confidence = confSum / votes;
        agg.exploitability = exploit;
        agg.needsManualReview = manual || (yes != 0 && yes != votes);
        agg.verificationUnavailable = (unavail * 2 > votes); // most lenses unavailable -> unverified
        agg.reasoning = "Adversarial oylama " + yes + "/" + votes
                + (agg.isValidVulnerability ? " (DOĞRULANDI)" : " (reddedildi)") + ". " + reasons.toString().trim();
        stdout.println("[*] consensus " + finding.getType() + ": " + yes + "/" + votes);
        return agg;
    }

    private ValidationResult verifyFindingLensed(Finding finding, IHttpRequestResponse baseRequest,
                                                 ContextInfo context, String localKbContext, String lens) {
        try {
            String prompt = buildVerificationPrompt(finding, baseRequest, baseRequest, context, localKbContext);
            List<QwenAPIClient.Message> messages = new ArrayList<>();
            messages.add(new QwenAPIClient.Message("system", getSystemPrompt() + "\n\nVERIFIER LENS: " + lens));
            messages.add(new QwenAPIClient.Message("user", prompt));
            return parseAIResponse(aiClient.chatCompletion(messages));
        } catch (Exception e) {
            ValidationResult r = new ValidationResult();
            r.isValidVulnerability = true; r.confidence = 0.0; r.needsManualReview = true;
            r.verificationUnavailable = true; r.reasoning = "lens verify failed: " + e.getMessage();
            return r;
        }
    }

    /**
     * AI-driven BOLA/IDOR detection: compares the legitimate (baseline) response with the
     * response returned after changing the object id / swapping identity, and decides if a
     * DIFFERENT owner's object was exposed. {@code isValidVulnerability=true} => BOLA/IDOR confirmed.
     */
    public ValidationResult judgeAccessControl(String findingType, String manipulation,
                                               String baselineBody, String manipulatedBody,
                                               ContextInfo context) {
        return judgeAccessControl(findingType, manipulation, baselineBody, manipulatedBody, null, context);
    }

    /** 3-reference variant: also pass the negative-control body (response to a definitely-invalid id / unauth). */
    public ValidationResult judgeAccessControl(String findingType, String manipulation,
                                               String baselineBody, String manipulatedBody,
                                               String negativeControlBody, ContextInfo context) {
        try {
            stdout.println("[*] AI access-control (BOLA/IDOR) judgment: " + findingType);
            List<QwenAPIClient.Message> messages = new ArrayList<>();
            messages.add(new QwenAPIClient.Message("system", getAccessSystemPrompt()));
            messages.add(new QwenAPIClient.Message("user",
                    buildAccessControlPrompt(findingType, manipulation, baselineBody, manipulatedBody,
                            negativeControlBody, context)));
            JSONObject aiResponse = aiClient.chatCompletion(messages);
            return parseAIResponse(aiResponse);
        } catch (Exception e) {
            stderr.println("[!] AI access judgment error: " + e.getMessage());
            ValidationResult result = new ValidationResult();
            result.isValidVulnerability = true; // don't hard-delete
            result.confidence = 0.0;
            result.needsManualReview = true;
            result.verificationUnavailable = true; // fail-closed: caller downgrades unverified high-sev
            result.reasoning = "AI access judgment failed: " + e.getMessage();
            return result;
        }
    }

    private static final String[] AC_LENSES = {
        "Be a STRICT skeptic: default to NOT a vulnerability unless the tampered response unmistakably contains "
            + "another principal's object data.",
        "Focus on identity fields: are there foreign owner identifiers (names, emails, user ids, ownership fields) "
            + "in the tampered response that are ABSENT from both the baseline and the negative control?",
        "Focus on the negative control: if the tampered response is not clearly different from the negative-control "
            + "response, the endpoint ignores the identifier and it is NOT a vulnerability."
    };

    /**
     * Adversarial multi-vote BOLA/IDOR judgment: runs {@link #judgeAccessControl} once per
     * diverse verifier lens (skeptic / identity-fields / negative-control) and confirms only
     * on a STRICT majority. Split votes are flagged for manual review. Reduces false positives.
     */
    public ValidationResult judgeAccessControlConsensus(String findingType, String manipulation,
                                                        String baselineBody, String manipulatedBody,
                                                        String negativeControlBody, ContextInfo context) {
        // ---- Deterministic pre-filter GATE (cost + FP): resolve the easy cases WITHOUT spending 3 AI
        // lens calls. AutorizePro spends its LLM only when a cheap comparison is inconclusive; we do the
        // same but with our stronger ownership oracle. This fires on the FIRST encounter (the HTTP-layer
        // response cache only helps on exact repeats), so it is the real token-saving lever.
        ValidationResult gated = accessControlGate(baselineBody, manipulatedBody, negativeControlBody);
        if (gated != null) {
            stdout.println("[*] BOLA/IDOR gate: resolved deterministically → AI skipped");
            return gated;
        }
        int votes = AC_LENSES.length;
        int yes = 0;
        int unavail = 0;
        double confSum = 0;
        boolean manual = false;
        String exploit = "Medium";
        StringBuilder reasons = new StringBuilder();
        for (int i = 0; i < votes; i++) {
            String lensed = (manipulation == null ? "" : manipulation) + "\n\nVERIFIER LENS: " + AC_LENSES[i];
            ValidationResult r = judgeAccessControl(findingType, lensed, baselineBody, manipulatedBody,
                    negativeControlBody, context);
            if (r.verificationUnavailable) unavail++;
            if (r.isValidVulnerability) yes++;
            confSum += r.confidence;
            if (r.needsManualReview) manual = true;
            if (r.exploitability != null && !r.exploitability.isEmpty()) exploit = r.exploitability;
            if (r.reasoning != null && !r.reasoning.isEmpty()) {
                reasons.append("v").append(i + 1).append(": ").append(trunc(r.reasoning, 200)).append("  ");
            }
        }
        ValidationResult agg = new ValidationResult();
        // Fail-open votes (AI down/unparseable) force isValidVulnerability=true; exclude them so a 503
        // storm cannot manufacture a CONFIRMED BOLA. Mark the whole verdict unavailable when most lenses
        // could not verify, so the caller fails CLOSED (downgrades) instead of reporting.
        agg.isValidVulnerability = ((yes - unavail) * 2 > votes); // strict majority of ACTUALLY-verified yes
        agg.verificationUnavailable = (unavail * 2 > votes);
        agg.confidence = confSum / votes;
        agg.exploitability = exploit;
        agg.needsManualReview = manual || (yes != 0 && yes != votes); // a split vote warrants a human look
        agg.reasoning = "Adversarial oylama " + yes + "/" + votes
                + (agg.isValidVulnerability ? " (DOĞRULANDI)" : " (reddedildi)") + ". " + reasons.toString().trim();
        stdout.println("[*] BOLA/IDOR consensus: " + yes + "/" + votes + " -> "
                + (agg.isValidVulnerability ? "real" : "false-positive"));
        return agg;
    }

    /**
     * Cheap deterministic gate run BEFORE the 3-lens AI vote (AutorizePro's "only spend the LLM on
     * genuinely ambiguous cases", but using our stronger ownership oracle). Resolves the obvious cases:
     *   • manipulated body empty / trivially small → cannot judge → unavailable (fail-closed).
     *   • manipulated ≈ baseline (caller's own data) → NOT a cross-owner hit (deterministic false positive).
     *   • manipulated ≈ negative control (id ignored) → NOT a vulnerability (deterministic false positive).
     * Returns null when the case is genuinely ambiguous and MUST go to the AI vote. Ground-truth CONFIRMED
     * findings never reach the equivalence branch — their callers only invoke the judge once the bodies are
     * already proven distinct — so the gate can only refute a not-yet-proven candidate, never a real hit.
     */
    private ValidationResult accessControlGate(String baselineBody, String manipulatedBody,
                                               String negativeControlBody) {
        String m = manipulatedBody == null ? "" : manipulatedBody;
        if (m.replaceAll("\\s+", "").length() < 5) {
            ValidationResult r = new ValidationResult();
            r.isValidVulnerability = true; r.confidence = 0.0; r.needsManualReview = true;
            r.verificationUnavailable = true; // fail-closed: an empty body is not judgeable
            r.reasoning = "Deterministik kapı: manipüle yanıt boş/çok küçük — yargılanamaz (fail-closed).";
            return r;
        }
        boolean eqBaseline = baselineBody != null
                && OwnershipOracle.bodiesEquivalent(manipulatedBody, baselineBody);
        boolean eqControl = negativeControlBody != null && !negativeControlBody.isEmpty()
                && OwnershipOracle.bodiesEquivalent(manipulatedBody, negativeControlBody);
        if (eqBaseline || eqControl) {
            ValidationResult r = new ValidationResult();
            r.isValidVulnerability = false; r.confidence = 0.9; r.exploitability = "None";
            r.needsManualReview = false; r.verificationUnavailable = false;
            r.reasoning = "Deterministik kapı: manipüle yanıt "
                    + (eqBaseline ? "taban (çağıranın kendi verisi)" : "negatif-kontrol (id yok sayılıyor)")
                    + " ile eşdeğer → çapraz-sahip erişimi yok, AI'ya sorulmadı.";
            return r;
        }
        return null; // ambiguous → escalate to the AI vote
    }

    private String getAccessSystemPrompt() {
        return "You are an expert adjudicator for broken access control (BOLA/IDOR). You compare HTTP response "
             + "bodies from the SAME request sent under different identities/ids:\n"
             + "• RESPONSE A = the legitimate owner's response (baseline).\n"
             + "• RESPONSE B = the response after tampering with an object identifier or swapping the "
             + "session/identity (the attacker's view).\n"
             + "• NEGATIVE CONTROL (when provided) = the response to a definitely-invalid id / unauthenticated call.\n"
             + "IGNORE DYNAMIC FIELDS when comparing — timestamps, dates, traceID/requestID/correlationId, "
             + "nonces, CSRF tokens, session ids, pagination cursors, ETags, signed-URL signatures. Compare only "
             + "the stable, ownership-bearing structure and content.\n"
             + "OWNERSHIP RULE: if RESPONSE B shows the CALLER'S OWN identity (the same owner fields as RESPONSE "
             + "A, or the caller's own account/name/email/id), the control is ENFORCED → this is NOT a "
             + "vulnerability. It is a real BOLA/IDOR ONLY if RESPONSE B contains ANOTHER owner's object data "
             + "(names, emails, account/customer/person ids, IBANs, ownership fields) that is ALSO absent from "
             + "BOTH RESPONSE A and the negative control.\n"
             + "CRITICAL: if RESPONSE B is essentially identical to the NEGATIVE CONTROL, the endpoint IGNORES "
             + "the identifier → NOT a vulnerability. Id reflection alone (our injected id echoed back) is NEVER "
             + "proof. An empty / error / access-denied / login body is NOT a leak.\n"
             + "Always respond in STRICT, MINIFIED JSON only — no markdown, no code fences, no prose.";
    }

    private String buildAccessControlPrompt(String findingType, String manipulation,
                                            String baselineBody, String manipulatedBody,
                                            String negativeControlBody, ContextInfo context) {
        StringBuilder p = new StringBuilder();
        p.append("Analyze a potential ").append(findingType)
         .append(" (broken object/function level access control).\n\n");
        if (context != null) {
            p.append("Technology: ").append(context.getTechnology())
             .append(" | Framework: ").append(context.getFramework()).append("\n");
        }
        p.append("Manipulation performed: ").append(manipulation == null ? "(n/a)" : manipulation).append("\n\n");
        p.append("ORACLE (expected-safe): the SAME request under a DIFFERENT id/identity MUST be denied "
                + "(401/403/404) or return ONLY the caller's own data. A 200 that returns ANOTHER owner's "
                + "object is the finding.\n\n");
        p.append("=== RESPONSE A (legitimate owner / baseline) ===\n").append(trunc(baselineBody, 1800)).append("\n\n");
        p.append("=== RESPONSE B (after tampering: other id / other identity) ===\n")
         .append(trunc(manipulatedBody, 1800)).append("\n\n");
        if (negativeControlBody != null && !negativeControlBody.isEmpty()) {
            p.append("=== NEGATIVE CONTROL (definitely-invalid id / unauth) ===\n")
             .append(trunc(negativeControlBody, 1800)).append("\n\n");
            p.append("If RESPONSE B is essentially the same as this NEGATIVE CONTROL, the endpoint ignores the "
                    + "identifier → set isValidVulnerability=false.\n\n");
        }
        p.append("Decide (IGNORE dynamic fields: timestamps, traceID/requestID, nonces, CSRF, session ids, ETags):\n");
        p.append("- Does RESPONSE B expose a DIFFERENT principal's object/data than RESPONSE A?\n");
        p.append("- Or is it the caller's OWN data, the same object, static, empty, an error, or access-denied?\n");
        p.append("- List the specific foreign-owner tokens (names/emails/ids/ownership fields) present in "
                + "RESPONSE B but ABSENT from BOTH RESPONSE A and the negative control — these are the evidence.\n\n");
        p.append("Set isValidVulnerability=true ONLY if it is a real BOLA/IDOR (another owner's data exposed, "
                + "not explained by the negative control, and not the caller's own identity).\n");
        p.append("Respond in STRICT MINIFIED JSON only (no markdown, no prose):\n");
        p.append("{\"isValidVulnerability\":true/false,\"confidence\":0.0-1.0,"
                + "\"exploitability\":\"High\"/\"Medium\"/\"Low\"/\"None\","
                + "\"reasoning\":\"what differs / why (owner fields, ids, names)\","
                + "\"needsManualReview\":true/false,\"recommendations\":[\"...\"]}\n");
        return p.toString();
    }

    private String trunc(String s, int n) {
        if (s == null || s.isEmpty()) return "(empty)";
        return s.length() <= n ? s : s.substring(0, n) + "…[truncated]";
    }

    /**
     * Concrete, per-type false-positive checklist injected into the verification prompt. These encode the
     * exact FP patterns that fooled the deterministic layer in real scans, so the AI rejects them too.
     */
    private String typeSpecificFpChecklist(String type) {
        String t = type == null ? "" : type.toLowerCase();
        StringBuilder s = new StringBuilder("=== TYPE-SPECIFIC FALSE-POSITIVE CHECKS (apply strictly) ===\n");
        if (t.contains("ssrf")) {
            s.append("- SSRF is REAL only if the EVIDENCE RESPONSE contains ACTUAL fetched internal/cloud-metadata "
                   + "content (e.g. ami-id, instance-id, iam/security-credentials, accessKeyId). If the body is a "
                   + "login page, an HTML page, a redirect, or merely REFLECTS the payload URL (the words 'meta-data'/'169.254' "
                   + "appear only because our payload was echoed), it is a FALSE POSITIVE.\n");
        } else if (t.contains("idor") || t.contains("bola") || t.contains("object")) {
            s.append("- IDOR/BOLA is REAL only if the evidence response exposes ANOTHER user's/tenant's private object "
                   + "(foreign names/emails/ids/ownership fields absent from baseline & control). Different sizes for a "
                   + "PUBLIC asset (chart/graphic/image/market data) keyed by an id are EXPECTED → FALSE POSITIVE. "
                   + "An image/binary body is not an owned object.\n");
        } else if (t.contains("access control") || t.contains("broken access") || t.contains("unauthenticated")) {
            s.append("- A pre-auth endpoint (login, captcha, token issuance, register, password reset, language/culture, "
                   + "warmup, health) returning 200 to an anonymous client is CORRECT, not a flaw. Reaching a public page, "
                   + "an error, a redirect, or a static asset is NOT a bypass. REAL only if a genuinely protected resource "
                   + "(another user's data, an admin function) is served without proper authorization.\n");
        } else if (t.contains("sensitive") || t.contains("path") || t.contains("file") || t.contains("discovery")) {
            s.append("- A 'discovered' path is REAL only if the EVIDENCE RESPONSE is the actual sensitive content "
                   + "(e.g. real .env KEY=VALUE lines, a [core] git config, a directory listing, an admin UI). If it is a "
                   + "WAF/block page, a generic error, a login wall, or the SPA index (same template returned for many "
                   + "paths), it is a FALSE POSITIVE.\n");
        } else if (t.contains("hidden parameter") || t.contains("parameter")) {
            s.append("- A honoured hidden parameter is REAL only if it EXPOSES additional restricted data/behaviour. If "
                   + "the response merely changed because it hit a WAF/block/error page (often SMALLER, generic), it is a "
                   + "FALSE POSITIVE.\n");
        } else if (t.contains("captcha")) {
            s.append("- A CAPTCHA bypass is REAL only if the EVIDENCE RESPONSE shows the server PROCESSED the request "
                   + "without a valid CAPTCHA — it reached credential validation (e.g. 'invalid username/password'), "
                   + "succeeded, issued a token, or advanced to an OTP/next step, OR is indistinguishable from the "
                   + "with-CAPTCHA baseline (control). If the response instead ASKS FOR or REJECTS the CAPTCHA "
                   + "('captcha required/invalid/expired', 'verify you are human', 'güvenlik kodu'), the control IS "
                   + "enforced → FALSE POSITIVE. A generic error/redirect/block page is NOT proof of bypass.\n");
        } else if (t.contains("brute") || t.contains("password")) {
            s.append("- 'Missing brute-force protection' needs enough attempts to be meaningful and no CAPTCHA/lockout in "
                   + "play. A weak-password claim is REAL only if a guess produced a genuinely AUTHENTICATED response.\n");
        } else {
            s.append("- Reject intentional/expected error messages, payload reflection without execution, network-jitter "
                   + "timing, WAF blocks, and bare status codes. Require direct evidence of impact in the evidence response.\n");
        }
        return s.toString();
    }

    /**
     * Build verification prompt
     */
    private String buildVerificationPrompt(Finding finding,
                                          IHttpRequestResponse baseRequest,
                                          IHttpRequestResponse testRequest,
                                          ContextInfo context,
                                          String localKbContext) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("You are a security expert verifying a potential vulnerability finding.\n\n");

        // Context information
        prompt.append("=== CONTEXT ===\n");
        if (context != null) {
            prompt.append("Technology: ").append(context.getTechnology()).append("\n");
            prompt.append("Framework: ").append(context.getFramework()).append("\n");
            prompt.append("Database: ").append(context.getDatabase()).append("\n");
            if (context.isWafDetected()) {
                prompt.append("WAF: ").append(context.getWafSignature()).append("\n");
            }
        }

        if (localKbContext != null && !localKbContext.trim().isEmpty()) {
            prompt.append("\n=== LOCAL KB CONTEXT ===\n");
            prompt.append(localKbContext.trim()).append("\n");
        }

        // Finding details
        prompt.append("\n=== FINDING ===\n");
        prompt.append("Type: ").append(finding.getType()).append("\n");
        prompt.append("Severity: ").append(finding.getSeverity()).append("\n");
        prompt.append("Confidence: ").append(finding.getConfidence()).append("\n");
        prompt.append("Description: ").append(finding.getDescription()).append("\n");

        if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
            prompt.append("\nEvidence:\n").append(finding.getEvidence()).append("\n");
        }

        // The ACTUAL response the detector fired on (the probe/manipulated response). Without this the
        // AI only sees the baseline and rubber-stamps reflections/block pages. This is the evidence to judge.
        if (finding.getHttpResponse() != null && !finding.getHttpResponse().isEmpty()) {
            prompt.append("\n=== EVIDENCE RESPONSE (the response that triggered this finding) ===\n")
                  .append(trunc(finding.getHttpResponse(), 1800)).append("\n");
        }
        if (finding.getControlResponse() != null && !finding.getControlResponse().isEmpty()) {
            prompt.append("\n=== NEGATIVE-CONTROL RESPONSE (invalid id / unauth) ===\n")
                  .append(trunc(finding.getControlResponse(), 1200))
                  .append("\nIf the evidence response is essentially the same as this control, it is NOT a vulnerability.\n");
        }
        prompt.append("\n").append(typeSpecificFpChecklist(finding.getType())).append("\n");

        // Baseline request
        if (baseRequest != null) {
            IRequestInfo baseReqInfo = helpers.analyzeRequest(baseRequest);
            prompt.append("\n=== BASELINE REQUEST ===\n");
            prompt.append("URL: ").append(baseReqInfo.getUrl().toString()).append("\n");
            prompt.append("Method: ").append(baseReqInfo.getMethod()).append("\n");

            if (baseRequest.getResponse() != null) {
                IResponseInfo baseRespInfo = helpers.analyzeResponse(baseRequest.getResponse());
                prompt.append("\nBaseline Response Status: ").append(baseRespInfo.getStatusCode()).append("\n");
                prompt.append("Baseline Response Length: ").append(baseRequest.getResponse().length).append("\n");

                // Response body excerpt
                int bodyOffset = baseRespInfo.getBodyOffset();
                if (bodyOffset < baseRequest.getResponse().length) {
                    String body = new String(baseRequest.getResponse(), bodyOffset,
                        Math.min(1200, baseRequest.getResponse().length - bodyOffset));
                    prompt.append("\nBaseline Response Body (excerpt):\n").append(body).append("\n");
                }
            }
        }

        // Test request with payload
        if (testRequest != null) {
            IRequestInfo testReqInfo = helpers.analyzeRequest(testRequest);
            prompt.append("\n=== TEST REQUEST (with payload) ===\n");
            prompt.append("URL: ").append(testReqInfo.getUrl().toString()).append("\n");
            prompt.append("Method: ").append(testReqInfo.getMethod()).append("\n");

            if (testRequest.getResponse() != null) {
                IResponseInfo testRespInfo = helpers.analyzeResponse(testRequest.getResponse());
                prompt.append("\nTest Response Status: ").append(testRespInfo.getStatusCode()).append("\n");
                prompt.append("Test Response Length: ").append(testRequest.getResponse().length).append("\n");

                // Response body excerpt
                int bodyOffset = testRespInfo.getBodyOffset();
                if (bodyOffset < testRequest.getResponse().length) {
                    String body = new String(testRequest.getResponse(), bodyOffset,
                        Math.min(500, testRequest.getResponse().length - bodyOffset));
                    prompt.append("\nTest Response Body (excerpt):\n").append(body).append("\n");
                }

                // Highlight differences
                if (baseRequest != null && baseRequest.getResponse() != null) {
                    IResponseInfo baseRespInfo = helpers.analyzeResponse(baseRequest.getResponse());
                    int statusDiff = testRespInfo.getStatusCode() - baseRespInfo.getStatusCode();
                    int lengthDiff = testRequest.getResponse().length - baseRequest.getResponse().length;

                    prompt.append("\n=== DIFFERENCES ===\n");
                    prompt.append("Status Code Diff: ").append(statusDiff).append("\n");
                    prompt.append("Response Length Diff: ").append(lengthDiff).append(" bytes\n");
                }
            }
        }

        // Verification questions
        prompt.append("\n=== VERIFICATION REQUIRED ===\n");
        prompt.append("Please analyze this finding and determine:\n\n");
        prompt.append("1. Is this a TRUE POSITIVE or FALSE POSITIVE?\n");
        prompt.append("2. What is your confidence level (0-100%)?\n");
        prompt.append("3. Is the vulnerability actually exploitable?\n");
        prompt.append("4. What is the exploitability level (High/Medium/Low/None)?\n");
        prompt.append("5. Does it need manual review by a human analyst?\n");
        prompt.append("6. What are your specific recommendations?\n\n");

        prompt.append("Common FALSE POSITIVE patterns to watch for:\n");
        prompt.append("- Error messages that are intentional/expected\n");
        prompt.append("- Payload reflection without actual execution\n");
        prompt.append("- Time delays caused by network latency, not injection\n");
        prompt.append("- WAF blocks mistaken for vulnerabilities\n");
        prompt.append("- Honeypot responses\n\n");

        prompt.append("Respond in JSON format:\n");
        prompt.append("{\n");
        prompt.append("  \"isValidVulnerability\": true/false,\n");
        prompt.append("  \"confidence\": 0.0-1.0,\n");
        prompt.append("  \"exploitability\": \"High\"/\"Medium\"/\"Low\"/\"None\",\n");
        prompt.append("  \"reasoning\": \"Detailed explanation...\",\n");
        prompt.append("  \"needsManualReview\": true/false,\n");
        prompt.append("  \"recommendations\": [\"recommendation 1\", \"recommendation 2\"]\n");
        prompt.append("}\n");

        return prompt.toString();
    }

    /**
     * System prompt for AI
     */
    private String getSystemPrompt() {
        return "You are a STRICT security finding adjudicator. Your job is to separate TRUE vulnerabilities "
             + "from FALSE POSITIVES, and you must be rigorous about EVIDENCE QUALITY: when the evidence is weak, "
             + "circumstantial, or single-sample, default to false positive (isValidVulnerability=false).\n"
             + "Rules:\n"
             + "- TIMING-BASED claims (e.g. command injection via 'sleep N'): the measured delay MUST match the "
             + "injected magnitude — a 'sleep 5' must add ~5s, 'sleep 10' ~10s. A sub-second or few-hundred-ms delta "
             + "is NOT proof; it is almost certainly network jitter/load — refute it. Real proof needs the delay to "
             + "SCALE with the sleep value across trials, or an out-of-band signal.\n"
             + "- REFLECTION/XSS: the payload must appear UNENCODED in an executable context; HTML-encoded or "
             + "JSON-escaped reflection is not exploitable.\n"
             + "- ACCESS CONTROL: a real flaw exposes ANOTHER principal's data, or a privileged action succeeding "
             + "under a low-privilege identity — not the caller's own data, an error, a redirect, or a bare status code.\n"
             + "- A status code alone (200/201/302/401/403/500) is NOT a vulnerability without concrete impact evidence.\n"
             + "Consider context and exploitability. Always respond in valid JSON.";
    }

    /**
     * Parse AI response
     */
    private ValidationResult parseAIResponse(JSONObject aiResponse) {
        ValidationResult result = new ValidationResult();

        String content = extractContent(aiResponse);
        if (content == null || content.trim().isEmpty()) {
            result.isValidVulnerability = true; result.confidence = 0.0;
            result.needsManualReview = true; result.verificationUnavailable = true;
            result.reasoning = "AI response empty/unreadable";
            return result;
        }

        // Strip markdown code fences (```json … ```) so a fenced verdict still parses.
        String cleaned = stripFences(content);

        // Primary: parse the outermost {…} as JSON.
        int jsonStart = cleaned.indexOf('{');
        int jsonEnd = cleaned.lastIndexOf('}') + 1;
        if (jsonStart >= 0 && jsonEnd > jsonStart) {
            try {
                JSONObject analysis = new JSONObject(cleaned.substring(jsonStart, jsonEnd));
                // Prefer our schema; fall back to the AutorizePro-style {"res":"true|false|unknown"} contract.
                result.isValidVulnerability = analysis.has("isValidVulnerability")
                        ? analysis.optBoolean("isValidVulnerability", true)
                        : (analysis.has("is_vulnerable")
                            ? analysis.optBoolean("is_vulnerable", true)
                            : parseResFlag(analysis, true));
                result.confidence = clamp01(analysis.optDouble("confidence", 0.5));
                result.exploitability = analysis.optString("exploitability", "Unknown");
                result.reasoning = analysis.optString("reasoning", analysis.optString("reason", "No reasoning provided"));
                result.needsManualReview = analysis.optBoolean("needsManualReview", false);
                if ("unknown".equalsIgnoreCase(analysis.optString("res", ""))) result.needsManualReview = true;
                if (analysis.has("recommendations")) {
                    JSONArray recsArray = analysis.getJSONArray("recommendations");
                    for (int i = 0; i < recsArray.length(); i++) result.recommendations.add(recsArray.getString(i));
                }
                return result;
            } catch (Exception ignore) {
                // malformed JSON (prose after the object, a stray brace, truncation) → try field salvage
            }
        }

        // Salvage: pull the individual fields with regexes even when the JSON is malformed / prose-wrapped.
        ValidationResult salvaged = salvage(cleaned);
        if (salvaged != null) return salvaged;

        // Nothing usable → fail-closed (keep the finding, mark unverified so the caller downgrades).
        result.isValidVulnerability = true; result.confidence = 0.0;
        result.needsManualReview = true; result.verificationUnavailable = true;
        result.reasoning = "AI response format error";
        return result;
    }

    /** Pull the assistant message text out of the completion, tolerant of OpenAI/Ollama/text shapes. */
    private String extractContent(JSONObject aiResponse) {
        if (aiResponse == null) return null;
        try { return aiResponse.getJSONArray("choices").getJSONObject(0)
                .getJSONObject("message").getString("content"); } catch (Exception ignore) {}
        try { String t = aiResponse.getJSONArray("choices").getJSONObject(0).optString("text", null);
              if (t != null && !t.isEmpty()) return t; } catch (Exception ignore) {}
        try { return aiResponse.getJSONObject("message").getString("content"); } catch (Exception ignore) {}
        return null;
    }

    private static final Pattern FENCE = Pattern.compile("```(?:json)?\\s*(.*?)\\s*```",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    private String stripFences(String s) {
        if (s == null) return null;
        Matcher m = FENCE.matcher(s.trim());
        return m.find() ? m.group(1).trim() : s.trim();
    }

    /** Map the AutorizePro-style {"res":"true|false|unknown|bypassed|enforced"} verdict to our boolean. */
    private boolean parseResFlag(JSONObject a, boolean dflt) {
        String res = a.optString("res", null);
        if (res == null) return dflt;
        res = res.trim().toLowerCase();
        return res.equals("true") || res.equals("yes") || res.equals("bypassed") || res.equals("vulnerable");
    }

    private static final Pattern SALV_FLAG = Pattern.compile(
            "\"?(?:isvalidvulnerability|is_vulnerable|res|vulnerable)\"?\\s*[:=]\\s*\"?"
            + "(true|false|yes|no|unknown|bypassed|enforced)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SALV_CONF = Pattern.compile(
            "\"?confidence\"?\\s*[:=]\\s*([0-9]*\\.?[0-9]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SALV_REASON = Pattern.compile(
            "\"?reason(?:ing)?\"?\\s*[:=]\\s*\"([^\"]{0,300})", Pattern.CASE_INSENSITIVE);

    /** Regex field-salvage for when the model wrapped/broke the JSON. Returns null if no verdict flag found. */
    private ValidationResult salvage(String content) {
        try {
            Matcher mf = SALV_FLAG.matcher(content);
            if (!mf.find()) return null;
            String v = mf.group(1).toLowerCase();
            ValidationResult r = new ValidationResult();
            boolean notVuln = v.equals("false") || v.equals("no") || v.equals("enforced") || v.equals("unknown");
            r.isValidVulnerability = !notVuln;
            if (v.equals("unknown")) r.needsManualReview = true; // model itself was unsure
            Matcher mc = SALV_CONF.matcher(content);
            r.confidence = mc.find() ? clamp01(Double.parseDouble(mc.group(1))) : 0.5;
            Matcher mr = SALV_REASON.matcher(content);
            r.reasoning = mr.find() ? mr.group(1) : "salvaged from malformed AI JSON";
            r.exploitability = "Unknown";
            return r;
        } catch (Exception e) {
            return null;
        }
    }

    private double clamp01(double d) {
        if (Double.isNaN(d)) return 0.0;
        // some models emit 0–100 confidence; fold it back into 0–1 before clamping.
        if (d > 1.0 && d <= 100.0) d = d / 100.0;
        return d < 0 ? 0 : (d > 1 ? 1 : d);
    }

    /**
     * Quick validation for simple checks (without full AI analysis)
     */
    public boolean quickValidate(Finding finding, IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return false;
        }

        String responseStr = new String(response.getResponse()).toLowerCase();

        // Check for obvious false positives
        if (finding.getType().contains("SQL")) {
            // If we see WAF blocks, might be false positive
            if (responseStr.contains("blocked") ||
                responseStr.contains("suspicious activity") ||
                responseStr.contains("security violation")) {
                stdout.println("[-] Possible WAF block detected, marking for AI review");
                return false;
            }

            // Look for actual SQL errors
            if (!responseStr.contains("sql") &&
                !responseStr.contains("mysql") &&
                !responseStr.contains("ora-") &&
                !responseStr.contains("sqlexception")) {
                stdout.println("[-] No SQL error indicators found");
                return false;
            }
        }

        // XSS validation
        if (finding.getType().contains("XSS")) {
            // Check if payload is actually reflected
            if (finding.getEvidence() != null) {
                String evidence = finding.getEvidence().toLowerCase();
                if (!responseStr.contains(evidence.toLowerCase())) {
                    stdout.println("[-] Payload not reflected in response");
                    return false;
                }
            }
        }

        return true;  // Looks valid, proceed with full AI verification
    }
}
