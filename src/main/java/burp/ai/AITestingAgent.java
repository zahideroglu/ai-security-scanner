package burp.ai;

import burp.*;
import org.json.*;
import java.io.PrintWriter;
import java.util.*;

/**
 * AI Testing Agent - AI decides what requests to send
 *
 * User request: "yapılacak istekleri de ai karar verip istek atabilsin"
 * (Let AI decide what requests to make and send them)
 *
 * @author Zahid Eroglu
 */
public class AITestingAgent {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private AiApiClient aiClient;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public AITestingAgent(IBurpExtenderCallbacks callbacks,
                         IExtensionHelpers helpers,
                         AiApiClient aiClient,
                         PrintWriter stdout,
                         PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * Let AI analyze and decide what test requests to send
     */
    public List<TestResult> runAIGuidedTesting(IHttpRequestResponse baseMessage) {
        List<TestResult> results = new ArrayList<>();

        stdout.println("\n╔════════════════════════════════════════════╗");
        stdout.println("║   AI AUTONOMOUS TESTING MODE               ║");
        stdout.println("║   AI will decide what requests to send     ║");
        stdout.println("╚════════════════════════════════════════════╝\n");

        try {
            // Step 1: Ask AI to analyze the request and plan tests
            stdout.println("[1/3] AI analyzing request and planning tests...");
            TestPlan plan = askAIForTestPlan(baseMessage);

            stdout.println("[+] AI created test plan with " + plan.tests.size() + " tests");
            stdout.println();

            // Step 2: Execute each test AI suggested
            stdout.println("[2/3] Executing AI-suggested tests...");
            for (int i = 0; i < plan.tests.size(); i++) {
                PlannedTest test = plan.tests.get(i);
                stdout.println("\n[Test " + (i+1) + "/" + plan.tests.size() + "] " + test.description);
                stdout.println("[*] Attack Type: " + test.attackType);
                stdout.println("[*] Target Parameter: " + test.targetParameter);
                stdout.println("[*] Payload: " + test.payload);

                TestResult result = executeAITest(baseMessage, test);
                results.add(result);

                if (result.vulnerabilityFound) {
                    stdout.println("[!] VULNERABILITY FOUND!");
                    stdout.println("[!] Severity: " + result.severity);
                } else {
                    stdout.println("[-] No vulnerability");
                }

                // Small delay between tests
                Thread.sleep(500);
            }

            // Step 3: Ask AI to analyze results
            stdout.println("\n[3/3] AI analyzing test results...");
            AIAnalysis analysis = askAIToAnalyzeResults(baseMessage, results);

            stdout.println("\n" + analysis.summary);

            if (analysis.additionalTestsNeeded) {
                stdout.println("\n[*] AI suggests additional tests:");
                for (String suggestion : analysis.suggestions) {
                    stdout.println("    - " + suggestion);
                }
            }

        } catch (Exception e) {
            stderr.println("[✗] AI testing error: " + e.getMessage());
            e.printStackTrace(stderr);
        }

        return results;
    }

    /**
     * Ask AI to create a test plan
     */
    public TestPlan askAIForTestPlan(IHttpRequestResponse baseMessage) {
        return askAIForTestPlan(baseMessage, null);
    }

    /**
     * Ask AI to create a test plan, optionally biased by a hypothesis hint
     * (e.g. the ranked likely-vulnerability list from the detection engine).
     */
    public TestPlan askAIForTestPlan(IHttpRequestResponse baseMessage, String hypothesisHint) {
        TestPlan plan = new TestPlan();

        try {
            // Get request details
            byte[] requestBytes = baseMessage.getRequest();
            String httpRequest = new String(requestBytes, "UTF-8");
            IRequestInfo requestInfo = helpers.analyzeRequest(baseMessage);

            // Build prompt for AI to plan tests
            String prompt = buildTestPlanningPrompt(httpRequest, requestInfo);
            if (hypothesisHint != null && !hypothesisHint.trim().isEmpty()) {
                prompt = prompt + "\n\n## PRIORITIZE THESE LIKELY ISSUES (from recon/hypothesis):\n"
                        + hypothesisHint + "\n";
            }

            // Ask AI
            List<AiApiClient.Message> messages = new ArrayList<>();
            messages.add(new AiApiClient.Message("system",
                "You are an expert penetration tester. " +
                "Analyze HTTP requests and create precise test plans. " +
                "Decide EXACTLY what requests to send to find vulnerabilities."
                + (burp.i18n.I18n.isTr()
                    ? " Write the \"description\", \"expectedBehavior\" and \"vulnerableIf\" field VALUES in TURKISH; "
                      + "keep all JSON keys and the attackType/location/targetParameter/payload values in English."
                    : "")));
            messages.add(new AiApiClient.Message("user", prompt));

            JSONObject aiResponse = aiClient.chatCompletion(messages);
            String content = aiResponse.getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");

            // Parse AI's test plan
            plan = parseTestPlan(content, requestInfo);

        } catch (Exception e) {
            stderr.println("[✗] Error getting AI test plan: " + e.getMessage());
        }

        return plan;
    }

    /**
     * Build prompt for AI to plan tests
     */
    private String buildTestPlanningPrompt(String httpRequest, IRequestInfo requestInfo) {
        StringBuilder prompt = new StringBuilder();

        prompt.append("# TEST PLANNING REQUEST\n\n");
        prompt.append("Analyze this HTTP request and create a DETAILED test plan.\n");
        prompt.append("For each test, specify EXACTLY what request to send.\n\n");

        prompt.append("## HTTP REQUEST:\n```\n");
        prompt.append(httpRequest);
        prompt.append("\n```\n\n");

        prompt.append("## YOUR TASK:\n");
        prompt.append("Create concrete, SENDABLE test requests. Each test injects ONE payload at ONE\n");
        prompt.append("location. Use the \"location\" field to say WHERE to inject:\n");
        prompt.append("- \"param\"  : an existing query/body parameter (set targetParameter to its name)\n");
        prompt.append("- \"path\"   : the URL path. targetParameter = the path segment to replace (e.g. \"123\"),\n");
        prompt.append("             payload = the new value. Use for IDOR on REST paths like /user/123.\n");
        prompt.append("- \"header\" : an HTTP header. targetParameter = header name, payload = header value\n");
        prompt.append("             (e.g. X-Forwarded-For, X-Original-URL, Host, X-Forwarded-Host).\n");
        prompt.append("- \"jwt\"    : replace the Bearer token value (payload = the manipulated JWT, e.g. alg=none).\n");
        prompt.append("- \"cookie\" : a cookie. targetParameter = cookie name, payload = value.\n");
        prompt.append("- \"body\"   : replace the entire request body with payload (for POST/PUT).\n\n");

        prompt.append("Cover (as applicable): IDOR (param AND path), Broken Auth/Authorization,\n");
        prompt.append("JWT attacks (alg none, signature strip), SQL/NoSQL/Command Injection, XSS,\n");
        prompt.append("SSRF (via params and headers), Path Traversal, Business Logic, Open Redirect,\n");
        prompt.append("Mass Assignment, and missing-auth (drop the Authorization header to test access).\n\n");

        prompt.append("## ACCOUNT-OWNERSHIP (Hesap Aitlik Kontrolü) — DO NOT SKIP ANY:\n");
        prompt.append("If the request carries ANY client-supplied account/customer identifier — CustomerId,\n");
        prompt.append("AccountNumber, SenderAccountNumber, ReceiverAccountNumber, AccountSuffix,\n");
        prompt.append("SenderAccountSuffix, Iban, SenderIban, ReceiverIban, PersonId (in the query, body or\n");
        prompt.append("JSON) — emit ONE IDOR test per such field that swaps it to ANOTHER owner's value,\n");
        prompt.append("keeping your own session. Vulnerable if the backend processes it without an ownership\n");
        prompt.append("check (IsOwnAccount-style): you see/transact on another customer's account or data.\n");
        prompt.append("Test EVERY ownership field present — never test only the first one.\n\n");

        prompt.append("## OUTPUT FORMAT (JSON only):\n");
        prompt.append("```json\n");
        prompt.append("{\n");
        prompt.append("  \"tests\": [\n");
        prompt.append("    {\"description\":\"IDOR via path id\",\"attackType\":\"IDOR\",\"location\":\"path\",\"targetParameter\":\"123\",\"payload\":\"124\",\"expectedBehavior\":\"Access denied\",\"vulnerableIf\":\"Returns another user's data\"},\n");
        prompt.append("    {\"description\":\"JWT alg=none bypass\",\"attackType\":\"JWT\",\"location\":\"jwt\",\"targetParameter\":\"Authorization\",\"payload\":\"<forged-token>\",\"expectedBehavior\":\"401\",\"vulnerableIf\":\"200 with forged token\"},\n");
        prompt.append("    {\"description\":\"Auth bypass by removing token\",\"attackType\":\"Broken Auth\",\"location\":\"header\",\"targetParameter\":\"Authorization\",\"payload\":\"\",\"expectedBehavior\":\"401\",\"vulnerableIf\":\"200 without auth\"},\n");
        prompt.append("    {\"description\":\"SSRF via header\",\"attackType\":\"SSRF\",\"location\":\"header\",\"targetParameter\":\"X-Forwarded-For\",\"payload\":\"127.0.0.1\",\"expectedBehavior\":\"no change\",\"vulnerableIf\":\"internal behavior differs\"}\n");
        prompt.append("  ]\n");
        prompt.append("}\n");
        prompt.append("```\n\n");

        prompt.append("IMPORTANT:\n");
        prompt.append("- If the request has NO query/body parameters, STILL produce tests using\n");
        prompt.append("  path / header / jwt / cookie locations. NEVER return an empty tests array.\n");
        prompt.append("- Be specific with payloads. Default location to \"param\" only when a real param exists.\n");
        prompt.append("- Prioritize HIGH-IMPACT tests. Create 5-12 tests.\n");

        return prompt.toString();
    }

    /**
     * Parse AI's test plan
     */
    private TestPlan parseTestPlan(String aiResponse, IRequestInfo requestInfo) {
        TestPlan plan = new TestPlan();

        try {
            // Extract JSON from AI response
            int jsonStart = aiResponse.indexOf("{");
            int jsonEnd = aiResponse.lastIndexOf("}") + 1;

            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                String jsonStr = aiResponse.substring(jsonStart, jsonEnd);
                JSONObject json = new JSONObject(jsonStr);

                JSONArray tests = json.getJSONArray("tests");

                for (int i = 0; i < tests.length(); i++) {
                    JSONObject testJson = tests.getJSONObject(i);

                    PlannedTest test = new PlannedTest();
                    test.description = testJson.optString("description", "AI test");
                    test.attackType = testJson.optString("attackType", "Vulnerability");
                    test.targetParameter = testJson.optString("targetParameter", "");
                    test.payload = testJson.optString("payload", "");
                    test.expectedBehavior = testJson.optString("expectedBehavior", "");
                    test.vulnerableIf = testJson.optString("vulnerableIf", "");
                    test.location = testJson.optString("location", "param").toLowerCase();

                    plan.tests.add(test);
                }
            }

        } catch (Exception e) {
            stderr.println("[✗] Error parsing test plan: " + e.getMessage());
        }

        return plan;
    }

    /**
     * Execute a test that AI suggested
     */
    public TestResult executeAITest(IHttpRequestResponse baseMessage, PlannedTest test) {
        TestResult result = new TestResult();
        result.test = test;

        try {
            byte[] modifiedRequest = buildModifiedRequest(baseMessage, test);
            if (modifiedRequest == null) {
                result.error = "Could not build request for location=" + test.location;
                return result;
            }

            // Send request
            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                baseMessage.getHttpService(),
                modifiedRequest
            );

            // Get response details
            IResponseInfo responseInfo = helpers.analyzeResponse(testResponse.getResponse());
            result.statusCode = responseInfo.getStatusCode();
            result.response = new String(testResponse.getResponse(), "UTF-8");

            // Ask AI if this indicates a vulnerability
            result.vulnerabilityFound = askAIIfVulnerable(baseMessage, testResponse, test);

            if (result.vulnerabilityFound) {
                result.severity = determineSeverity(test.attackType);
            }

        } catch (Exception e) {
            result.error = e.getMessage();
        }

        return result;
    }

    /**
     * Build the mutated request for a planned test, injecting the payload at the
     * declared location (param / path / header / jwt / cookie / body).
     */
    public byte[] buildModifiedRequest(IHttpRequestResponse base, PlannedTest test) throws Exception {
        IRequestInfo info = helpers.analyzeRequest(base);
        byte[] req = base.getRequest();
        String loc = test.location != null ? test.location.toLowerCase() : "param";
        List<String> headers = new ArrayList<>(info.getHeaders());
        byte[] body = java.util.Arrays.copyOfRange(req, info.getBodyOffset(), req.length);

        switch (loc) {
            case "param": {
                for (IParameter p : info.getParameters()) {
                    if (p.getName().equals(test.targetParameter)) {
                        byte pt = p.getType();
                        // Burp's buildParameter/updateParameter only support URL/BODY/COOKIE.
                        // For JSON/XML/multipart they throw "Action is not supported for this
                        // parameter type", so splice the payload into the value range instead.
                        if (pt == IParameter.PARAM_URL || pt == IParameter.PARAM_BODY
                                || pt == IParameter.PARAM_COOKIE) {
                            return helpers.updateParameter(req,
                                    helpers.buildParameter(p.getName(), test.payload, pt));
                        }
                        byte[] spliced = spliceValue(req, p, test.payload);
                        if (spliced != null) return spliced;
                    }
                }
                // Not found: add as a URL parameter
                if (test.targetParameter != null && !test.targetParameter.isEmpty()) {
                    return helpers.updateParameter(req,
                            helpers.buildParameter(test.targetParameter, test.payload, IParameter.PARAM_URL));
                }
                return null;
            }
            case "cookie": {
                if (test.targetParameter == null || test.targetParameter.isEmpty()) return null;
                return helpers.updateParameter(req,
                        helpers.buildParameter(test.targetParameter, test.payload, IParameter.PARAM_COOKIE));
            }
            case "header": {
                String hname = test.targetParameter;
                if (hname == null || hname.isEmpty()) return null;
                List<String> out = new ArrayList<>();
                boolean replaced = false;
                for (String h : headers) {
                    if (h.toLowerCase().startsWith(hname.toLowerCase() + ":")) {
                        // empty payload => drop the header entirely (e.g. remove Authorization)
                        if (test.payload != null && !test.payload.isEmpty()) {
                            out.add(hname + ": " + test.payload);
                        }
                        replaced = true;
                    } else {
                        out.add(h);
                    }
                }
                if (!replaced && test.payload != null && !test.payload.isEmpty()) {
                    out.add(hname + ": " + test.payload);
                }
                return helpers.buildHttpMessage(out, body);
            }
            case "jwt": {
                List<String> out = new ArrayList<>();
                for (String h : headers) {
                    if (h.toLowerCase().startsWith("authorization:")) {
                        out.add("Authorization: Bearer " + test.payload);
                    } else {
                        out.add(h);
                    }
                }
                return helpers.buildHttpMessage(out, body);
            }
            case "path": {
                if (headers.isEmpty()) return null;
                String reqLine = headers.get(0); // e.g. "GET /a/b?x=1 HTTP/1.1"
                String[] parts = reqLine.split(" ");
                if (parts.length < 2) return null;
                String path = parts[1];
                String newPath;
                if (test.targetParameter != null && !test.targetParameter.isEmpty()
                        && path.contains(test.targetParameter)) {
                    newPath = path.replace(test.targetParameter, test.payload);
                } else if (test.payload != null && test.payload.startsWith("/")) {
                    newPath = test.payload;
                } else {
                    return null;
                }
                parts[1] = newPath;
                headers.set(0, String.join(" ", parts));
                return helpers.buildHttpMessage(headers, body);
            }
            case "body": {
                byte[] newBody = test.payload != null ? test.payload.getBytes("UTF-8") : new byte[0];
                return helpers.buildHttpMessage(headers, newBody);
            }
            default:
                return null;
        }
    }

    /**
     * Replace a parameter's value in-place for types Burp's helper API cannot
     * rebuild (JSON, XML, multipart). Splices {@code payload} into the parameter's
     * value byte-range and rebuilds the message so Content-Length stays correct.
     * Returns null if the value offsets are unavailable.
     */
    private byte[] spliceValue(byte[] req, IParameter p, String payload) throws Exception {
        int s = p.getValueStart();
        int e = p.getValueEnd();
        if (s < 0 || e < s || e > req.length) {
            return null;
        }
        byte[] pay = payload != null ? payload.getBytes("UTF-8") : new byte[0];
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        bos.write(req, 0, s);
        bos.write(pay, 0, pay.length);
        bos.write(req, e, req.length - e);
        byte[] spliced = bos.toByteArray();
        // Rebuild via buildHttpMessage so Content-Length matches the new body.
        IRequestInfo si = helpers.analyzeRequest(spliced);
        List<String> hdrs = si.getHeaders();
        byte[] body = java.util.Arrays.copyOfRange(spliced, si.getBodyOffset(), spliced.length);
        return helpers.buildHttpMessage(hdrs, body);
    }

    /**
     * Ask AI if the test response indicates a vulnerability
     */
    private boolean askAIIfVulnerable(IHttpRequestResponse baseMessage,
                                     IHttpRequestResponse testResponse,
                                     PlannedTest test) {
        try {
            String baseResponseStr = new String(baseMessage.getResponse(), "UTF-8");
            String testResponseStr = new String(testResponse.getResponse(), "UTF-8");

            String prompt = "# VULNERABILITY VERIFICATION\n\n" +
                "Test: " + test.description + "\n" +
                "Attack Type: " + test.attackType + "\n" +
                "Payload: " + test.payload + "\n\n" +
                "## ORIGINAL RESPONSE:\n" + baseResponseStr.substring(0, Math.min(1000, baseResponseStr.length())) + "\n\n" +
                "## TEST RESPONSE:\n" + testResponseStr.substring(0, Math.min(1000, testResponseStr.length())) + "\n\n" +
                "Question: Does the test response indicate a " + test.attackType + " vulnerability?\n" +
                "Expected behavior: " + test.expectedBehavior + "\n" +
                "Vulnerable if: " + test.vulnerableIf + "\n\n" +
                "Answer with YES or NO and brief explanation.";

            List<AiApiClient.Message> messages = new ArrayList<>();
            messages.add(new AiApiClient.Message("user", prompt));

            JSONObject aiResponse = aiClient.chatCompletion(messages);
            String content = aiResponse.getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");

            return content.toLowerCase().contains("yes");

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Ask AI to analyze all results
     */
    private AIAnalysis askAIToAnalyzeResults(IHttpRequestResponse baseMessage, List<TestResult> results) {
        AIAnalysis analysis = new AIAnalysis();

        try {
            StringBuilder resultsStr = new StringBuilder();
            for (TestResult result : results) {
                resultsStr.append("Test: ").append(result.test.description).append("\n");
                resultsStr.append("Vulnerable: ").append(result.vulnerabilityFound).append("\n");
                if (result.vulnerabilityFound) {
                    resultsStr.append("Severity: ").append(result.severity).append("\n");
                }
                resultsStr.append("\n");
            }

            String prompt = "# TEST RESULTS ANALYSIS\n\n" +
                resultsStr.toString() + "\n" +
                "Analyze these test results and provide:\n" +
                "1. Summary of findings\n" +
                "2. Are additional tests needed?\n" +
                "3. Suggestions for next steps";

            List<AiApiClient.Message> messages = new ArrayList<>();
            messages.add(new AiApiClient.Message("user", prompt));

            JSONObject aiResponse = aiClient.chatCompletion(messages);
            String content = aiResponse.getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");

            analysis.summary = content;
            analysis.additionalTestsNeeded = content.toLowerCase().contains("additional") ||
                                           content.toLowerCase().contains("more tests");

        } catch (Exception e) {
            analysis.summary = "Error analyzing results: " + e.getMessage();
        }

        return analysis;
    }

    /**
     * Determine severity based on attack type
     */
    private String determineSeverity(String attackType) {
        switch (attackType.toLowerCase()) {
            case "business logic":
                return "Critical";
            case "idor":
                return "High";
            case "sql injection":
                return "Critical";
            case "authentication bypass":
                return "Critical";
            default:
                return "Medium";
        }
    }

    // Data classes
    public static class TestPlan {
        public List<PlannedTest> tests = new ArrayList<>();
    }

    public static class PlannedTest {
        public String description;
        public String attackType;
        public String targetParameter;
        public String payload;
        public String expectedBehavior;
        public String vulnerableIf;
        // Where to inject the payload: "param" | "path" | "header" | "jwt" | "cookie" | "body"
        public String location = "param";
    }

    public static class TestResult {
        public PlannedTest test;
        public boolean vulnerabilityFound = false;
        public String severity;
        public int statusCode;
        public String response;
        public String error;
    }

    public static class AIAnalysis {
        public String summary;
        public boolean additionalTestsNeeded;
        public List<String> suggestions = new ArrayList<>();
    }
}
