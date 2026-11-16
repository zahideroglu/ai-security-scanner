package burp.api;

import burp.*;
import burp.i18n.I18n;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * API Chain Attack Detector
 * Discovers and exploits logical vulnerabilities in API endpoint chains
 *
 * @author Zahid Eroglu
 * @version 2.0
 */
public class ChainAttackDetector {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final burp.engine.SharedRateLimiter limiter; // site-wide throttle (may be null)

    // Track discovered endpoints
    private final Map<String, APIEndpoint> discoveredEndpoints;
    private final List<APIChain> discoveredChains;

    /**
     * API Endpoint representation
     */
    /**
     * API Endpoint representation
     */
    public static class APIEndpoint {
        public String url;
        public String method;
        public String path;
        public List<String> parameters;
        public Map<String, String> headers;
        public String requestBody;
        public String responseBody;
        public int statusCode;
        public String category; // user, auth, product, payment, admin, etc.
        public Map<String, Object> extractedData; // IDs, tokens, etc.

        public APIEndpoint(String url, String method) {
            this.url = url;
            this.method = method;
            this.parameters = new java.util.concurrent.CopyOnWriteArrayList<>();
            this.headers = new ConcurrentHashMap<>();
            this.extractedData = new ConcurrentHashMap<>();
        }
    }

    /**
     * API Chain representation
     */
    public static class APIChain {
        public String chainId;
        public String name;
        public String description;
        public List<APIEndpoint> steps;
        public String attackScenario;
        public String severity;
        public boolean exploitable;
        public String proof;

        public APIChain() {
            this.chainId = UUID.randomUUID().toString();
            this.steps = new java.util.concurrent.CopyOnWriteArrayList<>();
        }
    }

    /**
     * Chain Attack Result
     */
    public static class ChainAttackResult {
        public APIChain chain;
        public boolean successful;
        public String evidence;
        public String impact;
        public String remediation;
        public List<String> executionLog;

        public ChainAttackResult(APIChain chain) {
            this.chain = chain;
            this.executionLog = new ArrayList<>();
        }
    }

    public ChainAttackDetector(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
            burp.engine.SharedRateLimiter limiter, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.limiter = limiter;
        this.stdout = stdout;
        this.stderr = stderr;
        this.discoveredEndpoints = new ConcurrentHashMap<>();
        this.discoveredChains = new java.util.concurrent.CopyOnWriteArrayList<>();
    }

    /**
     * Analyze HTTP traffic to discover API endpoints
     */
    public APIEndpoint analyzeEndpoint(IHttpRequestResponse requestResponse) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            IResponseInfo respInfo = helpers.analyzeResponse(requestResponse.getResponse());

            URL url = reqInfo.getUrl();
            String method = reqInfo.getMethod();
            String path = url.getPath();

            APIEndpoint endpoint = new APIEndpoint(url.toString(), method);
            endpoint.path = path;
            endpoint.statusCode = respInfo.getStatusCode();

            // Extract parameters
            for (IParameter param : reqInfo.getParameters()) {
                endpoint.parameters.add(param.getName() + "=" + param.getValue());
            }

            // Extract headers
            for (String header : reqInfo.getHeaders()) {
                if (header.contains(":")) {
                    String[] parts = header.split(":", 2);
                    if (parts.length == 2) {
                        endpoint.headers.put(parts[0].trim(), parts[1].trim());
                    }
                }
            }

            // Extract request body
            int bodyOffset = reqInfo.getBodyOffset();
            byte[] requestBytes = requestResponse.getRequest();
            if (requestBytes != null && requestBytes.length > bodyOffset) {
                endpoint.requestBody = new String(Arrays.copyOfRange(requestBytes, bodyOffset, requestBytes.length));
            }

            // Extract response body
            byte[] responseBytes = requestResponse.getResponse();
            if (responseBytes != null) {
                int respBodyOffset = respInfo.getBodyOffset();
                if (responseBytes.length > respBodyOffset) {
                    endpoint.responseBody = new String(
                            Arrays.copyOfRange(responseBytes, respBodyOffset, responseBytes.length));
                }
            }

            // Categorize endpoint
            endpoint.category = categorizeEndpoint(path, endpoint.requestBody, endpoint.responseBody);

            // Extract important data (IDs, tokens, etc.)
            extractDataFromResponse(endpoint);

            // Store endpoint
            String key = method + ":" + path;
            discoveredEndpoints.put(key, endpoint);

            return endpoint;

        } catch (Exception e) {
            stderr.println("[ChainAttack] Error analyzing endpoint: " + e.getMessage());
            return null;
        }
    }

    /**
     * Categorize endpoint based on path and content
     */
    private String categorizeEndpoint(String path, String requestBody, String responseBody) {
        path = path.toLowerCase();
        String content = (requestBody + " " + responseBody).toLowerCase();

        if (path.contains("/user") || path.contains("/profile") || content.contains("user")) {
            return "user";
        } else if (path.contains("/auth") || path.contains("/login") || path.contains("/token") ||
                content.contains("token") || content.contains("session")) {
            return "auth";
        } else if (path.contains("/product") || path.contains("/item") || content.contains("product")) {
            return "product";
        } else if (path.contains("/cart") || path.contains("/checkout") || path.contains("/order") ||
                content.contains("cart") || content.contains("price")) {
            return "payment";
        } else if (path.contains("/admin") || path.contains("/manage") || content.contains("admin")) {
            return "admin";
        } else if (path.contains("/email") || path.contains("/verify") || path.contains("/reset")) {
            return "verification";
        } else if (path.contains("/api/v")) {
            return "api";
        }

        return "other";
    }

    /**
     * Extract important data from response (IDs, tokens, emails, etc.)
     */
    private void extractDataFromResponse(APIEndpoint endpoint) {
        if (endpoint.responseBody == null)
            return;

        try {
            // Try to parse as JSON
            if (endpoint.responseBody.trim().startsWith("{") || endpoint.responseBody.trim().startsWith("[")) {
                JSONObject json = new JSONObject(endpoint.responseBody);
                extractFromJSON(json, endpoint.extractedData, "");
            }
        } catch (Exception e) {
            // Not JSON, try regex extraction
            extractWithRegex(endpoint.responseBody, endpoint.extractedData);
        }
    }

    /**
     * Extract data from JSON recursively
     */
    private void extractFromJSON(JSONObject json, Map<String, Object> data, String prefix) {
        for (String key : json.keySet()) {
            Object value = json.get(key);
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;

            if (value instanceof JSONObject) {
                extractFromJSON((JSONObject) value, data, fullKey);
            } else if (value instanceof JSONArray) {
                // Store array
                data.put(fullKey, value.toString());
            } else {
                // Store primitive values
                data.put(fullKey, value);
            }
        }
    }

    /**
     * Extract data using regex patterns
     */
    private void extractWithRegex(String text, Map<String, Object> data) {
        // Extract IDs
        Pattern idPattern = Pattern
                .compile("\"?(id|user_id|product_id|order_id|cart_id)\"?\\s*[:=]\\s*\"?([0-9a-fA-F-]+)\"?");
        Matcher idMatcher = idPattern.matcher(text);
        while (idMatcher.find()) {
            data.put(idMatcher.group(1), idMatcher.group(2));
        }

        // Extract tokens
        Pattern tokenPattern = Pattern.compile("\"?(token|access_token|session|api_key)\"?\\s*[:=]\\s*\"([^\"]+)\"");
        Matcher tokenMatcher = tokenPattern.matcher(text);
        while (tokenMatcher.find()) {
            data.put(tokenMatcher.group(1), tokenMatcher.group(2));
        }

        // Extract emails
        Pattern emailPattern = Pattern.compile("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");
        Matcher emailMatcher = emailPattern.matcher(text);
        while (emailMatcher.find()) {
            data.put("email", emailMatcher.group(1));
        }
    }

    /**
     * Discover attack chains based on endpoint relationships
     */
    public List<APIChain> discoverChains() {
        discoveredChains.clear();

        stdout.println("[ChainAttack] Discovering attack chains from " + discoveredEndpoints.size() + " endpoints");

        // Pattern 1: User Creation → Email Verification Bypass → Privilege Escalation
        discoverUserCreationChain();

        // Pattern 2: Cart → Discount → Price Manipulation
        discoverPriceManipulationChain();

        // Pattern 3: Password Reset → Token Reuse → Account Takeover
        discoverPasswordResetChain();

        // Pattern 4: IDOR → Privilege Escalation → Admin Access
        discoverIDORToAdminChain();

        // Pattern 5: API Key Leak → Unauthorized Access → Data Exfiltration
        discoverAPIKeyLeakChain();

        stdout.println("[ChainAttack] Discovered " + discoveredChains.size() + " potential attack chains");

        return new ArrayList<>(discoveredChains);
    }

    /**
     * Pattern 1: User Creation → Email Verification Bypass → Privilege Escalation
     */
    private void discoverUserCreationChain() {
        List<APIEndpoint> userEndpoints = getEndpointsByCategory("user");
        List<APIEndpoint> authEndpoints = getEndpointsByCategory("auth");
        List<APIEndpoint> verifyEndpoints = getEndpointsByCategory("verification");

        if (!userEndpoints.isEmpty() && !authEndpoints.isEmpty()) {
            APIChain chain = new APIChain();
            chain.name = "User Registration → Verification Bypass → Privilege Escalation";
            chain.description = I18n.t("f.chain.desc.registration");
            chain.severity = "Critical";
            chain.attackScenario = I18n.t("f.chain.scenario.registration");

            // Add relevant endpoints to chain
            for (APIEndpoint ep : userEndpoints) {
                if (ep.method.equals("POST") && (ep.path.contains("register") || ep.path.contains("signup"))) {
                    chain.steps.add(ep);
                }
            }

            for (APIEndpoint ep : verifyEndpoints) {
                chain.steps.add(ep);
            }

            if (!chain.steps.isEmpty()) {
                discoveredChains.add(chain);
            }
        }
    }

    /**
     * Pattern 2: Cart → Discount → Price Manipulation
     */
    private void discoverPriceManipulationChain() {
        List<APIEndpoint> paymentEndpoints = getEndpointsByCategory("payment");

        if (!paymentEndpoints.isEmpty()) {
            APIChain chain = new APIChain();
            chain.name = "Shopping Cart → Discount Abuse → Price Manipulation";
            chain.description = I18n.t("f.chain.desc.cart");
            chain.severity = "High";
            chain.attackScenario = I18n.t("f.chain.scenario.cart");

            for (APIEndpoint ep : paymentEndpoints) {
                if (ep.path.contains("cart") || ep.path.contains("checkout") || ep.path.contains("order")) {
                    chain.steps.add(ep);
                }
            }

            if (!chain.steps.isEmpty()) {
                discoveredChains.add(chain);
            }
        }
    }

    /**
     * Pattern 3: Password Reset → Token Reuse → Account Takeover
     */
    private void discoverPasswordResetChain() {
        List<APIEndpoint> authEndpoints = getEndpointsByCategory("auth");
        List<APIEndpoint> verifyEndpoints = getEndpointsByCategory("verification");

        boolean hasPasswordReset = false;
        for (APIEndpoint ep : authEndpoints) {
            if (ep.path.contains("reset") || ep.path.contains("forgot")) {
                hasPasswordReset = true;
                break;
            }
        }

        if (hasPasswordReset) {
            APIChain chain = new APIChain();
            chain.name = "Password Reset → Token Reuse → Account Takeover";
            chain.description = I18n.t("f.chain.desc.pwreset");
            chain.severity = "Critical";
            chain.attackScenario = I18n.t("f.chain.scenario.pwreset");

            for (APIEndpoint ep : authEndpoints) {
                if (ep.path.contains("reset") || ep.path.contains("forgot") || ep.path.contains("password")) {
                    chain.steps.add(ep);
                }
            }

            if (!chain.steps.isEmpty()) {
                discoveredChains.add(chain);
            }
        }
    }

    /**
     * Pattern 4: IDOR → Privilege Escalation → Admin Access
     */
    private void discoverIDORToAdminChain() {
        List<APIEndpoint> userEndpoints = getEndpointsByCategory("user");
        List<APIEndpoint> adminEndpoints = getEndpointsByCategory("admin");

        if (!userEndpoints.isEmpty() || !adminEndpoints.isEmpty()) {
            APIChain chain = new APIChain();
            chain.name = "IDOR → Privilege Escalation → Admin Panel Access";
            chain.description = I18n.t("f.chain.desc.idor");
            chain.severity = "Critical";
            chain.attackScenario = I18n.t("f.chain.scenario.idor");

            for (APIEndpoint ep : userEndpoints) {
                if (ep.path.matches(".*/users?/[0-9]+.*")) {
                    chain.steps.add(ep);
                }
            }

            for (APIEndpoint ep : adminEndpoints) {
                chain.steps.add(ep);
            }

            if (!chain.steps.isEmpty()) {
                discoveredChains.add(chain);
            }
        }
    }

    /**
     * Pattern 5: API Key Leak → Unauthorized Access → Data Exfiltration
     */
    private void discoverAPIKeyLeakChain() {
        // Check if any endpoint leaked API keys or tokens
        boolean hasKeyLeak = false;
        APIEndpoint leakEndpoint = null;

        for (APIEndpoint ep : discoveredEndpoints.values()) {
            // Only a REAL credential leak counts. A bare "token" field is usually a CSRF/anti-forgery or
            // short-lived session token, not an API key — matching it produced a false Critical. Match the
            // LEAF of dotted/nested keys too (extractFromJSON stores e.g. "data.access_token").
            for (String k : ep.extractedData.keySet()) {
                String leaf = k.contains(".") ? k.substring(k.lastIndexOf('.') + 1) : k;
                if (leaf.equalsIgnoreCase("api_key") || leaf.equalsIgnoreCase("access_token")) {
                    hasKeyLeak = true;
                    leakEndpoint = ep;
                    break;
                }
            }
            if (hasKeyLeak) break;
        }

        if (hasKeyLeak) {
            APIChain chain = new APIChain();
            chain.name = "API Key Leak → Unauthorized Access → Data Exfiltration";
            chain.description = I18n.t("f.chain.desc.apikey");
            // Not Critical without exploit confirmation — the chain is discovered, not proven.
            chain.severity = "High";
            chain.attackScenario = I18n.t("f.chain.scenario.apikey");

            if (leakEndpoint != null) {
                chain.steps.add(leakEndpoint);
            }

            discoveredChains.add(chain);
        }
    }

    /**
     * Get endpoints by category
     */
    private List<APIEndpoint> getEndpointsByCategory(String category) {
        List<APIEndpoint> result = new ArrayList<>();
        for (APIEndpoint ep : discoveredEndpoints.values()) {
            if (ep.category.equals(category)) {
                result.add(ep);
            }
        }
        return result;
    }

    /**
     * Execute a discovered chain attack
     */
    public ChainAttackResult executeChain(APIChain chain) {
        ChainAttackResult result = new ChainAttackResult(chain);

        stdout.println("\n[ChainAttack] Executing chain: " + chain.name);
        result.executionLog.add("Starting chain execution: " + chain.name);

        try {
            // Context for the chain execution (persists across steps)
            Map<String, Object> chainContext = new HashMap<>();

            // Execute each step in the chain
            for (int i = 0; i < chain.steps.size(); i++) {
                APIEndpoint step = chain.steps.get(i);

                stdout.println("[ChainAttack] Step " + (i + 1) + ": " + step.method + " " + step.path);
                result.executionLog.add("Step " + (i + 1) + ": " + step.method + " " + step.path);

                // Execute Step
                boolean stepSuccess = executeStep(step, result, chainContext);

                if (!stepSuccess) {
                    result.successful = false;
                    result.evidence = I18n.t("f.chain.ev.failed", (i + 1));
                    return result;
                }
            }

            result.successful = true;
            result.evidence = I18n.t("f.chain.ev.success", chain.steps.size());
            result.impact = generateImpactDescription(chain);
            result.remediation = generateRemediationAdvice(chain);

            stdout.println("[ChainAttack] Chain execution completed successfully");

        } catch (Exception e) {
            stderr.println("[ChainAttack] Chain execution error: " + e.getMessage());
            result.successful = false;
            result.evidence = I18n.t("f.chain.ev.error") + e.getMessage();
        }

        return result;
    }

    /**
     * Execute a single step in the chain
     */
    private boolean executeStep(APIEndpoint step, ChainAttackResult result, Map<String, Object> chainContext) {
        try {
            // 1. Build Request with Context Substitution
            byte[] request = buildRequest(step, chainContext);
            IHttpService service = helpers.buildHttpService(step.url,
                    step.url.startsWith("https") ? 443 : 80,
                    step.url.startsWith("https"));

            // 2. Send Request
            long startTime = System.currentTimeMillis();
            if (limiter != null) limiter.acquire(); // share the global per-minute budget
            IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
            long duration = System.currentTimeMillis() - startTime;

            // 3. Analyze Response
            IResponseInfo respInfo = helpers.analyzeResponse(response.getResponse());
            int statusCode = respInfo.getStatusCode();
            String responseBody = new String(response.getResponse()).substring(respInfo.getBodyOffset());

            // Log execution
            result.executionLog.add(String.format("  → %s %s (Status: %d, Time: %dms)",
                    step.method, step.path, statusCode, duration));

            // 4. Update Context with New Data
            APIEndpoint executedStep = new APIEndpoint(step.url, step.method);
            executedStep.responseBody = responseBody;
            extractDataFromResponse(executedStep);
            chainContext.putAll(executedStep.extractedData);

            // Log extracted data
            if (!executedStep.extractedData.isEmpty()) {
                result.executionLog.add("    Extracted: " + executedStep.extractedData.keySet());
            }

            // 5. Verify Success (Basic check: 2xx status)
            return statusCode >= 200 && statusCode < 300;

        } catch (Exception e) {
            result.executionLog.add("  → Error: " + e.getMessage());
            e.printStackTrace(stderr);
            return false;
        }
    }

    /**
     * Build HTTP request with variable substitution
     */
    private byte[] buildRequest(APIEndpoint step, Map<String, Object> context) {
        // Substitute path parameters
        String path = step.path;
        for (Map.Entry<String, Object> entry : context.entrySet()) {
            String placeholder = "{" + entry.getKey() + "}";
            if (path.contains(placeholder)) {
                path = path.replace(placeholder, entry.getValue().toString());
            }
        }

        // Build headers
        List<String> headers = new ArrayList<>();
        headers.add(step.method + " " + path + " HTTP/1.1");
        headers.add("Host: " + getHostFromUrl(step.url));

        for (Map.Entry<String, String> header : step.headers.entrySet()) {
            String value = header.getValue();
            // Substitute header values (e.g., Bearer {token})
            for (Map.Entry<String, Object> ctxEntry : context.entrySet()) {
                String placeholder = "{" + ctxEntry.getKey() + "}";
                if (value.contains(placeholder)) {
                    value = value.replace(placeholder, ctxEntry.getValue().toString());
                }
            }
            headers.add(header.getKey() + ": " + value);
        }

        // Build body
        byte[] body = null;
        if (step.requestBody != null && !step.requestBody.isEmpty()) {
            String bodyStr = step.requestBody;
            // Substitute body values
            for (Map.Entry<String, Object> ctxEntry : context.entrySet()) {
                String placeholder = "{" + ctxEntry.getKey() + "}";
                if (bodyStr.contains(placeholder)) {
                    bodyStr = bodyStr.replace(placeholder, ctxEntry.getValue().toString());
                }
            }
            body = bodyStr.getBytes();
        }

        return helpers.buildHttpMessage(headers, body);
    }

    private String getHostFromUrl(String urlStr) {
        try {
            URL url = new URL(urlStr);
            return url.getHost();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Generate impact description
     */
    private String generateImpactDescription(APIChain chain) {
        switch (chain.name) {
            case "User Registration → Verification Bypass → Privilege Escalation":
                return I18n.t("f.chain.impact.registration");

            case "Shopping Cart → Discount Abuse → Price Manipulation":
                return I18n.t("f.chain.impact.cart");

            case "Password Reset → Token Reuse → Account Takeover":
                return I18n.t("f.chain.impact.pwreset");

            case "IDOR → Privilege Escalation → Admin Panel Access":
                return I18n.t("f.chain.impact.idor");

            case "API Key Leak → Unauthorized Access → Data Exfiltration":
                return I18n.t("f.chain.impact.apikey");

            default:
                return I18n.t("f.chain.impact.default");
        }
    }

    /**
     * Generate remediation advice
     */
    private String generateRemediationAdvice(APIChain chain) {
        switch (chain.name) {
            case "User Registration → Verification Bypass → Privilege Escalation":
                return I18n.t("f.chain.rem.registration");

            case "Shopping Cart → Discount Abuse → Price Manipulation":
                return I18n.t("f.chain.rem.cart");

            case "Password Reset → Token Reuse → Account Takeover":
                return I18n.t("f.chain.rem.pwreset");

            case "IDOR → Privilege Escalation → Admin Panel Access":
                return I18n.t("f.chain.rem.idor");

            case "API Key Leak → Unauthorized Access → Data Exfiltration":
                return I18n.t("f.chain.rem.apikey");

            default:
                return I18n.t("f.chain.rem.default");
        }
    }

    /**
     * Get all discovered endpoints
     */
    public Map<String, APIEndpoint> getDiscoveredEndpoints() {
        return new HashMap<>(discoveredEndpoints);
    }

    /**
     * Get all discovered chains
     */
    public List<APIChain> getDiscoveredChains() {
        return new ArrayList<>(discoveredChains);
    }

    /**
     * Clear all discovered data
     */
    public void clear() {
        discoveredEndpoints.clear();
        discoveredChains.clear();
        stdout.println("[ChainAttack] Cleared all discovered endpoints and chains");
    }
}
