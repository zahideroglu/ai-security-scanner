package burp;

import java.util.*;
import java.io.PrintWriter;
import org.json.JSONObject;

/**
 * Multi-Session Tester - Role-based authorization testing
 * Tests for privilege escalation, IDOR, and authorization bypass vulnerabilities
 *
 * @author Zahid Eroglu
 */
public class MultiSessionTester {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private AiApiClient aiClient;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // Session storage
    private Map<String, UserSession> sessions;
    private UserSession currentActiveSession;

    public MultiSessionTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                             AiApiClient aiClient, PrintWriter out, PrintWriter err) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.stdout = out;
        this.stderr = err;
        this.sessions = new HashMap<>();
    }

    /**
     * Add a user session for testing
     */
    public String addSession(String roleName, String description, Map<String, String> authTokens) {
        return addSession(roleName, description, authTokens, null);
    }

    /**
     * Add a session that also carries the token in the request BODY (not just headers). {@code bodyTokens}
     * maps a JSON field name → value to set on every replayed JSON body — for APIs (e.g. Gateway) that
     * carry the session in the body (field {@code sessionToken}) rather than an {@code Authorization} header.
     */
    public String addSession(String roleName, String description, Map<String, String> authTokens,
                             Map<String, String> bodyTokens) {
        String sessionId = UUID.randomUUID().toString();

        UserSession session = new UserSession();
        session.id = sessionId;
        session.roleName = roleName;
        session.description = description;
        session.authTokens = authTokens;
        session.bodyTokens = bodyTokens;
        session.createdAt = new Date();

        sessions.put(sessionId, session);

        stdout.println("[+] Session added: " + roleName + " (" + sessionId + ")"
                + (bodyTokens != null && !bodyTokens.isEmpty() ? " [body: " + bodyTokens.keySet() + "]" : ""));

        return sessionId;
    }

    /**
     * Add session from request (auto-extract tokens)
     */
    public String addSessionFromRequest(String roleName, String description, IHttpRequestResponse request) {
        Map<String, String> authTokens = extractAuthTokens(request);
        return addSession(roleName, description, authTokens);
    }

    /**
     * Extract authentication tokens from request
     */
    private Map<String, String> extractAuthTokens(IHttpRequestResponse request) {
        Map<String, String> tokens = new HashMap<>();

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            List<String> headers = reqInfo.getHeaders();

            for (String header : headers) {
                String lower = header.toLowerCase();

                // Cookie header
                if (lower.startsWith("cookie:")) {
                    String cookieValue = header.substring(7).trim();
                    tokens.put("Cookie", cookieValue);
                    stdout.println("[+] Found Cookie header");
                }
                // Authorization header (Bearer, Basic, etc.)
                else if (lower.startsWith("authorization:")) {
                    String authValue = header.substring(14).trim();
                    tokens.put("Authorization", authValue);
                    stdout.println("[+] Found Authorization header");
                }
                // X-Auth-Token
                else if (lower.startsWith("x-auth-token:")) {
                    String tokenValue = header.substring(13).trim();
                    tokens.put("X-Auth-Token", tokenValue);
                    stdout.println("[+] Found X-Auth-Token header");
                }
                // X-API-Key
                else if (lower.startsWith("x-api-key:")) {
                    String keyValue = header.substring(10).trim();
                    tokens.put("X-API-Key", keyValue);
                    stdout.println("[+] Found X-API-Key header");
                }
                // X-Access-Token
                else if (lower.startsWith("x-access-token:")) {
                    String tokenValue = header.substring(15).trim();
                    tokens.put("X-Access-Token", tokenValue);
                    stdout.println("[+] Found X-Access-Token header");
                }
                // CSRF Token
                else if (lower.startsWith("x-csrf-token:")) {
                    String csrfValue = header.substring(13).trim();
                    tokens.put("X-CSRF-Token", csrfValue);
                    stdout.println("[+] Found X-CSRF-Token header");
                }
            }

            if (tokens.isEmpty()) {
                stdout.println("[!] WARNING: No authentication tokens found in request!");
                stdout.println("[!] Make sure the request contains Cookie or Authorization headers");
            }

        } catch (Exception e) {
            stderr.println("[!] Token extraction failed: " + e.getMessage());
            e.printStackTrace(stderr);
        }

        return tokens;
    }

    /**
     * Execute multi-session testing on a request
     */
    public List<SessionTestResult> executeMultiSessionTest(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        if (sessions.size() < 2) {
            stdout.println("[!] Need at least 2 sessions for multi-session testing");
            return results;
        }

        stdout.println("\n========================================");
        stdout.println("🎭 MULTI-SESSION TESTING");
        stdout.println("========================================");
        stdout.println("Sessions: " + sessions.size());
        stdout.println("Target: " + helpers.analyzeRequest(baseRequest).getUrl());
        stdout.println("========================================\n");

        // Test 1: Cross-user IDOR
        results.addAll(testCrossUserIDOR(baseRequest));

        // Test 2: Privilege Escalation
        results.addAll(testPrivilegeEscalation(baseRequest));

        // Test 3: Horizontal Authorization Bypass
        results.addAll(testHorizontalAuthBypass(baseRequest));

        // Test 4: Vertical Authorization Bypass
        results.addAll(testVerticalAuthBypass(baseRequest));

        // Test 5: Session Fixation
        results.addAll(testSessionFixation(baseRequest));

        stdout.println("\n[✓] Multi-session testing completed");
        stdout.println("[*] Total tests: " + results.size());

        int vulnerableCount = 0;
        for (SessionTestResult result : results) {
            if (result.vulnerable) {
                vulnerableCount++;
                stdout.println("    🔴 " + result.testType + ": VULNERABLE");
            }
        }

        if (vulnerableCount > 0) {
            stdout.println("\n⚠️  Found " + vulnerableCount + " authorization vulnerabilities!");
        } else {
            stdout.println("\n✅ No authorization vulnerabilities found");
        }

        stdout.println("========================================\n");

        return results;
    }

    /**
     * Test for cross-user IDOR vulnerabilities
     */
    private List<SessionTestResult> testCrossUserIDOR(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        stdout.println("[*] Testing Cross-User IDOR...");

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(baseRequest);
            String url = reqInfo.getUrl().toString();

            // Extract user IDs or resource IDs from URL/parameters
            List<String> detectedIds = extractResourceIds(baseRequest);

            if (detectedIds.isEmpty()) {
                stdout.println("    [i] No resource IDs detected in request");
                return results;
            }

            stdout.println("    [*] Detected IDs: " + detectedIds);

            // Get baseline response (original user)
            byte[] baseResponse = baseRequest.getResponse();
            String baseResponseStr = baseResponse != null ? helpers.bytesToString(baseResponse) : "";

            // Test each session with the same resource IDs
            for (UserSession session : sessions.values()) {
                for (String resourceId : detectedIds) {
                    // Replace auth tokens and send request
                    byte[] modifiedRequest = replaceAuthTokens(baseRequest.getRequest(), session);
                    IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                        baseRequest.getHttpService(),
                        modifiedRequest
                    );

                    // Analyze response
                    if (testResponse.getResponse() != null) {
                        IResponseInfo respInfo = helpers.analyzeResponse(testResponse.getResponse());
                        String testResponseStr = helpers.bytesToString(testResponse.getResponse());

                        // Check if successful access
                        if (respInfo.getStatusCode() == 200) {
                            // Compare responses
                            boolean different = !testResponseStr.equals(baseResponseStr);
                            boolean hasData = testResponseStr.length() > 1000;

                            if (hasData) {
                                // Potential IDOR vulnerability!
                                SessionTestResult result = new SessionTestResult();
                                result.testType = "Cross-User IDOR";
                                result.vulnerable = true;
                                result.severity = "High";
                                result.session1 = "Original User";
                                result.session2 = session.roleName;
                                result.evidence = "Session '" + session.roleName +
                                                "' can access resource ID: " + resourceId;
                                result.description = "User can access another user's resources without proper authorization checks.";
                                result.remediation = "Implement server-side authorization checks to verify that the authenticated user has permission to access the requested resource.";

                                results.add(result);

                                stdout.println("    🔴 IDOR FOUND: " + session.roleName +
                                             " accessed resource: " + resourceId);
                            }
                        }
                    }
                }
            }

        } catch (Exception e) {
            stderr.println("[!] IDOR test error: " + e.getMessage());
        }

        return results;
    }

    /**
     * Test for privilege escalation
     */
    private List<SessionTestResult> testPrivilegeEscalation(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        stdout.println("[*] Testing Privilege Escalation...");

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(baseRequest);
            String url = reqInfo.getUrl().toString().toLowerCase();

            // Check if this is a privileged endpoint
            boolean isPrivilegedEndpoint = url.contains("/admin") ||
                                         url.contains("/management") ||
                                         url.contains("/control") ||
                                         url.contains("/dashboard");

            if (!isPrivilegedEndpoint) {
                stdout.println("    [i] Not a privileged endpoint");
                return results;
            }

            // Find low-privilege sessions
            List<UserSession> lowPrivSessions = new ArrayList<>();
            for (UserSession session : sessions.values()) {
                String role = session.roleName.toLowerCase();
                if (role.contains("user") || role.contains("guest") ||
                    role.contains("basic") || role.contains("member")) {
                    lowPrivSessions.add(session);
                }
            }

            // Test each low-privilege session
            for (UserSession session : lowPrivSessions) {
                byte[] modifiedRequest = replaceAuthTokens(baseRequest.getRequest(), session);
                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                    baseRequest.getHttpService(),
                    modifiedRequest
                );

                if (testResponse.getResponse() != null) {
                    IResponseInfo respInfo = helpers.analyzeResponse(testResponse.getResponse());

                    // If low-privilege user gets 200 OK on admin endpoint
                    if (respInfo.getStatusCode() == 200) {
                        SessionTestResult result = new SessionTestResult();
                        result.testType = "Privilege Escalation";
                        result.vulnerable = true;
                        result.severity = "Critical";
                        result.session1 = "Admin";
                        result.session2 = session.roleName;
                        result.evidence = "Low-privilege user '" + session.roleName +
                                        "' accessed admin endpoint: " + url;
                        result.description = "Low-privilege user can access administrative functions.";
                        result.remediation = "Implement role-based access control (RBAC) on the server side.";

                        results.add(result);

                        stdout.println("    🔴 PRIVILEGE ESCALATION: " + session.roleName +
                                     " accessed admin endpoint");
                    }
                }
            }

        } catch (Exception e) {
            stderr.println("[!] Privilege escalation test error: " + e.getMessage());
        }

        return results;
    }

    /**
     * Test for horizontal authorization bypass
     */
    private List<SessionTestResult> testHorizontalAuthBypass(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        stdout.println("[*] Testing Horizontal Authorization Bypass...");

        try {
            // Get sessions with same privilege level
            Map<String, List<UserSession>> sessionsByRole = new HashMap<>();
            for (UserSession session : sessions.values()) {
                String role = session.roleName.toLowerCase();
                if (!sessionsByRole.containsKey(role)) {
                    sessionsByRole.put(role, new ArrayList<>());
                }
                sessionsByRole.get(role).add(session);
            }

            // Test between users of same role
            for (List<UserSession> sameLevelSessions : sessionsByRole.values()) {
                if (sameLevelSessions.size() < 2) continue;

                UserSession user1 = sameLevelSessions.get(0);
                UserSession user2 = sameLevelSessions.get(1);

                // User2 tries to access User1's request
                byte[] modifiedRequest = replaceAuthTokens(baseRequest.getRequest(), user2);
                IHttpRequestResponse testResponse = callbacks.makeHttpRequest(
                    baseRequest.getHttpService(),
                    modifiedRequest
                );

                if (testResponse.getResponse() != null) {
                    IResponseInfo respInfo = helpers.analyzeResponse(testResponse.getResponse());

                    if (respInfo.getStatusCode() == 200) {
                        // Check if response contains user-specific data
                        String responseStr = helpers.bytesToString(testResponse.getResponse());

                        // Simple heuristic: if response is substantial, might be vulnerable
                        if (responseStr.length() > 1000) {
                            SessionTestResult result = new SessionTestResult();
                            result.testType = "Horizontal Authorization Bypass";
                            result.vulnerable = true;
                            result.severity = "High";
                            result.session1 = user1.roleName;
                            result.session2 = user2.roleName;
                            result.evidence = user2.roleName + " can access " + user1.roleName + "'s resources";
                            result.description = "Users at the same privilege level can access each other's resources.";
                            result.remediation = "Implement user-specific authorization checks.";

                            results.add(result);
                        }
                    }
                }
            }

        } catch (Exception e) {
            stderr.println("[!] Horizontal auth bypass test error: " + e.getMessage());
        }

        return results;
    }

    /**
     * Test for vertical authorization bypass
     */
    private List<SessionTestResult> testVerticalAuthBypass(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        stdout.println("[*] Testing Vertical Authorization Bypass...");

        try {
            // Try unauthenticated access
            byte[] requestWithoutAuth = removeAuthTokens(baseRequest.getRequest());
            IHttpRequestResponse unauthResponse = callbacks.makeHttpRequest(
                baseRequest.getHttpService(),
                requestWithoutAuth
            );

            if (unauthResponse.getResponse() != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(unauthResponse.getResponse());

                if (respInfo.getStatusCode() == 200) {
                    SessionTestResult result = new SessionTestResult();
                    result.testType = "Vertical Authorization Bypass";
                    result.vulnerable = true;
                    result.severity = "Critical";
                    result.session1 = "Authenticated User";
                    result.session2 = "Unauthenticated";
                    result.evidence = "Protected resource accessible without authentication";
                    result.description = "Protected endpoint can be accessed without authentication.";
                    result.remediation = "Enforce authentication on all protected endpoints.";

                    results.add(result);

                    stdout.println("    🔴 VERTICAL BYPASS: Unauthenticated access successful");
                }
            }

        } catch (Exception e) {
            stderr.println("[!] Vertical auth bypass test error: " + e.getMessage());
        }

        return results;
    }

    /**
     * Test for session fixation
     */
    private List<SessionTestResult> testSessionFixation(IHttpRequestResponse baseRequest) {
        List<SessionTestResult> results = new ArrayList<>();

        stdout.println("[*] Testing Session Fixation...");

        // This is a simplified test - full session fixation testing requires login flow
        stdout.println("    [i] Session fixation test requires login flow (not implemented)");

        return results;
    }

    /**
     * Replace authentication tokens in request
     */
    private byte[] replaceAuthTokens(byte[] request, UserSession session) {
        try {
            String requestStr = helpers.bytesToString(request);
            String[] lines = requestStr.split("\r\n");
            StringBuilder modified = new StringBuilder();

            boolean inHeaders = true;

            for (String line : lines) {
                if (line.trim().isEmpty()) {
                    inHeaders = false;
                }

                if (inHeaders) {
                    String lower = line.toLowerCase();

                    // Skip existing auth headers
                    if (lower.startsWith("cookie:") ||
                        lower.startsWith("authorization:") ||
                        lower.startsWith("x-auth-token:") ||
                        lower.startsWith("x-api-key:") ||
                        lower.startsWith("x-access-token:")) {
                        continue;
                    }
                }

                modified.append(line).append("\r\n");

                // Add new auth headers after first line (request line)
                if (inHeaders && line.matches("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS).*")) {
                    for (Map.Entry<String, String> entry : session.authTokens.entrySet()) {
                        modified.append(entry.getKey()).append(": ")
                                .append(sanitizeHeaderValue(entry.getValue()))
                                .append("\r\n");
                    }
                }
            }

            byte[] out = helpers.stringToBytes(modified.toString());
            // Body-carried session (e.g. Gateway sessionToken): set the configured JSON field(s) too.
            if (session.bodyTokens != null && !session.bodyTokens.isEmpty()) {
                out = injectBodyTokens(out, session.bodyTokens);
            }
            return out;

        } catch (Exception e) {
            stderr.println("[!] Token replacement failed: " + e.getMessage());
            return request;
        }
    }

    /**
     * Set {@code bodyTokens} (JSON field → value) inside a request's JSON body and fix Content-Length.
     * Used for APIs that carry the session in the body. A field already present (at any depth) is
     * overwritten; if absent everywhere it is added at the top level so the session still applies.
     */
    private byte[] injectBodyTokens(byte[] request, Map<String, String> bodyTokens) {
        try {
            IRequestInfo ri = helpers.analyzeRequest(request);
            int off = ri.getBodyOffset();
            if (off <= 0 || off >= request.length) return request;
            String body = new String(request, off, request.length - off, "UTF-8");
            if (!body.trim().startsWith("{")) return request; // only JSON object bodies
            JSONObject o = new JSONObject(body);
            for (Map.Entry<String, String> e : bodyTokens.entrySet()) {
                if (!setJsonFieldRecursive(o, e.getKey(), e.getValue())) {
                    o.put(e.getKey(), e.getValue());
                }
            }
            return helpers.buildHttpMessage(ri.getHeaders(), o.toString().getBytes("UTF-8"));
        } catch (Exception e) {
            return request; // unparseable body → leave it (fail-open)
        }
    }

    /** Overwrite {@code key} wherever it appears in the object tree; returns true if it set at least one. */
    private boolean setJsonFieldRecursive(JSONObject o, String key, String value) {
        boolean set = false;
        if (o.has(key)) { o.put(key, value); set = true; }
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            Object v = o.opt(it.next());
            if (v instanceof JSONObject) set |= setJsonFieldRecursive((JSONObject) v, key, value);
        }
        return set;
    }

    /**
     * Replay the given base request under another identity's auth tokens and
     * return the live response. Used by the agentic pentester for BOLA / privilege
     * escalation: same request, different session, compare the result.
     */
    public IHttpRequestResponse replayAs(IHttpRequestResponse base, UserSession session) {
        byte[] modified = replaceAuthTokens(base.getRequest(), session);
        return callbacks.makeHttpRequest(base.getHttpService(), modified);
    }

    /**
     * Build (do NOT send) a copy of {@code request} with this session's auth tokens applied — header
     * tokens (Cookie/Authorization/…) AND body-carried tokens (e.g. Gateway {@code sessionToken}).
     * Lets another scanner (single-session IDOR) run on a FRESH session instead of the seed's dead one.
     */
    public byte[] applySession(byte[] request, UserSession session) {
        if (request == null || session == null) return request;
        try {
            return replaceAuthTokens(request, session);
        } catch (Exception e) {
            return request;
        }
    }

    private String sanitizeHeaderValue(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\r", "").replace("\n", "");
    }

    /**
     * Remove authentication tokens from request
     */
    private byte[] removeAuthTokens(byte[] request) {
        try {
            String requestStr = helpers.bytesToString(request);
            String[] lines = requestStr.split("\r\n");
            StringBuilder modified = new StringBuilder();

            for (String line : lines) {
                String lower = line.toLowerCase();

                // Skip auth headers
                if (lower.startsWith("cookie:") ||
                    lower.startsWith("authorization:") ||
                    lower.startsWith("x-auth-token:") ||
                    lower.startsWith("x-api-key:") ||
                    lower.startsWith("x-access-token:")) {
                    continue;
                }

                modified.append(line).append("\r\n");
            }

            return helpers.stringToBytes(modified.toString());

        } catch (Exception e) {
            stderr.println("[!] Token removal failed: " + e.getMessage());
            return request;
        }
    }

    /**
     * Extract resource IDs from request
     */
    private List<String> extractResourceIds(IHttpRequestResponse request) {
        List<String> ids = new ArrayList<>();

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            String url = reqInfo.getUrl().toString();

            // Extract numeric IDs from URL
            String[] parts = url.split("/");
            for (String part : parts) {
                if (part.matches("\\d+")) {
                    ids.add(part);
                }
            }

            // Extract IDs from parameters
            List<IParameter> params = reqInfo.getParameters();
            for (IParameter param : params) {
                String name = param.getName().toLowerCase();
                if (name.contains("id") || name.contains("user") || name.contains("account")) {
                    ids.add(param.getValue());
                }
            }

        } catch (Exception e) {
            // Ignore
        }

        return ids;
    }

    /**
     * Get all sessions
     */
    public List<UserSession> getSessions() {
        return new ArrayList<>(sessions.values());
    }

    /** True if any registered session was minted from a login profile (description marks it "login-profili"). */
    public boolean hasLoginProfileSessions() {
        if (sessions == null) return false;
        for (UserSession s : sessions.values()) {
            if (s != null && s.description != null && s.description.contains("login-profili")) return true;
        }
        return false;
    }

    /**
     * Remove session
     */
    public void removeSession(String sessionId) {
        sessions.remove(sessionId);
        stdout.println("[-] Session removed: " + sessionId);
    }

    /**
     * Clear all sessions
     */
    public void clearSessions() {
        sessions.clear();
        stdout.println("[*] All sessions cleared");
    }

    /**
     * User Session class
     */
    public static class UserSession {
        public String id;
        public String roleName; // Admin, User, Guest, etc.
        public String description;
        public Map<String, String> authTokens; // Cookie, Authorization, etc.
        public Map<String, String> bodyTokens; // JSON body field → value (body-carried session, e.g. gateway sessionToken)
        public Date createdAt;
    }

    /**
     * Session Test Result class
     */
    public static class SessionTestResult {
        public String testType; // IDOR, Privilege Escalation, etc.
        public boolean vulnerable;
        public String severity; // Critical, High, Medium, Low
        public String session1; // First session role
        public String session2; // Second session role
        public String evidence;
        public String description;
        public String remediation;
    }
}
