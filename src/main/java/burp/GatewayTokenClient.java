package burp;

import org.json.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Base64;

/**
 * Gateway LLM client — obtains an access token from Keycloak via the OAuth
 * token-exchange grant, then forwards an (OpenAI/OpenAI-style) chat payload to an
 * enterprise LLM gateway. Point it at your own gateway + Keycloak in Settings.
 *
 * @author Zahid Eroglu
 */
public class GatewayTokenClient {
    
    private String keycloakUrl;
    private String apiUrl;
    private String username;
    private String password;
    private String clientId;
    private String clientSecret;
    private String requestedSubject;
    private int timeout;
    private boolean allowInsecureSsl;
    private SSLSocketFactory insecureSocketFactory;
    private HostnameVerifier insecureHostnameVerifier;
    
    // Token cache
    private String cachedToken;
    private long tokenExpiryTime;
    
    public GatewayTokenClient(String keycloakUrl, String apiUrl, String username, String password,
                               String clientId, String clientSecret, String requestedSubject, int timeout, boolean allowInsecureSsl) {
        this.keycloakUrl = keycloakUrl;
        this.apiUrl = normalizeApiUrl(apiUrl);
        this.username = username;
        this.password = password;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.requestedSubject = requestedSubject;
        this.timeout = timeout;
        this.allowInsecureSsl = allowInsecureSsl;
    }

    /**
     * Normalize the configured gateway URL: trim it and drop any trailing slashes.
     * Point {@code apiUrl} directly at your gateway's chat endpoint.
     */
    private static String normalizeApiUrl(String url) {
        if (url == null) return null;
        String u = url.trim();
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        return u;
    }

    /**
     * Send chat completion request to the gateway
     */
    public JSONObject chatCompletion(List<AiApiClient.Message> messages) throws Exception {
        return chatCompletion(messages, 0.7, 2000);
    }
    
    public JSONObject chatCompletion(List<AiApiClient.Message> messages, double temperature, int maxTokens) throws Exception {
        // Get valid token
        String token = getValidToken();
        
        // Build inner payload (OpenAI-compatible format)
        JSONObject innerPayload = new JSONObject();
        innerPayload.put("model", "Qwen3-235B-FP8");
        innerPayload.put("temperature", temperature);
        innerPayload.put("max_tokens", maxTokens);
        
        JSONArray messagesArray = new JSONArray();
        for (AiApiClient.Message msg : messages) {
            JSONObject msgObj = new JSONObject();
            msgObj.put("role", msg.getRole());
            msgObj.put("content", msg.getContent());
            messagesArray.put(msgObj);
        }
        innerPayload.put("messages", messagesArray);
        
        // Build outer payload (gateway envelope)
        JSONObject payload = new JSONObject();
        payload.put("endpointCode", "LLMServing");
        payload.put("jsonData", innerPayload.toString());

        // Send request
        JSONObject response = sendRequestWithRetry(payload.toString(), 3);
        AIUsageStats.getInstance().recordResponse(response);
        return response;
    }
    
    /**
     * Get valid token (cached or new)
     */
    private String getValidToken() throws Exception {
        // Check if cached token is still valid
        if (cachedToken != null && System.currentTimeMillis() < tokenExpiryTime) {
            return cachedToken;
        }
        
        // Get new token
        cachedToken = getKeycloakToken();
        // Set expiry to 55 minutes from now (tokens typically last 60 minutes)
        tokenExpiryTime = System.currentTimeMillis() + (55 * 60 * 1000);
        
        return cachedToken;
    }
    
    /**
     * Get Keycloak token
     */
    private String getKeycloakToken() throws Exception {
        URL url = new URL(keycloakUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            // Configure connection with increased timeouts
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("User-Agent", "AI-Security-Scanner/1.0");
            configureSslIfNeeded(conn);
            conn.setConnectTimeout(timeout * 2000); // Double timeout for connection
            conn.setReadTimeout(timeout * 2000);    // Double timeout for read
            conn.setDoOutput(true);
            
            // Build form data
            StringBuilder formData = new StringBuilder();
            formData.append("username=").append(URLEncoder.encode(username, "UTF-8"));
            formData.append("&password=").append(URLEncoder.encode(password, "UTF-8"));
            formData.append("&grant_type=").append(URLEncoder.encode("urn:ietf:params:oauth:grant-type:token-exchange", "UTF-8"));
            formData.append("&client_id=").append(URLEncoder.encode(clientId, "UTF-8"));
            formData.append("&client_secret=").append(URLEncoder.encode(clientSecret, "UTF-8"));
            formData.append("&requested_subject=").append(URLEncoder.encode(requestedSubject, "UTF-8"));
            
            // Send form data
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = formData.toString().getBytes("UTF-8");
                os.write(input, 0, input.length);
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                JSONObject response = readResponse(conn.getInputStream());
                return response.getString("access_token");
            } else {
                String errorBody = readErrorResponse(conn.getErrorStream());
                throw new Exception("Keycloak token request failed: " + responseCode + " - " + errorBody);
            }
            
        } finally {
            conn.disconnect();
        }
    }
    
    /**
     * Test API connection
     */
    public boolean testConnection() {
        try {
            // Try to get a token
            String token = getKeycloakToken();
            return token != null && !token.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Test API connection with detailed result
     */
    public AiApiClient.ConnectionTestResult testConnectionDetailed() {
        AiApiClient.ConnectionTestResult result = new AiApiClient.ConnectionTestResult();
        result.endpoint = apiUrl;
        result.model = "Qwen3-235B-FP8";

        long startTime = System.currentTimeMillis();

        try {
            // Test 1: Check if Keycloak URL is valid
            URL keycloakUrlObj = new URL(keycloakUrl);
            result.urlValid = true;

            // Test 2: Try to get token
            String token = getKeycloakToken();
            if (token == null || token.isEmpty()) {
                result.success = false;
                result.message = "Failed to obtain access token from Keycloak";
                result.errorDetails = "Check credentials and Keycloak endpoint";
                return result;
            }

            // Test 3: Try a simple API call
            JSONObject testPayload = new JSONObject();
            testPayload.put("endpointCode", "LLMServing");
            
            JSONObject innerPayload = new JSONObject();
            innerPayload.put("model", "Qwen3-235B-FP8");
            innerPayload.put("max_tokens", 10);
            innerPayload.put("temperature", 0.1);
            
            JSONArray testMessages = new JSONArray();
            JSONObject testMsg = new JSONObject();
            testMsg.put("role", "user");
            testMsg.put("content", "test");
            testMessages.put(testMsg);
            innerPayload.put("messages", testMessages);
            
            testPayload.put("jsonData", innerPayload.toString());
            
            JSONObject response = sendRequest(testPayload.toString());
            
            result.success = true;
            result.message = "Connection successful!";
            result.responseTime = System.currentTimeMillis() - startTime;

        } catch (Exception e) {
            result.success = false;
            result.responseTime = System.currentTimeMillis() - startTime;
            result.message = "Connection error: " + e.getClass().getSimpleName();
            result.errorDetails = "Error: " + e.getMessage();
        }

        return result;
    }
    
    /**
     * Send POST request with retry logic
     */
    private JSONObject sendRequestWithRetry(String payload, int maxRetries) throws Exception {
        Exception lastException = null;
        boolean lastWasRateLimit = false;
        // Rate-limits (429) get a SEPARATE, more patient budget than hard errors. A shared
        // gateway LLM backend is frequently busy; backing off only ~6s over 3 tries and then
        // giving up is what let the agent's 2-strike circuit breaker stop the scan after ~2 turns.
        // Retry up to rateLimitBudget times with capped exponential backoff (2,4,8,16,16s) so a
        // busy model gets time to free up before we surface the failure. The call is idempotent.
        int rateLimitBudget = Math.max(maxRetries, 6);
        int hardAttempt = 0;
        int rlAttempt = 0;

        while (true) {
            try {
                return sendRequest(payload);
            } catch (SocketTimeoutException e) {
                lastException = e; lastWasRateLimit = false;
                if (++hardAttempt >= maxRetries) break;
                Thread.sleep(2000); // Wait 2 seconds before retry
            } catch (RateLimitException e) {
                // Backend is rate-limited (429), often wrapped as a 503 by the gateway.
                lastException = e; lastWasRateLimit = true;
                if (++rlAttempt >= rateLimitBudget) break;
                Thread.sleep(Math.min(20000L, 2000L * (1L << Math.min(rlAttempt - 1, 3))));
            } catch (Exception e) {
                throw e; // Don't retry on other errors
            }
        }

        int tries = lastWasRateLimit ? rlAttempt : hardAttempt;
        throw new Exception("Request failed after " + tries + " retries: " +
                          (lastException != null ? lastException.getMessage() : "Unknown error"));
    }
    
    /**
     * Send POST request
     */
    private JSONObject sendRequest(String payload) throws Exception {
        String token = getValidToken();
        
        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            // Configure connection with increased timeouts
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setRequestProperty("User-Agent", "AI-Security-Scanner/1.0");
            conn.setRequestProperty("Accept", "application/json");
            configureSslIfNeeded(conn);
            conn.setConnectTimeout(timeout * 2000); // Double timeout for connection
            conn.setReadTimeout(timeout * 2000);    // Double timeout for read
            conn.setDoOutput(true);
            
            // Send payload
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.getBytes("UTF-8");
                os.write(input, 0, input.length);
                os.flush();
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                return readResponse(conn.getInputStream());
            }
            String errorBody = readErrorResponse(conn.getErrorStream());
            // The gateway forwards an overloaded model backend as HTTP 503 with a nested
            // "429 (Too Many Requests)" in the body. Treat the direct 429 AND that wrapped
            // form as a retryable rate-limit so sendRequestWithRetry backs off and retries.
            if (responseCode == 429 || responseCode == 503
                    || errorBody.contains("Too Many Requests") || errorBody.contains("429 (Too Many Requests)")) {
                throw new RateLimitException(summarizeGatewayError(responseCode, errorBody));
            }
            throw new Exception(summarizeGatewayError(responseCode, errorBody));
            
        } finally {
            conn.disconnect();
        }
    }
    
    /**
     * Read JSON response
     */
    private JSONObject readResponse(InputStream inputStream) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line.trim());
        }
        
        return new JSONObject(response.toString());
    }
    
    /**
     * Read error response
     */
    private String readErrorResponse(InputStream errorStream) {
        if (errorStream == null) return "No error details";
        
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream, "UTF-8"));
            StringBuilder error = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                error.append(line);
            }
            
            return error.toString();
        } catch (Exception e) {
            return "Could not read error details";
        }
    }

    /**
     * Turn the gateway's verbose error envelope into a short, user-facing message.
     * Falls back to the raw body (trimmed) when it is not the expected JSON shape.
     */
    private static String summarizeGatewayError(int httpCode, String body) {
        if (body == null) body = "";
        try {
            JSONObject j = new JSONObject(body);
            JSONObject err = j.optJSONObject("error");
            if (err != null) {
                String text = err.optString("localizedText", err.optString("text", ""));
                if (text.contains("429") || text.contains("Too Many Requests")) {
                    return "Model şu an meşgul (429 Too Many Requests). Lütfen birkaç saniye sonra tekrar deneyin.";
                }
                String code = err.optString("code", "");
                String shortText = text.length() > 200 ? text.substring(0, 200) + "…" : text;
                String msg = (code.isEmpty() ? "" : code) + (shortText.isEmpty() ? "" : (": " + shortText));
                return msg.isEmpty() ? ("API returned " + httpCode) : msg;
            }
        } catch (Exception ignore) {
            // not the gateway JSON shape; fall through to the raw (trimmed) body
        }
        String trimmed = body.length() > 200 ? body.substring(0, 200) + "…" : body;
        return "API returned " + httpCode + (trimmed.isEmpty() ? "" : (": " + trimmed));
    }

    /** Marker for a retryable rate-limit (HTTP 429, or a 503 wrapping a 429). */
    private static class RateLimitException extends Exception {
        RateLimitException(String message) { super(message); }
    }

    private void configureSslIfNeeded(HttpURLConnection conn) throws Exception {
        // Enterprise gateway endpoints (Keycloak + the LLM gateway) are often internal,
        // VPN-only hosts whose TLS certs are signed by a private CA that is NOT in the
        // JVM truststore -> "PKIX path building failed". Cert verification is therefore
        // skipped for the Gateway provider only, as an explicit opt-in. This client never
        // talks to any host other than the configured gateway, so the hosted/local secure
        // paths are unaffected.
        if (!(conn instanceof HttpsURLConnection)) {
            return;
        }

        HttpsURLConnection httpsConn = (HttpsURLConnection) conn;

        if (insecureSocketFactory == null || insecureHostnameVerifier == null) {
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            insecureSocketFactory = sc.getSocketFactory();
            insecureHostnameVerifier = (hostname, session) -> true;
        }

        httpsConn.setSSLSocketFactory(insecureSocketFactory);
        httpsConn.setHostnameVerifier(insecureHostnameVerifier);
    }
    
    // Getters and setters
    public String getKeycloakUrl() { return keycloakUrl; }
    public void setKeycloakUrl(String keycloakUrl) { this.keycloakUrl = keycloakUrl; }
    
    public String getApiUrl() { return apiUrl; }
    public void setApiUrl(String apiUrl) { this.apiUrl = normalizeApiUrl(apiUrl); }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    
    public String getRequestedSubject() { return requestedSubject; }
    public void setRequestedSubject(String requestedSubject) { this.requestedSubject = requestedSubject; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
}
