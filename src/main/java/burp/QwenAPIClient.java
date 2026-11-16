package burp;

import org.json.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Universal AI API Client - Supports both Qwen and Gateway APIs
 * 
 * @author Zahid Eroglu
 */
public class QwenAPIClient {

    private String apiUrl;
    private String apiKey;
    private String model;
    private int timeout;
    private boolean allowInsecureSsl;
    private SSLSocketFactory insecureSocketFactory;
    private HostnameVerifier insecureHostnameVerifier;

    // Performance: LRU Cache
    private final LinkedHashMap<String, JSONObject> responseCache;
    private static final int MAX_CACHE_SIZE = 100;

    // Gateway API client (optional)
    private GatewayTokenClient gatewayClient;
    private boolean useGateway;

    // Constructor for Qwen API
    public QwenAPIClient(String apiUrl, String apiKey, String model, int timeout, boolean allowInsecureSsl) {
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.model = model;
        this.timeout = timeout;
        this.useGateway = false;
        this.allowInsecureSsl = allowInsecureSsl;

        // Initialize cache
        this.responseCache = new LinkedHashMap<String, JSONObject>(MAX_CACHE_SIZE + 1, .75F, true) {
            public boolean removeEldestEntry(Map.Entry<String, JSONObject> eldest) {
                return size() > MAX_CACHE_SIZE;
            }
        };
    }

    // Constructor for Gateway API
    public QwenAPIClient(String keycloakUrl, String apiUrl, String username, String password,
            String clientId, String clientSecret, String requestedSubject, int timeout, boolean allowInsecureSsl) {
        this.gatewayClient = new GatewayTokenClient(
                keycloakUrl, apiUrl, username, password, clientId, clientSecret, requestedSubject, timeout,
                allowInsecureSsl);
        this.useGateway = true;
        this.timeout = timeout;
        this.allowInsecureSsl = allowInsecureSsl;

        // Initialize cache
        this.responseCache = new LinkedHashMap<String, JSONObject>(MAX_CACHE_SIZE + 1, .75F, true) {
            public boolean removeEldestEntry(Map.Entry<String, JSONObject> eldest) {
                return size() > MAX_CACHE_SIZE;
            }
        };
    }

    /**
     * Factory method to create appropriate client based on provider
     */
    public static QwenAPIClient createClient(Settings settings) {
        if ("gateway".equals(settings.getApiProvider())) {
            return new QwenAPIClient(
                    "https://your-keycloak.example.com/realms/your-realm/protocol/openid-connect/token",
                    settings.getGatewayApiUrl(),
                    settings.getGatewayUsername(),
                    settings.getGatewayPassword(),
                    settings.getGatewayClientId(),
                    settings.getGatewayClientSecret(),
                    settings.getGatewayRequestedSubject(),
                    settings.getTimeout(),
                    settings.isAllowInsecureSsl());
        } else if ("local".equals(settings.getApiProvider())) {
            // Local AI model (Ollama / LM Studio / llama.cpp - OpenAI compatible)
            return new QwenAPIClient(
                    settings.getLocalApiUrl(),
                    settings.getLocalApiKey(),
                    settings.getLocalModel(),
                    settings.getTimeout(),
                    settings.isAllowInsecureSsl());
        } else {
            // Default to Qwen API
            return new QwenAPIClient(
                    settings.getApiUrl(),
                    settings.getApiKey(),
                    settings.getModel(),
                    settings.getTimeout(),
                    settings.isAllowInsecureSsl());
        }
    }

    /**
     * Update all internal fields from the given settings without replacing the instance.
     * Called after the user saves settings so every component that holds this reference
     * automatically picks up the new model / API key / endpoint.
     */
    public synchronized void rebuildFromSettings(Settings settings) {
        if ("gateway".equals(settings.getApiProvider())) {
            this.useGateway = true;
            this.gatewayClient = new GatewayTokenClient(
                    "https://your-keycloak.example.com/realms/your-realm/protocol/openid-connect/token",
                    settings.getGatewayApiUrl(),
                    settings.getGatewayUsername(),
                    settings.getGatewayPassword(),
                    settings.getGatewayClientId(),
                    settings.getGatewayClientSecret(),
                    settings.getGatewayRequestedSubject(),
                    settings.getTimeout(),
                    settings.isAllowInsecureSsl());
        } else if ("local".equals(settings.getApiProvider())) {
            this.useGateway = false;
            this.gatewayClient = null;
            this.apiUrl = settings.getLocalApiUrl();
            this.apiKey = settings.getLocalApiKey();
            this.model = settings.getLocalModel();
        } else {
            this.useGateway = false;
            this.gatewayClient = null;
            this.apiUrl = settings.getApiUrl();
            this.apiKey = settings.getApiKey();
            this.model = settings.getModel();
        }
        this.timeout = settings.getTimeout();
        this.allowInsecureSsl = settings.isAllowInsecureSsl();
        // Reset lazy SSL state so it is re-initialized with updated allowInsecureSsl.
        this.insecureSocketFactory = null;
        this.insecureHostnameVerifier = null;
        responseCache.clear();
    }

    /**
     * Send chat completion request to appropriate API
     */
    public JSONObject chatCompletion(List<Message> messages) throws Exception {
        return chatCompletion(messages, 0.3, 2000);
    }

    public JSONObject chatCompletion(List<Message> messages, double temperature, int maxTokens) throws Exception {
        return chatCompletion(messages, temperature, maxTokens, null);
    }

    /** Chat completion with an optional per-call model override (used by the fast engine). */
    public JSONObject chatCompletion(List<Message> messages, double temperature, int maxTokens, String modelOverride) throws Exception {
        return chatCompletion(messages, temperature, maxTokens, modelOverride, 3);
    }

    /**
     * Chat completion with an explicit retry count. The agentic engine uses
     * maxRetries=1 so a single slow/transient call does not block a turn with
     * the default 3×2s back-off.
     */
    public JSONObject chatCompletion(List<Message> messages, double temperature, int maxTokens,
                                     String modelOverride, int maxRetries) throws Exception {
        if (useGateway) {
            // The gateway client records the SUCCESS (token usage) itself; mirror the Qwen path by
            // also recording FAILURES here, so 429/timeout/error calls show up in AI Usage stats
            // instead of silently vanishing (the user only saw successes counted otherwise).
            try {
                return gatewayClient.chatCompletion(messages, temperature, maxTokens);
            } catch (Exception e) {
                AIUsageStats.getInstance().recordFailure();
                throw e;
            }
        } else {
            return chatCompletionQwen(messages, temperature, maxTokens, modelOverride, maxRetries);
        }
    }

    /**
     * Send chat completion request to Qwen API
     */
    private JSONObject chatCompletionQwen(List<Message> messages, double temperature, int maxTokens, String modelOverride, int maxRetries) throws Exception {
        String endpoint = apiUrl + "/chat/completions";

        // Build request payload
        JSONObject payload = new JSONObject();
        payload.put("model", (modelOverride != null && !modelOverride.trim().isEmpty()) ? modelOverride : model);
        payload.put("temperature", temperature);
        payload.put("max_tokens", maxTokens);

        JSONArray messagesArray = new JSONArray();
        for (Message msg : messages) {
            JSONObject msgObj = new JSONObject();
            msgObj.put("role", msg.getRole());
            msgObj.put("content", msg.getContent());
            messagesArray.put(msgObj);
        }
        payload.put("messages", messagesArray);

        // Check cache
        String cacheKey = payload.toString();
        synchronized (responseCache) {
            if (responseCache.containsKey(cacheKey)) {
                AIUsageStats.getInstance().recordCacheHit(); // served free, no tokens
                return responseCache.get(cacheKey);
            }
        }

        // Send HTTP request with retry
        JSONObject response;
        try {
            response = sendRequestWithRetry(endpoint, payload.toString(), Math.max(1, maxRetries));
        } catch (Exception e) {
            AIUsageStats.getInstance().recordFailure();
            throw e;
        }

        // Count this real call and its token usage.
        AIUsageStats.getInstance().recordResponse(response);

        // Update cache
        if (response != null && !response.has("error")) {
            synchronized (responseCache) {
                responseCache.put(cacheKey, response);
            }
        }

        return response;
    }

    /**
     * Test API connection - returns detailed result
     */
    public boolean testConnection() {
        if (useGateway) {
            return gatewayClient.testConnection();
        } else {
            try {
                String endpoint = apiUrl + "/models";
                JSONObject response = sendGetRequest(endpoint);
                return response != null && response.has("data");
            } catch (Exception e) {
                return false;
            }
        }
    }

    /**
     * Test API connection with detailed error info
     */
    public ConnectionTestResult testConnectionDetailed() {
        if (useGateway) {
            ConnectionTestResult result = gatewayClient.testConnectionDetailed();
            return result;
        } else {
            return testConnectionDetailedQwen();
        }
    }

    /**
     * Test Qwen API connection with detailed error info
     */
    private ConnectionTestResult testConnectionDetailedQwen() {
        ConnectionTestResult result = new ConnectionTestResult();
        result.endpoint = apiUrl + "/models"; // Use full endpoint for clarity
        result.model = model;

        long startTime = System.currentTimeMillis();

        try {
            // Test 1: Check if URL is valid
            URL url = new URL(apiUrl + "/models");
            result.urlValid = true;

            // Test 2: Try to connect
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            applyAuth(conn);
            configureSslIfNeeded(conn);
            conn.setConnectTimeout(timeout * 1000);
            conn.setReadTimeout(timeout * 1000);

            // Test 3: Get response
            int responseCode = conn.getResponseCode();
            result.responseCode = responseCode;
            result.responseTime = System.currentTimeMillis() - startTime;

            if (responseCode == 200) {
                JSONObject response = readResponse(conn.getInputStream());
                result.success = true;
                result.message = "Connection successful!";

                // Get model count
                if (response.has("data")) {
                    result.modelCount = response.getJSONArray("data").length();
                }
            } else if (responseCode == 401) {
                result.success = false;
                result.message = "Authentication failed - Invalid API key";
                result.errorDetails = "HTTP 401: The API key is invalid or missing.";
            } else if (responseCode == 403) {
                result.success = false;
                result.message = "Access denied - Check API permissions";
                result.errorDetails = "HTTP 403: You don't have permission to access this endpoint.";
            } else if (responseCode == 404) {
                result.success = false;
                result.message = "Endpoint not found - Check API URL";
                result.errorDetails = "HTTP 404: The /models endpoint was not found. Verify the API URL is correct.";
            } else {
                result.success = false;
                result.message = "Server error: " + responseCode;
                result.errorDetails = readErrorResponse(conn.getErrorStream());
            }

            conn.disconnect();

        } catch (java.net.SocketTimeoutException e) {
            result.success = false;
            result.responseTime = System.currentTimeMillis() - startTime;
            result.message = "Connection timeout";
            result.errorDetails = "The server did not respond within " + timeout + " seconds.\n\n" +
                    "Possible causes:\n" +
                    "- Server is not reachable from this network\n" +
                    "- Firewall blocking the connection\n" +
                    "- Server is overloaded or down\n" +
                    "- Wrong port or protocol (http vs https)\n\n" +
                    "Try:\n" +
                    "- Increase timeout in settings\n" +
                    "- Check if you can access the URL in browser\n" +
                    "- Verify network/VPN settings";
        } catch (java.net.ConnectException e) {
            result.success = false;
            result.responseTime = System.currentTimeMillis() - startTime;
            result.message = "Connection refused";
            result.errorDetails = "Could not connect to the server.\n\n" +
                    "Error: " + e.getMessage() + "\n\n" +
                    "Possible causes:\n" +
                    "- Server is not running\n" +
                    "- Wrong port number\n" +
                    "- Firewall blocking the connection\n\n" +
                    "URL attempted: " + apiUrl;
        } catch (java.net.UnknownHostException e) {
            result.success = false;
            result.message = "Unknown host";
            result.errorDetails = "Could not resolve hostname.\n\n" +
                    "Error: " + e.getMessage() + "\n\n" +
                    "Possible causes:\n" +
                    "- DNS resolution failed\n" +
                    "- Typo in the URL\n" +
                    "- No internet connection";
        } catch (javax.net.ssl.SSLException e) {
            result.success = false;
            result.message = "SSL/TLS error";
            result.errorDetails = "SSL certificate or handshake error.\n\n" +
                    "Error: " + e.getMessage() + "\n\n" +
                    "Possible causes:\n" +
                    "- Invalid SSL certificate\n" +
                    "- Certificate expired\n" +
                    "- Protocol mismatch";
        } catch (java.net.MalformedURLException e) {
            result.success = false;
            result.urlValid = false;
            result.message = "Invalid URL format";
            result.errorDetails = "The API URL is not valid.\n\n" +
                    "Error: " + e.getMessage() + "\n\n" +
                    "Expected format: https://your-server.com/v1";
        } catch (Exception e) {
            result.success = false;
            result.responseTime = System.currentTimeMillis() - startTime;
            result.message = "Connection error: " + e.getClass().getSimpleName();
            result.errorDetails = "Error: " + e.getMessage() + "\n\n" +
                    "Exception type: " + e.getClass().getName() + "\n\n" +
                    "Stack trace:\n" + getStackTraceString(e);
        }

        return result;
    }

    /**
     * Get stack trace as string
     */
    private String getStackTraceString(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        String trace = sw.toString();
        // Limit to first 500 chars
        if (trace.length() > 500) {
            trace = trace.substring(0, 500) + "...";
        }
        return trace;
    }

    /**
     * Connection test result holder
     */
    public static class ConnectionTestResult {
        public boolean success = false;
        public boolean urlValid = false;
        public String message = "";
        public String errorDetails = "";
        public String endpoint = "";
        public String model = "";
        public int responseCode = 0;
        public long responseTime = 0;
        public int modelCount = 0;

        public String getDetailedReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== Connection Test Report ===\n\n");
            sb.append("Status: ").append(success ? "SUCCESS" : "FAILED").append("\n");
            sb.append("Endpoint: ").append(endpoint).append("\n");
            sb.append("Model: ").append(model).append("\n");
            sb.append("URL Valid: ").append(urlValid ? "Yes" : "No").append("\n");

            if (responseCode > 0) {
                sb.append("HTTP Response: ").append(responseCode).append("\n");
            }
            if (responseTime > 0) {
                sb.append("Response Time: ").append(responseTime).append(" ms\n");
            }
            if (modelCount > 0) {
                sb.append("Available Models: ").append(modelCount).append("\n");
            }

            sb.append("\n").append(message).append("\n");

            if (errorDetails != null && !errorDetails.isEmpty()) {
                sb.append("\n--- Details ---\n");
                sb.append(errorDetails);
            }

            return sb.toString();
        }
    }

    /**
     * Get available models
     */
    public JSONArray getModels() throws Exception {
        if (useGateway) {
            // Gateway serves a fixed model; return it as a synthetic list.
            JSONArray arr = new JSONArray();
            JSONObject m = new JSONObject();
            m.put("id", "Qwen3-235B-FP8");
            arr.put(m);
            return arr;
        }
        String endpoint = apiUrl + "/models";
        JSONObject response = sendGetRequest(endpoint);
        return response != null ? response.getJSONArray("data") : new JSONArray();
    }

    /**
     * Send POST request with retry logic
     */
    private JSONObject sendRequestWithRetry(String endpoint, String payload, int maxRetries) throws Exception {
        Exception lastException = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                return sendPostRequest(endpoint, payload);
            } catch (SocketTimeoutException e) {
                lastException = e;
                if (attempt < maxRetries - 1) {
                    Thread.sleep(2000); // Wait 2 seconds before retry
                }
            } catch (Exception e) {
                throw e; // Don't retry on other errors
            }
        }

        throw new Exception("Request failed after " + maxRetries + " retries: " +
                (lastException != null ? lastException.getMessage() : "Unknown error"));
    }

    /**
     * Send POST request
     */
    private JSONObject sendPostRequest(String endpoint, String payload) throws Exception {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            // Configure connection
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            applyAuth(conn);
            configureSslIfNeeded(conn);
            conn.setConnectTimeout(timeout * 1000);
            conn.setReadTimeout(timeout * 1000);
            conn.setDoOutput(true);

            // Send payload
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.getBytes("UTF-8");
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();

            if (responseCode == 200) {
                return readResponse(conn.getInputStream());
            } else if (responseCode == 429) {
                throw new Exception("Rate limited by API");
            } else {
                String errorBody = readErrorResponse(conn.getErrorStream());
                throw new Exception("API returned " + responseCode + ": " + errorBody);
            }

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Send GET request
     */
    private JSONObject sendGetRequest(String endpoint) throws Exception {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("GET");
            applyAuth(conn);
            configureSslIfNeeded(conn);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                return readResponse(conn.getInputStream());
            }

            return null;

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
        if (errorStream == null)
            return "No error details";

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
     * Apply Authorization header only when an API key is present.
     * Local models (Ollama / llama.cpp) typically need no key.
     */
    private void applyAuth(HttpURLConnection conn) {
        // Some gateways/WAFs block the default "Java/..." User-Agent (HTTP 403),
        // so always send a non-Java User-Agent.
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; AppSecHunter/2.0)");
        conn.setRequestProperty("Accept", "application/json");
        if (apiKey != null && !apiKey.trim().isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
        }
    }

    private void configureSslIfNeeded(HttpURLConnection conn) throws Exception {
        if (!allowInsecureSsl) {
            return;
        }
        if (!(conn instanceof HttpsURLConnection)) {
            return;
        }

        HttpsURLConnection httpsConn = (HttpsURLConnection) conn;

        if (insecureSocketFactory == null || insecureHostnameVerifier == null) {
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
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
    public String getApiUrl() {
        return apiUrl;
    }

    public void setApiUrl(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    // Alias method for compatibility
    public void setApiEndpoint(String apiUrl) {
        this.apiUrl = apiUrl;
    }

    /**
     * Message class for chat API
     */
    public static class Message {
        private String role;
        private String content;

        public Message(String role, String content) {
            this.role = role;
            this.content = content;
        }

        public String getRole() {
            return role;
        }

        public String getContent() {
            return content;
        }
    }
}
