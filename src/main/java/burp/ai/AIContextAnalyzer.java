package burp.ai;

import burp.*;
import org.json.*;
import java.io.PrintWriter;
import java.util.*;

/**
 * AI-Powered Context Analyzer
 * Analyzes target application context using AI to detect technology stack,
 * frameworks, databases, and security measures
 *
 * This is a DIFFERENTIATING feature - Burp Scanner does NOT have this!
 *
 * @author Zahid Eroglu
 */
public class AIContextAnalyzer {

    private AiApiClient aiClient;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    // Cache for analyzed hosts
    private Map<String, ContextInfo> contextCache;

    public AIContextAnalyzer(AiApiClient aiClient,
                            IExtensionHelpers helpers,
                            PrintWriter stdout,
                            PrintWriter stderr) {
        this.aiClient = aiClient;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
        this.contextCache = new HashMap<>();
    }

    /**
     * Analyze application context from HTTP request/response
     */
    public ContextInfo analyzeContext(IHttpRequestResponse message) {
        try {
            // Get host for caching
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            String host = requestInfo.getUrl().getHost();

            // Check cache
            if (contextCache.containsKey(host)) {
                stdout.println("[*] Using cached context for: " + host);
                return contextCache.get(host);
            }

            stdout.println("[*] Analyzing context with AI for: " + host);

            // Build analysis prompt
            String prompt = buildContextAnalysisPrompt(message);

            // Send to AI
            List<AiApiClient.Message> messages = new ArrayList<>();
            messages.add(new AiApiClient.Message("system", getSystemPrompt()));
            messages.add(new AiApiClient.Message("user", prompt));

            JSONObject aiResponse = aiClient.chatCompletion(messages);

            // Parse AI response
            ContextInfo context = parseAIResponse(aiResponse, message);

            // Cache the result
            contextCache.put(host, context);

            stdout.println("[+] Context analysis complete:");
            stdout.println(context.toString());

            return context;

        } catch (Exception e) {
            stderr.println("[!] Context analysis error: " + e.getMessage());
            e.printStackTrace(stderr);
            return createBasicContext(message);
        }
    }

    /**
     * Build context analysis prompt
     */
    private String buildContextAnalysisPrompt(IHttpRequestResponse message) {
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        IResponseInfo responseInfo = message.getResponse() != null ?
            helpers.analyzeResponse(message.getResponse()) : null;

        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze the following HTTP request and response to identify the technology stack:\n\n");

        // Request details
        prompt.append("=== REQUEST ===\n");
        prompt.append("URL: ").append(requestInfo.getUrl().toString()).append("\n");
        prompt.append("Method: ").append(requestInfo.getMethod()).append("\n");

        // Headers
        prompt.append("\nRequest Headers:\n");
        List<String> headers = requestInfo.getHeaders();
        for (String header : headers) {
            if (!header.startsWith("GET") && !header.startsWith("POST")) {
                prompt.append(header).append("\n");
            }
        }

        // Response details
        if (responseInfo != null && message.getResponse() != null) {
            prompt.append("\n=== RESPONSE ===\n");
            prompt.append("Status Code: ").append(responseInfo.getStatusCode()).append("\n");

            prompt.append("\nResponse Headers:\n");
            List<String> respHeaders = responseInfo.getHeaders();
            for (String header : respHeaders) {
                if (!header.startsWith("HTTP/")) {
                    prompt.append(header).append("\n");
                }
            }

            // Response body (first 2000 chars)
            byte[] responseBytes = message.getResponse();
            int bodyOffset = responseInfo.getBodyOffset();
            if (bodyOffset < responseBytes.length) {
                String body = new String(responseBytes, bodyOffset,
                    Math.min(2000, responseBytes.length - bodyOffset));
                prompt.append("\nResponse Body (excerpt):\n");
                prompt.append(body);
            }
        }

        prompt.append("\n\n=== ANALYSIS REQUIRED ===\n");
        prompt.append("Please identify:\n");
        prompt.append("1. Technology (PHP, Java, .NET, Node.js, Python, Ruby, Go)\n");
        prompt.append("2. Framework (Laravel, Spring Boot, Django, Express, Rails, etc.)\n");
        prompt.append("3. Web Server (Apache, Nginx, IIS, Tomcat, etc.)\n");
        prompt.append("4. Database (MySQL, PostgreSQL, MSSQL, MongoDB, Oracle, etc.)\n");
        prompt.append("5. WAF/Security (Cloudflare, Akamai, ModSecurity, AWS WAF, etc.)\n");
        prompt.append("6. Application Type (e-commerce, banking, social, API, CMS, etc.)\n");
        prompt.append("7. API Type (REST, SOAP, or none)\n");
        prompt.append("8. Authentication Type (JWT, Session, OAuth, Basic Auth, etc.)\n");
        prompt.append("9. Any security headers or measures detected\n");
        prompt.append("10. Your confidence level (0-100%)\n\n");
        prompt.append("Respond in JSON format with these exact keys:\n");
        prompt.append("{\n");
        prompt.append("  \"technology\": \"...\",\n");
        prompt.append("  \"framework\": \"...\",\n");
        prompt.append("  \"webServer\": \"...\",\n");
        prompt.append("  \"database\": \"...\",\n");
        prompt.append("  \"wafDetected\": true/false,\n");
        prompt.append("  \"wafSignature\": \"...\",\n");
        prompt.append("  \"applicationType\": \"...\",\n");
        prompt.append("  \"isRestAPI\": true/false,\n");
        prompt.append("  \"authType\": \"...\",\n");
        prompt.append("  \"securityHeaders\": [...],\n");
        prompt.append("  \"confidence\": 0.0-1.0,\n");
        prompt.append("  \"reasoning\": \"Why you think this...\"\n");
        prompt.append("}\n");

        return prompt.toString();
    }

    /**
     * System prompt for AI
     */
    private String getSystemPrompt() {
        return "You are a security expert specialized in technology stack identification. " +
               "Analyze HTTP traffic to identify web technologies, frameworks, databases, " +
               "and security measures. Be precise and provide confidence scores. " +
               "Always respond in valid JSON format.";
    }

    /**
     * Parse AI response to ContextInfo
     */
    private ContextInfo parseAIResponse(JSONObject aiResponse, IHttpRequestResponse message) {
        ContextInfo context = new ContextInfo();

        try {
            // Extract AI response content
            String content = aiResponse.getJSONArray("choices")
                                      .getJSONObject(0)
                                      .getJSONObject("message")
                                      .getString("content");

            // Find JSON in the response
            int jsonStart = content.indexOf("{");
            int jsonEnd = content.lastIndexOf("}") + 1;

            if (jsonStart >= 0 && jsonEnd > jsonStart) {
                String jsonStr = content.substring(jsonStart, jsonEnd);
                JSONObject analysis = new JSONObject(jsonStr);

                // Parse fields
                context.setTechnology(analysis.optString("technology", "Unknown"));
                context.setFramework(analysis.optString("framework", "Unknown"));
                context.setWebServer(analysis.optString("webServer", "Unknown"));
                context.setDatabase(analysis.optString("database", "Unknown"));
                context.setWafDetected(analysis.optBoolean("wafDetected", false));
                context.setWafSignature(analysis.optString("wafSignature", "None"));
                context.setApplicationType(analysis.optString("applicationType", "Unknown"));
                context.setRestAPI(analysis.optBoolean("isRestAPI", false));
                context.setAuthType(analysis.optString("authType", "Unknown"));
                context.setConfidence(analysis.optDouble("confidence", 0.5));

                // Parse security headers
                if (analysis.has("securityHeaders")) {
                    JSONArray headers = analysis.getJSONArray("securityHeaders");
                    for (int i = 0; i < headers.length(); i++) {
                        context.addSecurityHeader(headers.getString(i));
                    }
                }

                // Store reasoning
                if (analysis.has("reasoning")) {
                    context.addCustomFinding("ai_reasoning", analysis.getString("reasoning"));
                }

            } else {
                stderr.println("[!] No JSON found in AI response, using basic detection");
                return createBasicContext(message);
            }

        } catch (Exception e) {
            stderr.println("[!] Error parsing AI response: " + e.getMessage());
            return createBasicContext(message);
        }

        // Enhance with header-based detection
        enhanceWithHeaderDetection(context, message);

        return context;
    }

    /**
     * Create basic context using header-based detection (fallback)
     */
    private ContextInfo createBasicContext(IHttpRequestResponse message) {
        ContextInfo context = new ContextInfo();
        context.setConfidence(0.3); // Low confidence for basic detection

        if (message.getResponse() == null) {
            return context;
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
        List<String> headers = responseInfo.getHeaders();

        for (String header : headers) {
            String lowerHeader = header.toLowerCase();

            // Server detection
            if (lowerHeader.startsWith("server:")) {
                String serverValue = header.substring(7).trim();
                context.setWebServer(serverValue);

                if (serverValue.toLowerCase().contains("apache")) {
                    context.setWebServer("Apache");
                } else if (serverValue.toLowerCase().contains("nginx")) {
                    context.setWebServer("Nginx");
                } else if (serverValue.toLowerCase().contains("iis")) {
                    context.setWebServer("IIS");
                }
            }

            // Technology detection
            if (lowerHeader.contains("x-powered-by:")) {
                String poweredBy = header.substring(header.indexOf(":") + 1).trim();
                if (poweredBy.toLowerCase().contains("php")) {
                    context.setTechnology("PHP");
                } else if (poweredBy.toLowerCase().contains("asp.net")) {
                    context.setTechnology(".NET");
                } else if (poweredBy.toLowerCase().contains("express")) {
                    context.setTechnology("Node.js");
                    context.setFramework("Express");
                }
            }

            // WAF detection
            if (lowerHeader.contains("cf-ray")) {
                context.setWafDetected(true);
                context.setWafSignature("Cloudflare");
            } else if (lowerHeader.contains("x-sucuri-id")) {
                context.setWafDetected(true);
                context.setWafSignature("Sucuri");
            }

            // Security headers
            if (lowerHeader.startsWith("x-frame-options:") ||
                lowerHeader.startsWith("content-security-policy:") ||
                lowerHeader.startsWith("strict-transport-security:")) {
                context.addSecurityHeader(header);
            }
        }

        return context;
    }

    /**
     * Enhance context with header-based detection
     */
    private void enhanceWithHeaderDetection(ContextInfo context, IHttpRequestResponse message) {
        if (message.getResponse() == null) {
            return;
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(message.getResponse());
        List<String> headers = responseInfo.getHeaders();

        for (String header : headers) {
            String lowerHeader = header.toLowerCase();

            // Additional WAF signatures
            if (!context.isWafDetected()) {
                if (lowerHeader.contains("cf-ray")) {
                    context.setWafDetected(true);
                    context.setWafSignature("Cloudflare");
                } else if (lowerHeader.contains("x-sucuri-id")) {
                    context.setWafDetected(true);
                    context.setWafSignature("Sucuri");
                } else if (lowerHeader.contains("x-akamai")) {
                    context.setWafDetected(true);
                    context.setWafSignature("Akamai");
                }
            }

            // Collect all security headers
            if (lowerHeader.startsWith("x-frame-options:") ||
                lowerHeader.startsWith("content-security-policy:") ||
                lowerHeader.startsWith("strict-transport-security:") ||
                lowerHeader.startsWith("x-content-type-options:") ||
                lowerHeader.startsWith("x-xss-protection:")) {

                if (!context.getSecurityHeaders().contains(header)) {
                    context.addSecurityHeader(header);
                }
            }
        }
    }

    /**
     * Clear context cache
     */
    public void clearCache() {
        contextCache.clear();
        stdout.println("[*] Context cache cleared");
    }

    /**
     * Get cached context for a host
     */
    public ContextInfo getCachedContext(String host) {
        return contextCache.get(host);
    }

    /**
     * Check if context is cached
     */
    public boolean hasCache(String host) {
        return contextCache.containsKey(host);
    }
}
