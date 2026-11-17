package burp.businesslogic;

import burp.*;
import org.json.*;
import java.io.PrintWriter;
import java.util.*;

/**
 * Workflow Analyzer
 * Analyzes application workflows using AI to find bypass opportunities
 *
 * @author Zahid Eroglu
 */
public class WorkflowAnalyzer {

    private AiApiClient aiClient;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public WorkflowAnalyzer(AiApiClient aiClient,
            IExtensionHelpers helpers,
            PrintWriter stdout,
            PrintWriter stderr) {
        this.aiClient = aiClient;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * Generate attack chains using AI analysis
     */
    public List<burp.api.ChainAttackDetector.APIChain> generateAttackChains(IHttpRequestResponse message) {
        List<burp.api.ChainAttackDetector.APIChain> chains = new ArrayList<>();

        try {
            // Build AI prompt
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            String url = requestInfo.getUrl().toString();
            String method = requestInfo.getMethod();
            String requestBody = "";

            // Extract body
            int bodyOffset = requestInfo.getBodyOffset();
            byte[] request = message.getRequest();
            if (request.length > bodyOffset) {
                requestBody = new String(Arrays.copyOfRange(request, bodyOffset, request.length));
            }

            StringBuilder prompt = new StringBuilder();
            prompt.append(
                    "Analyze this HTTP request and generate potential attack chains (sequences of requests) to exploit business logic vulnerabilities.\n");
            prompt.append("Focus on: Price Manipulation, IDOR, Privilege Escalation, and Workflow Bypass.\n\n");
            prompt.append("Request:\n");
            prompt.append(method).append(" ").append(url).append("\n");
            prompt.append(requestBody).append("\n\n");

            prompt.append(
                    "Respond with a JSON array of attack chains. Each chain should have 'name', 'description', and 'steps'.\n");
            prompt.append(
                    "Each step should have 'url', 'method', 'body' (optional), and 'headers' (optional JSON object).\n");
            prompt.append("Example format:\n");
            prompt.append("[\n");
            prompt.append("  {\n");
            prompt.append("    \"name\": \"Price Manipulation\",\n");
            prompt.append("    \"description\": \"Change price to 0.01\",\n");
            prompt.append("    \"steps\": [\n");
            prompt.append("      { \"url\": \"...\", \"method\": \"POST\", \"body\": \"{...}\" }\n");
            prompt.append("    ]\n");
            prompt.append("  }\n");
            prompt.append("]\n");

            List<AiApiClient.Message> messages = new ArrayList<>();
            messages.add(new AiApiClient.Message("system",
                    "You are an expert security researcher. Output only valid JSON."
                    + (burp.i18n.I18n.isTr()
                        ? " Write any human-readable \"description\", \"attackScenario\"/scenario and \"remediation\" "
                          + "field VALUES in TURKISH; keep all JSON keys, the chain \"name\" and \"severity\" enum in English."
                        : "")));
            messages.add(new AiApiClient.Message("user", prompt.toString()));

            JSONObject aiResponse = aiClient.chatCompletion(messages);

            String content = aiResponse.getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content");

            // Extract JSON from content (handle markdown code blocks if present)
            if (content.contains("```json")) {
                content = content.substring(content.indexOf("```json") + 7);
                if (content.contains("```")) {
                    content = content.substring(0, content.indexOf("```"));
                }
            } else if (content.contains("```")) {
                content = content.substring(content.indexOf("```") + 3);
                if (content.contains("```")) {
                    content = content.substring(0, content.indexOf("```"));
                }
            }

            content = content.trim();

            // Parse JSON
            stdout.println("[DEBUG] Parsing chain JSON: " + content);
            JSONArray chainsJson = new JSONArray(content);
            stdout.println("[DEBUG] Chains count: " + chainsJson.length());

            for (int i = 0; i < chainsJson.length(); i++) {
                JSONObject chainJson = chainsJson.getJSONObject(i);
                burp.api.ChainAttackDetector.APIChain chain = new burp.api.ChainAttackDetector.APIChain();
                chain.name = chainJson.optString("name", "AI Found Chain");
                chain.description = chainJson.optString("description", "");

                JSONArray stepsJson = chainJson.getJSONArray("steps");
                stdout.println("[DEBUG] Chain " + i + " steps count: " + stepsJson.length());

                for (int j = 0; j < stepsJson.length(); j++) {
                    try {
                        JSONObject stepJson = stepsJson.getJSONObject(j);
                        String u = stepJson.getString("url");
                        String m = stepJson.getString("method");
                        stdout.println("[DEBUG] Step " + j + ": " + m + " " + u);

                        // SCOPE GUARD: the AI returns step URLs as free text. Never let the scanner fire a
                        // request the model invented at an off-scope / cross-origin host (would be a
                        // scanner-driven SSRF / out-of-scope hit). Keep only same-host steps.
                        if (!sameHost(u, url)) {
                            stdout.println("[WorkflowAnalyzer] off-scope step skipped: " + u);
                            continue;
                        }

                        burp.api.ChainAttackDetector.APIEndpoint step = new burp.api.ChainAttackDetector.APIEndpoint(u,
                                m);

                        if (stepJson.has("body")) {
                            step.requestBody = stepJson.getString("body");
                        }

                        if (stepJson.has("headers")) {
                            JSONObject headers = stepJson.getJSONObject("headers");
                            for (String key : headers.keySet()) {
                                step.headers.put(key, headers.getString(key));
                            }
                        }

                        chain.steps.add(step);
                    } catch (Exception ex) {
                        stderr.println("[ERROR] Failed to parse step " + j + ": " + ex.getMessage());
                    }
                }
                chains.add(chain);
            }

        } catch (Exception e) {
            stderr.println("[!] AI chain generation error: " + e.getMessage());
            e.printStackTrace(stderr);
        }

        return chains;
    }

    /** True if the AI-supplied step URL is on the SAME host as the analysed request (scope guard).
     *  Uses a lenient regex host extractor — java.net.URI throws on the {id}/{token} placeholders and
     *  unencoded query values the model routinely emits, which would over-suppress legit same-host steps. */
    private boolean sameHost(String stepUrl, String baseUrl) {
        String sh = hostOf(stepUrl);
        if (sh == null || sh.isEmpty()) return true; // relative URL → resolved against the base host, in scope
        String bh = hostOf(baseUrl);
        return bh != null && sh.equalsIgnoreCase(bh);
    }

    /** Host of an absolute URL via regex (tolerant of placeholders); null for a scheme-less/relative URL. */
    private String hostOf(String url) {
        if (url == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^[a-zA-Z][a-zA-Z0-9+.\\-]*://([^/?#]+)").matcher(url.trim());
        if (!m.find()) return null; // no scheme → relative/in-scope
        String authority = m.group(1);
        int at = authority.indexOf('@');
        if (at >= 0) authority = authority.substring(at + 1);
        int colon = authority.indexOf(':');
        if (colon >= 0) authority = authority.substring(0, colon);
        return authority;
    }
}
