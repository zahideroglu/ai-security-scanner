package burp;

import burp.i18n.I18n;
import org.json.*;
import java.util.*;
import java.util.regex.*;

/**
 * Response Analyzer - Parses and validates Qwen AI responses
 * 
 * @author Zahid Eroglu
 */
public class ResponseAnalyzer {
    
    private double minConfidence;
    
    public ResponseAnalyzer(double minConfidence) {
        this.minConfidence = minConfidence;
    }
    
    /**
     * Parse API response and extract findings
     */
    public ScanResult parseResponse(JSONObject apiResponse, String rawRequest, String rawResponse) {
        try {
            // Extract content from API response
            String content = apiResponse
                .getJSONArray("choices")
                .getJSONObject(0)
                .getJSONObject("message")
                .getString("content");
            
            // Try to parse as JSON
            JSONObject parsed = extractJSON(content);
            
            if (parsed != null) {
                List<Finding> findings = parseFindings(parsed);
                String summary = parsed.optString("summary", "");
                
                return new ScanResult(findings, summary, content);
            } else {
                // Fallback parsing
                return fallbackParse(content);
            }
            
        } catch (Exception e) {
            return new ScanResult(
                new ArrayList<>(),
                "Parse error: " + e.getMessage(),
                apiResponse.toString()
            );
        }
    }
    
    /**
     * Extract JSON from text (handles markdown code blocks)
     */
    private JSONObject extractJSON(String text) {
        try {
            // Remove markdown code blocks
            text = text.replaceAll("```json\\s*", "");
            text = text.replaceAll("```\\s*", "");
            
            // Find JSON object
            Pattern pattern = Pattern.compile("\\{.*\\}", Pattern.DOTALL);
            Matcher matcher = pattern.matcher(text);
            
            if (matcher.find()) {
                return new JSONObject(matcher.group());
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Parse findings from JSON
     */
    private List<Finding> parseFindings(JSONObject parsed) {
        List<Finding> findings = new ArrayList<>();

        if (!parsed.has("vulnerabilities")) {
            return findings;
        }

        JSONArray vulns = parsed.getJSONArray("vulnerabilities");

        for (int i = 0; i < vulns.length(); i++) {
            try {
                JSONObject vuln = vulns.getJSONObject(i);

                // Required fields
                if (!vuln.has("type") || !vuln.has("severity") || !vuln.has("confidence")) {
                    continue;
                }

                double confidence = vuln.getDouble("confidence");

                // Filter by confidence - also apply minimum threshold of 0.70
                if (confidence < minConfidence || confidence < 0.70) {
                    continue;
                }

                // Normalize and categorize vulnerability type (delegates to Finding.normalizeType)
                String vulnType = Finding.normalizeType(vuln.getString("type"),
                    vuln.optString("description", ""),
                    vuln.optString("evidence", ""));

                Finding finding = new Finding(
                    vulnType,
                    normalizeSeverity(vuln.getString("severity")),
                    confidence,
                    vuln.optString("description", ""),
                    vuln.optString("evidence", ""),
                    vuln.optString("exploitation", ""),
                    vuln.optString("remediation", "")
                );

                // Faz 1: carry the model's verification steps (methodology.py next_verification_steps).
                JSONArray steps = vuln.optJSONArray("next_verification_steps");
                if (steps != null) {
                    for (int j = 0; j < steps.length(); j++) finding.addVerificationStep(steps.optString(j, ""));
                }

                findings.add(finding);

            } catch (Exception e) {
                // Skip invalid finding
            }
        }

        return findings;
    }

    /**
     * Fallback parsing when JSON extraction fails
     * Only create findings for high-confidence items
     */
    private ScanResult fallbackParse(String content) {
        List<Finding> findings = new ArrayList<>();
        String lowerContent = content.toLowerCase();

        // Only look for definitive patterns - no speculation

        // Check for version disclosure patterns
        Pattern serverPattern = Pattern.compile("server:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher serverMatcher = serverPattern.matcher(content);
        if (serverMatcher.find()) {
            String serverHeader = serverMatcher.group(1).trim();
            if (serverHeader.matches(".*\\d+\\.\\d+.*")) {  // Has version number
                findings.add(new Finding(
                    "Server Version Disclosure",
                    "Low",
                    0.90,
                    I18n.t("f.ra.serverver.desc", serverHeader),
                    I18n.t("f.ra.serverver.ev", serverHeader),
                    I18n.t("f.ra.serverver.exp"),
                    I18n.t("f.ra.serverver.rem")
                ));
            }
        }

        // Check for X-Powered-By
        Pattern poweredByPattern = Pattern.compile("x-powered-by:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
        Matcher poweredByMatcher = poweredByPattern.matcher(content);
        if (poweredByMatcher.find()) {
            String poweredBy = poweredByMatcher.group(1).trim();
            findings.add(new Finding(
                "Technology Stack Disclosure",
                "Low",
                0.90,
                I18n.t("f.ra.techstack.desc", poweredBy),
                I18n.t("f.ra.techstack.ev", poweredBy),
                I18n.t("f.ra.techstack.exp"),
                I18n.t("f.ra.techstack.rem")
            ));
        }

        // Only check for ACTUAL error messages, not just keywords
        if (lowerContent.contains("mysql") && (lowerContent.contains("error in your sql syntax") ||
            lowerContent.contains("mysql_fetch") || lowerContent.contains("mysqli"))) {
            findings.add(new Finding(
                "SQL Error Message Exposure",
                "High",
                0.85,
                I18n.t("f.ra.sqlerr.desc"),
                I18n.t("f.ra.sqlerr.ev"),
                I18n.t("f.ra.sqlerr.exp"),
                I18n.t("f.ra.sqlerr.rem")
            ));
        }

        // If no concrete findings, return empty list with summary
        String summary = findings.isEmpty()
            ? "AI response could not be parsed as JSON. No high-confidence vulnerabilities detected in text analysis."
            : "Parsed findings from text analysis (JSON parsing failed)";

        return new ScanResult(findings, summary, content);
    }
    
    /**
     * Normalize severity strings
     */
    private String normalizeSeverity(String severity) {
        String lower = severity.toLowerCase();
        
        if (lower.contains("critical")) return "Critical";
        if (lower.contains("high")) return "High";
        if (lower.contains("medium")) return "Medium";
        if (lower.contains("low")) return "Low";
        if (lower.contains("info")) return "Info";
        
        return "Medium";
    }
    
    /**
     * Validate finding against enabled types
     */
    public boolean isTypeEnabled(Finding finding, Map<String, Boolean> enabledTypes) {
        String type = finding.getType().toLowerCase();
        
        for (Map.Entry<String, Boolean> entry : enabledTypes.entrySet()) {
            if (!entry.getValue()) continue;
            
            String enabledType = entry.getKey().toLowerCase();
            if (type.contains(enabledType) || enabledType.contains(type)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Getters and setters
    public double getMinConfidence() {
        return minConfidence;
    }
    
    public void setMinConfidence(double minConfidence) {
        this.minConfidence = minConfidence;
    }
}
