package burp.report;

import burp.Finding;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serialises findings to SARIF 2.1.0 (Static Analysis Results Interchange Format) so they flow into
 * GitHub code scanning, DefectDojo, Azure DevOps, or any SARIF consumer. Deterministic, offline.
 *
 * <p>Each finding becomes a {@code result}; its OWASP API Top-10 category (or type) becomes the
 * {@code ruleId}, with the full standards tags (CVSS vector + score, CWE, WSTG, confidence) in the
 * result property bag so downstream tools can route and prioritise.
 *
 * @author Zahid Eroglu
 */
public final class SarifWriter {

    private SarifWriter() {}

    private static final String SCHEMA =
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    public static String write(List<Finding> findings) {
        JSONObject driver = new JSONObject();
        driver.put("name", "AppSecHunter");
        driver.put("informationUri", "https://github.com/zahideroglu/ai-security-scanner");
        driver.put("version", "2.0");

        // Collect unique rules keyed by ruleId, preserving first-seen order.
        Map<String, JSONObject> rules = new LinkedHashMap<>();
        JSONArray results = new JSONArray();

        if (findings != null) {
            for (Finding f : findings) {
                if (f == null || f.isFalsePositive()) continue;
                String ruleId = ruleId(f);
                rules.computeIfAbsent(ruleId, id -> rule(id, f));
                results.put(result(ruleId, f));
            }
        }

        JSONArray ruleArray = new JSONArray();
        for (JSONObject r : rules.values()) ruleArray.put(r);
        driver.put("rules", ruleArray);

        JSONObject tool = new JSONObject().put("driver", driver);
        JSONObject run = new JSONObject().put("tool", tool).put("results", results);

        JSONObject sarif = new JSONObject();
        sarif.put("version", "2.1.0");
        sarif.put("$schema", SCHEMA);
        sarif.put("runs", new JSONArray().put(run));
        return sarif.toString(2);
    }

    private static String ruleId(Finding f) {
        String api = Standards.owaspApi(f);
        if (api != null && !api.isEmpty()) {
            int dash = api.indexOf(' ');
            return dash > 0 ? api.substring(0, dash) : api;   // e.g. "API1:2023"
        }
        String t = f.getType();
        return (t == null || t.isEmpty()) ? "finding" : t.replaceAll("\\s+", "-");
    }

    private static JSONObject rule(String ruleId, Finding f) {
        JSONObject rule = new JSONObject();
        rule.put("id", ruleId);
        String api = Standards.owaspApi(f);
        rule.put("name", (api == null || api.isEmpty()) ? f.getType() : api);
        rule.put("shortDescription", new JSONObject().put("text",
                (api == null || api.isEmpty()) ? f.getType() : api));
        List<String> refs = f.getReferences();
        if (refs != null && !refs.isEmpty()) rule.put("helpUri", refs.get(0));
        JSONObject props = new JSONObject();
        if (f.getCweId() != null && !f.getCweId().isEmpty()) {
            props.put("tags", new JSONArray().put("security").put(f.getCweId()));
        } else {
            props.put("tags", new JSONArray().put("security"));
        }
        rule.put("properties", props);
        return rule;
    }

    private static JSONObject result(String ruleId, Finding f) {
        JSONObject r = new JSONObject();
        r.put("ruleId", ruleId);
        r.put("level", level(f));
        r.put("message", new JSONObject().put("text", message(f)));

        String url = f.getAffectedUrl();
        if (url != null && !url.isEmpty()) {
            JSONObject artifact = new JSONObject().put("uri", url);
            JSONObject physical = new JSONObject().put("artifactLocation", artifact);
            JSONObject location = new JSONObject().put("physicalLocation", physical);
            r.put("locations", new JSONArray().put(location));
        }

        JSONObject props = new JSONObject();
        props.put("severity", f.getEffectiveSeverity());
        props.put("confidence", f.getConfidence());
        props.put("cvssScore", f.getEffectiveCvss());
        props.put("cvssVector", Standards.cvssVector(f));
        if (f.getCweId() != null && !f.getCweId().isEmpty()) props.put("cwe", f.getCweId());
        String wstg = Standards.wstg(f);
        if (!wstg.isEmpty()) props.put("wstg", wstg);
        if (f.getOwaspCategory() != null && !f.getOwaspCategory().isEmpty())
            props.put("owaspWeb", f.getOwaspCategory());
        String api = Standards.owaspApi(f);
        if (!api.isEmpty()) props.put("owaspApi", api);
        props.put("oracleVerdict", String.valueOf(f.getOracleVerdict()));
        r.put("properties", props);
        return r;
    }

    private static String message(Finding f) {
        StringBuilder sb = new StringBuilder();
        if (f.getType() != null) sb.append(f.getType());
        if (f.getDescription() != null && !f.getDescription().isEmpty()) sb.append(" — ").append(f.getDescription());
        if (f.getEvidence() != null && !f.getEvidence().isEmpty()) sb.append("\nEvidence: ").append(f.getEvidence());
        return sb.toString();
    }

    /** SARIF level from effective severity: error (crit/high), warning (medium), note (low/info). */
    private static String level(Finding f) {
        String s = f.getEffectiveSeverity();
        if (s == null) return "note";
        switch (s.trim().toLowerCase()) {
            case "critical":
            case "high":   return "error";
            case "medium": return "warning";
            default:       return "note";
        }
    }
}
