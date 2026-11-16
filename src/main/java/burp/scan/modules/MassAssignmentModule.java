package burp.scan.modules;

import burp.Finding;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A03/A08 - Mass Assignment / BOPLA (Broken Object Property Level Authorization).
 * INTRUSIVE (off by default). On state-changing requests with a JSON / form body it
 * injects privileged or ownership properties the client should not control
 * (isAdmin, role, ownerId, balance, price, status...) and flags those the server
 * accepts (and especially reflects). AI confirms whether the property took effect.
 *
 * @author Zahid Eroglu
 */
public class MassAssignmentModule implements ScanModule {

    /** Privileged / ownership / financial properties a client must not be able to set. */
    private static final String[][] PROPS = {
            {"isAdmin", "true"}, {"admin", "true"}, {"is_admin", "true"}, {"role", "admin"},
            {"roles", "admin"}, {"isVerified", "true"}, {"verified", "true"}, {"emailVerified", "true"},
            {"approved", "true"}, {"isActive", "true"}, {"status", "active"}, {"permissions", "admin"},
            {"owner", "1"}, {"ownerId", "1"}, {"userId", "1"}, {"user_id", "1"}, {"accountId", "1"},
            {"price", "0"}, {"amount", "0"}, {"balance", "999999"}, {"credit", "999999"}, {"discount", "100"}
    };

    public String id() { return "massassign"; }
    public String displayName() { return "Mass Assignment / BOPLA (intrusive)"; }
    public boolean isEnabled(Settings s) { return s.isModuleMassAssignmentEnabled(); }

    public boolean appliesTo(Baseline b) {
        if (!isMutating(b.method)) return false;
        String ct = b.requestContentType == null ? "" : b.requestContentType.toLowerCase();
        return b.requestBody != null && !b.requestBody.trim().isEmpty()
                && (ct.contains("json") || ct.contains("urlencoded") || ct.contains("form"));
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        boolean json = b.requestContentType != null && b.requestContentType.toLowerCase().contains("json");
        String bodyLow = b.requestBody.toLowerCase();
        for (String[] kv : PROPS) {
            String key = kv[0];
            // Only INJECT properties the request does not already carry.
            if (bodyLow.contains("\"" + key.toLowerCase() + "\"") || bodyLow.matches("(?s).*\\b" + Pattern.quote(key.toLowerCase()) + "=.*")) {
                continue;
            }
            String newBody = inject(b.requestBody.trim(), key, kv[1], json);
            if (newBody == null) continue;
            Probe pr = new Probe(id(), "Mass-assign " + key + "=" + kv[1], "body", key, newBody, "Mass Assignment", "High");
            pr.tag = kv[1]; // the injected VALUE (payload holds the whole modified body, not the value)
            probes.add(pr);
        }
        return probes;
    }

    private String inject(String body, String key, String val, boolean json) {
        if (json) {
            if (!body.startsWith("{")) return null;
            boolean scalar = val.matches("\\d+") || val.equals("true") || val.equals("false");
            String v = scalar ? val : "\"" + val + "\"";
            String rest = body.substring(1);
            boolean empty = rest.trim().startsWith("}");
            return "{\"" + key + "\":" + v + (empty ? "" : ",") + rest;
        }
        return body + (body.isEmpty() ? "" : "&") + key + "=" + val;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Mass Assignment".equals(r.probe.attackType)) continue;
            String body = r.bodySnippet == null ? "" : r.bodySnippet;
            // FP guards: a WAF/block page or a binary blob is not evidence the field was bound.
            if (Signals.looksLikeBlockPage(body)) continue;
            if (Signals.isBinaryOrImageType(Signals.contentTypeOf(r.responseHeaders))) continue;
            if (r.statusCode < 200 || r.statusCode >= 300) continue; // server accepted the request
            String key = r.probe.targetParameter;
            String value = r.probe.tag == null ? "" : String.valueOf(r.probe.tag); // the injected VALUE
            // Require POSITIVE evidence the injected property was HONORED: the key:value pair appears in
            // the returned entity AND was NOT already there in the baseline. A bare 2xx (the server simply
            // ignored the extra field) is NOT a finding — that was the #1 mass-assignment false positive.
            boolean honored = bodyHasKeyValue(body, key, value)
                    && !bodyHasKeyValue(b.bodySnippet, key, value);
            if (!honored) continue;
            // Echo guard: a create/validation/debug endpoint that simply REFLECTS the submitted object back
            // satisfies "key:value present" without binding anything. If the whole injected body is echoed
            // verbatim, this is an echo, not a bind → leave it to the AI (lower confidence) rather than assert.
            boolean echo = r.probe.payload != null && r.probe.payload.length() > 8 && body.contains(r.probe.payload);
            String desc = echo
                    ? I18n.t("f.mass.bopla.desc.echo", key, value)
                    : I18n.t("f.mass.bopla.desc.bound", key, value);
            String ev = echo
                    ? I18n.t("f.mass.bopla.ev.echo", key, value, r.statusCode)
                    : I18n.t("f.mass.bopla.ev", key, value, r.statusCode);
            Finding f = new Finding("Mass Assignment (BOPLA)", echo ? "Medium" : "High", echo ? 0.45 : 0.7,
                    desc,
                    "", ev,
                    I18n.t("f.mass.bopla.exp"),
                    I18n.t("f.mass.bopla.rem"));
            f.setHttpResponse(body);
            if (echo) f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            findings.add(f);
        }
        return findings;
    }

    /** True if the body contains the injected key paired with the injected value (JSON or form). */
    private boolean bodyHasKeyValue(String body, String key, String val) {
        if (body == null || key == null || val == null || val.isEmpty()) return false;
        String k = Pattern.quote(key);
        String v = Pattern.quote(val);
        // "key": value  |  "key":"value"  |  key=value
        Pattern p = Pattern.compile("(\"" + k + "\"\\s*:\\s*\"?" + v + "\"?|\\b" + k + "=" + v + "\\b)",
                Pattern.CASE_INSENSITIVE);
        return p.matcher(body).find();
    }

    private boolean isMutating(String m) {
        return "POST".equalsIgnoreCase(m) || "PUT".equalsIgnoreCase(m) || "PATCH".equalsIgnoreCase(m);
    }
}
