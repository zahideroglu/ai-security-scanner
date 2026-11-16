package burp.scan.modules;

import burp.Finding;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.RequestKit;
import burp.scan.ScanModule;

import java.util.ArrayList;
import java.util.List;

/**
 * A05 Security Misconfiguration (B06): HTTP method enumeration. Sends TRACE /
 * TRACK / OPTIONS and flags TRACE/TRACK answered with 200 (Cross-Site Tracing)
 * or OPTIONS advertising dangerous verbs. Host-level: runs only on the site root
 * to avoid per-endpoint noise.
 *
 * @author Zahid Eroglu
 */
public class HttpMethodModule implements ScanModule {

    public String id() { return "httpmethod"; }
    public String displayName() { return "HTTP Method Misconfiguration"; }
    public boolean isEnabled(Settings s) { return s.isModuleMisconfigEnabled(); }

    public boolean appliesTo(Baseline b) {
        return b.statusCode > 0 && b.helpers != null && (b.singleRequestScan || isRoot(b.path));
    }
    private boolean isRoot(String p) { return p == null || p.isEmpty() || p.equals("/"); }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> p = new ArrayList<>();
        String path = "/";
        // TRACK (the IIS alias of TRACE) was dropped: it returns the same disposition as TRACE on virtually
        // every server, so TRACE alone covers XST — one fewer host-level request. judge() still handles a
        // TRACK result if one ever arrives from elsewhere.
        for (String m : new String[]{"TRACE", "OPTIONS"}) {
            byte[] raw = RequestKit.reshape(b.helpers, b.requestHeaders, m, path, false);
            if (raw == null) continue;
            Probe pr = new Probe(id(), m + " " + path, "raw", m, "", "HTTP Method", "Low");
            pr.rawRequest = raw;
            p.add(pr);
        }
        return p;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> f = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"HTTP Method".equals(r.probe.attackType)) continue;
            String method = r.probe.targetParameter;
            if (("TRACE".equals(method) || "TRACK".equals(method)) && r.statusCode == 200) {
                // A 200 alone is NOT XST: SPA/catch-all servers return their index.html for ANY method.
                // Real XST means the response ECHOES the request (Content-Type: message/http, or the body
                // replays the request line). Require that reflection, else it's a benign catch-all.
                String ct = headerVal(r.responseHeaders, "content-type");
                if (!looksLikeXstEcho(method, ct, r.bodySnippet)) continue;
                f.add(new Finding("HTTP Method Misconfiguration", "Low", 0.85,
                        I18n.t("f.meth.xst.desc", method),
                        "", method + I18n.t("f.meth.xst.ev", (ct == null ? "?" : ct)),
                        I18n.t("f.meth.xst.exp", method),
                        I18n.t("f.meth.xst.rem")));
            } else if ("OPTIONS".equals(method)) {
                String allow = headerVal(r.responseHeaders, "allow");
                if (allow != null) {
                    String al = allow.toLowerCase();
                    if (al.contains("put") || al.contains("delete") || al.contains("trace") || al.contains("patch")) {
                        // The Allow header frequently LIES (advertises verbs the server actually 405/500s on).
                        // We do NOT send a mutating PUT/DELETE to confirm (unsafe), so this stays an
                        // UNCONFIRMED informational hint, not a Low we assert.
                        Finding f2 = new Finding("HTTP Method Misconfiguration", "Info", 0.3,
                                I18n.t("f.meth.options.desc", allow),
                                "", "Allow: " + allow + I18n.t("f.meth.options.ev"),
                                I18n.t("f.meth.options.exp"),
                                I18n.t("f.meth.options.rem"));
                        f2.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
                        f.add(f2);
                    }
                }
            }
        }
        return f;
    }

    /**
     * True only when a TRACE/TRACK 200 response is a genuine request ECHO (XST), not a
     * catch-all index page. Strong signal: Content-Type: message/http. Fallback: the body
     * replays the request line ("TRACE / HTTP/…") and is not an HTML document.
     */
    private boolean looksLikeXstEcho(String method, String contentType, String body) {
        if (contentType != null && contentType.toLowerCase().contains("message/http")) return true;
        if (body == null || body.isEmpty()) return false;
        String head = body.length() > 400 ? body.substring(0, 400) : body;
        String low = head.toLowerCase();
        if (low.contains("<html") || low.contains("<!doctype")) return false; // SPA/page, not an echo
        return head.contains(method + " ") && low.contains("http/");          // request line echoed back
    }

    private String headerVal(String joined, String name) {
        if (joined == null) return null;
        for (String line : joined.split("\n")) {
            if (line.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                int c = line.indexOf(':');
                return c >= 0 ? line.substring(c + 1).trim() : "";
            }
        }
        return null;
    }
}
