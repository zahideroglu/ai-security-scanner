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

/**
 * A05 Security Misconfiguration: missing security headers, verbose banners
 * (passive from baseline), and a single active CORS reflection probe.
 *
 * @author Zahid Eroglu
 */
public class MisconfigModule implements ScanModule {

    private static final String EVIL_ORIGIN = "https://evil.example";

    public String id() { return "misconfig"; }
    public String displayName() { return "Security Misconfiguration"; }
    public boolean isEnabled(Settings s) { return s.isModuleMisconfigEnabled(); }
    public boolean appliesTo(Baseline b) { return b.statusCode > 0; }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        probes.add(new Probe(id(), "CORS reflection (Origin: evil)", "header",
                "Origin", EVIL_ORIGIN, "CORS Misconfiguration", "High"));
        return probes;
    }

    // Cookie names that carry a session/identity (worth flagging for missing Secure/HttpOnly).
    // Infra/analytics cookies (NetScaler NSC_*, F5 TS*, _ga, AWSALB, ...) are not security-sensitive
    // and flagging their flags is pure noise.
    private static final java.util.regex.Pattern AUTH_COOKIE = java.util.regex.Pattern.compile(
            "(sess|sid|auth|jwt|token|login|ident|\\.aspxauth|saml|oauth|account|user|member|"
            + "phpsessid|jsessionid|asp\\.net|csrf|xsrf)", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern INFRA_COOKIE = java.util.regex.Pattern.compile(
            "^(nsc_|bigip|f5|ts[0-9a-f]{6,}|incap_|visid_|__cf|cf_|_ga|_gid|_gat|_gcl|awsalb|aka_|ak_bms|bm_|"
            + "route|server_?id|lb_|persist|x-ms-|datadome|__utm)", java.util.regex.Pattern.CASE_INSENSITIVE);

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();

        // A WAF/block page is not the real application response; passive header/cookie/banner checks on
        // it are misleading. Skip them (the active CORS probe below is still evaluated).
        boolean blockPage = Signals.looksLikeBlockPage(b.bodySnippet);

        // --- Passive checks on the baseline response ---
        List<String> missing = blockPage ? new ArrayList<String>() : Signals.missingSecurityHeaders(b.responseHeaders);
        if (!missing.isEmpty()) {
            boolean isApi = (b.path != null && b.path.toLowerCase().contains("/api/")) || !b.responseIsHtml;
            String missingList = String.join(", ", missing);
            findings.add(new Finding(
                    "Security Misconfiguration", "Low", 0.9,
                    isApi ? I18n.t("f.misc.headers.desc.api", b.path, missingList)
                          : I18n.t("f.misc.headers.desc.html", missingList),
                    "", I18n.t("f.misc.headers.ev", missingList, isApi ? "API" : "HTML"),
                    I18n.t("f.misc.headers.exp"),
                    I18n.t("f.misc.headers.rem")));
        }
        // Insecure cookie flags — only on SESSION/AUTH cookies (not LB/analytics infra cookies).
        for (String h : blockPage ? java.util.Collections.<String>emptyList() : b.responseHeaders) {
            if (h.toLowerCase().startsWith("set-cookie:")) {
                String low = h.toLowerCase();
                String cookieName = h.length() > 12 ? h.substring(12).split("=", 2)[0].trim() : "?";
                // Skip infra/analytics cookies and anything that doesn't look like a session/identity token.
                if (INFRA_COOKIE.matcher(cookieName).find() || !AUTH_COOKIE.matcher(cookieName).find()) continue;
                boolean secure = low.contains("secure");
                boolean httpOnly = low.contains("httponly");
                if (!secure || !httpOnly) {
                    java.util.List<String> miss = new java.util.ArrayList<>();
                    if (!secure) miss.add("Secure");
                    if (!httpOnly) miss.add("HttpOnly");
                    findings.add(new Finding(
                            "Security Misconfiguration", "Low", 0.85,
                            I18n.t("f.misc.cookie.desc", cookieName, String.join("/", miss)),
                            "", h.length() > 120 ? h.substring(0, 120) + "…" : h,
                            I18n.t("f.misc.cookie.exp"),
                            I18n.t("f.misc.cookie.rem")));
                    break; // one finding is enough
                }
            }
        }

        String server = Signals.serverBanner(b.responseHeaders);
        String poweredBy = Signals.poweredBy(b.responseHeaders);
        if (server != null || poweredBy != null) {
            String ev = (server != null ? "Server: " + server : "")
                    + (poweredBy != null ? (server != null ? " | " : "") + "X-Powered-By: " + poweredBy : "");
            findings.add(new Finding(
                    "Information Disclosure", "Low", 0.85,
                    I18n.t("f.misc.banner.desc"),
                    "", ev, I18n.t("f.misc.banner.exp"),
                    I18n.t("f.misc.banner.rem")));
        }

        // --- Active CORS probe ---
        for (ProbeResult r : results) {
            if (r.probe == null || !"CORS Misconfiguration".equals(r.probe.attackType) || !r.ok()) {
                continue;
            }
            String hdrs = r.responseHeaders == null ? "" : r.responseHeaders.toLowerCase();
            boolean reflectsOrigin = hdrs.contains("access-control-allow-origin: " + EVIL_ORIGIN.toLowerCase())
                    || hdrs.contains("access-control-allow-origin:" + EVIL_ORIGIN.toLowerCase());
            boolean allowsCreds = hdrs.contains("access-control-allow-credentials: true");
            if (reflectsOrigin) {
                Finding f = new Finding(
                        "CORS Misconfiguration", allowsCreds ? "High" : "Medium",
                        allowsCreds ? 0.9 : 0.7,
                        allowsCreds ? I18n.t("f.misc.cors.desc.creds") : I18n.t("f.misc.cors.desc.plain"),
                        "", I18n.t("f.misc.cors.ev", EVIL_ORIGIN) + (allowsCreds ? " + ACAC:true" : ""),
                        I18n.t("f.misc.cors.exp"),
                        I18n.t("f.misc.cors.rem"));
                f.setHttpResponse(r.bodySnippet);
                findings.add(f);
            }
        }
        return findings;
    }
}
