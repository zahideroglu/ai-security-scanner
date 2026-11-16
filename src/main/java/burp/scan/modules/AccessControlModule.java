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
import java.util.Base64;
import java.util.List;

/**
 * A01 Broken Access Control - authentication bypass. Re-sends an authenticated
 * request WITHOUT credentials (drop Authorization / Cookie) and with a forged
 * JWT (alg=none); flags when the protected resource is still served (HTTP 200).
 *
 * @author Zahid Eroglu
 */
public class AccessControlModule implements ScanModule {

    // Static assets / public endpoints: dropping auth on them and still getting 200 is EXPECTED,
    // not a vulnerability. This was the #1 source of false-positive "Broken Access Control".
    private static final java.util.regex.Pattern STATIC_PATH = java.util.regex.Pattern.compile(
            "\\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|html?|vsf|bmp|tiff?|pdf)($|\\?)"
            + "|/(images|img|fonts|css|js|lib|assets|scripts|app_plugins|media|medium|banner|content)/",
            java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern BENIGN_PATH = java.util.regex.Pattern.compile(
            "(logout|log-?off|sign-?out|localizedtext|/404|/403|/error|favicon)", java.util.regex.Pattern.CASE_INSENSITIVE);

    private static boolean skipPath(String p) {
        return p != null && (STATIC_PATH.matcher(p).find() || BENIGN_PATH.matcher(p).find());
    }

    public String id() { return "access"; }
    public String displayName() { return "Broken Access Control / Auth"; }
    public boolean isEnabled(Settings s) { return s.isModuleAccessControlEnabled(); }

    public boolean appliesTo(Baseline b) {
        if (skipPath(b.path)) return false; // never test static assets / public endpoints
        return b.statusCode == 200
                && (b.requestHeader("Authorization") != null || b.requestHeader("Cookie") != null);
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        String auth = b.requestHeader("Authorization");
        if (auth != null) {
            probes.add(new Probe(id(), "Auth bypass: drop Authorization", "header",
                    "Authorization", "", "Broken Access Control", "Critical"));
            String forged = forgeNoneJwt(auth);
            if (forged != null) {
                probes.add(new Probe(id(), "JWT alg=none forge", "jwt",
                        "Authorization", forged, "JWT", "High"));
            }
        }
        // Only meaningful if the request actually carries a SESSION/AUTH cookie. Dropping a pure
        // load-balancer / CDN / analytics cookie jar (NetScaler NSC_*, F5 TS*, _ga, AWSALB, ...) and
        // still getting 200 proves nothing — those cookies never gated authorization. This was a
        // major false-positive source ("drop Cookie -> 200" on NSC_WT persistence cookies).
        if (hasAuthCookie(b.requestHeader("Cookie"))) {
            probes.add(new Probe(id(), "Auth bypass: drop Cookie", "header",
                    "Cookie", "", "Broken Access Control", "High"));
        }
        return probes;
    }

    // Cookie names that plausibly carry a session/identity (worth testing); and infra/analytics
    // cookies that never carry authorization (skip — dropping them is not an access-control test).
    private static final java.util.regex.Pattern AUTH_COOKIE = java.util.regex.Pattern.compile(
            "(sess|sid|auth|jwt|token|login|ident|\\.aspxauth|saml|oauth|account|user|member|csrf|xsrf|"
            + "phpsessid|jsessionid|asp\\.net)", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern INFRA_COOKIE = java.util.regex.Pattern.compile(
            "^(nsc_|bigip|f5|ts[0-9a-f]{6,}|incap_|visid_|__cf|cf_|_ga|_gid|_gat|_gcl|awsalb|aka_|ak_bms|bm_|"
            + "route|server_?id|lb_|persist|x-ms-|datadome|__utm)", java.util.regex.Pattern.CASE_INSENSITIVE);

    /** True if the Cookie header contains at least one cookie that looks like a real session/auth token. */
    private boolean hasAuthCookie(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return false;
        for (String c : cookieHeader.split(";")) {
            String name = c.trim();
            int eq = name.indexOf('=');
            if (eq > 0) name = name.substring(0, eq).trim();
            if (name.isEmpty()) continue;
            if (INFRA_COOKIE.matcher(name).find()) continue;      // LB/CDN/analytics → not auth
            if (AUTH_COOKIE.matcher(name).find()) return true;    // looks like session/identity
        }
        return false;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok()) continue;
            if (r.statusCode == 200
                    && Signals.lengthDeltaRatio(b.responseLength, r.responseLength) < 0.30) {
                // If dropping auth yields a login page, authorization IS enforced -> not a bypass.
                if (looksLikeLogin(r.bodySnippet)) continue;
                // Byte-identical to the authenticated baseline => the dropped credential changed
                // NOTHING, so it was never gating this resource (it is public, or the cookie was an
                // LB/analytics token). Not an access-control bypass — drop it. Kills the NSC_WT /
                // static-banner false positives where baseline==tamper to the byte (e.g. 87704b=87704b).
                if (r.responseLength == b.responseLength && sameBody(r.bodySnippet, b.bodySnippet)) continue;
                if (Signals.looksLikeBlockPage(r.bodySnippet)) continue;
                boolean jwt = "JWT".equals(r.probe.attackType);
                Finding f = new Finding(
                        jwt ? "JWT" : "Broken Access Control",
                        "High", // not Critical without proof; AI consensus + effective-severity set the ceiling
                        0.6,
                        I18n.t("f.access.bypass.desc", r.probe.description),
                        "", I18n.t("f.access.bypass.ev", r.probe.description, r.statusCode,
                                r.responseLength, b.responseLength),
                        I18n.t("f.access.bypass.exp"),
                        I18n.t("f.access.bypass.rem"));
                f.setHttpResponse(r.bodySnippet);
                f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE); // needs AI / effective-severity gating
                findings.add(f);
            }
        }
        return findings;
    }

    /** Body-equality check tolerant of the 8 KB snippet cap (compares what we have). */
    private boolean sameBody(String a, String b) {
        if (a == null || b == null) return a == b;
        return a.equals(b);
    }

    private boolean looksLikeLogin(String body) {
        if (body == null) return false;
        String b = body.toLowerCase();
        return b.contains("type=\"password\"") || b.contains("name=\"password\"")
                || b.contains(">sign in") || b.contains(">log in")
                || b.contains("oturum aç") || b.contains("giriş yap")
                || (b.contains("login") && b.contains("password"));
    }

    /** Build an alg=none JWT from an existing Bearer token (header swapped, sig blank). */
    private String forgeNoneJwt(String authHeader) {
        try {
            String tok = authHeader.trim();
            if (tok.toLowerCase().startsWith("bearer ")) tok = tok.substring(7).trim();
            String[] parts = tok.split("\\.");
            if (parts.length < 2) return null;
            String newHeader = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes("UTF-8"));
            return newHeader + "." + parts[1] + ".";
        } catch (Exception e) {
            return null;
        }
    }
}
