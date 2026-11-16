package burp.scan.modules;

import burp.Finding;
import burp.IParameter;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A07 Identification & Authentication Failures - missing brute-force protection.
 * INTRUSIVE (off by default). Sends a small, capped set of wrong-password
 * attempts against a detected login form and flags if NONE are rate-limited /
 * locked out (no HTTP 429, no lockout message).
 *
 * @author Zahid Eroglu
 */
public class BruteForceModule implements ScanModule {

    private static final int MAX_ATTEMPTS = 8;
    private static final Set<String> PW_NAMES = new HashSet<>(Arrays.asList(
            "pass", "password", "passwd", "pwd", "pass1", "user_password"));
    private static final String[] COMMON = {
            "Sifre123.", "Parola123.", "password", "Password1", "123456", "admin", "Admin123."};

    public String id() { return "bruteforce"; }
    public String displayName() { return "Login Brute Force (intrusive)"; }
    public boolean isEnabled(Settings s) { return s.isBruteForceEnabled(); }

    public boolean appliesTo(Baseline b) {
        return "POST".equalsIgnoreCase(b.method) && passwordParam(b) != null;
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        IParameter pw = passwordParam(b);
        if (pw == null) return probes;
        List<String> guesses = buildGuesses(b.host);
        int n = Math.min(MAX_ATTEMPTS, guesses.size());
        for (int i = 0; i < n; i++) {
            probes.add(new Probe(id(), "Login attempt " + (i + 1) + " (" + pw.getName() + ")",
                    "param", pw.getName(), guesses.get(i), "Brute Force", "High"));
        }
        return probes;
    }

    /** Common + pattern-derived guesses (company/host name + predictable suffixes). */
    private List<String> buildGuesses(String host) {
        List<String> g = new ArrayList<>();
        String base = host == null ? "" : host.split("\\.")[0].replaceAll("[^A-Za-z0-9]", "");
        if (!base.isEmpty()) {
            g.add(base + "1234.");
            g.add(base + "123.");
            g.add(base + "2024!");
            g.add(capitalize(base) + "123.");
        }
        for (String c : COMMON) g.add(c);
        return g;
    }

    private String capitalize(String s) {
        return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        int attempts = 0, blocked = 0;
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Brute Force".equals(r.probe.attackType)) continue;
            attempts++;
            String body = r.bodySnippet == null ? "" : r.bodySnippet.toLowerCase();
            String hdrs = r.responseHeaders == null ? "" : r.responseHeaders.toLowerCase();
            // Weak/guessable password: a guess produced an authenticated response.
            if (isLoginSuccess(r.statusCode, body, hdrs)) {
                Finding f = new Finding("Weak / Guessable Password", "High", 0.9,
                        I18n.t("f.bf.weakpw.desc", r.probe.payload),
                        "", I18n.t("f.bf.weakpw.ev", r.probe.payload, r.statusCode),
                        I18n.t("f.bf.weakpw.exp"),
                        I18n.t("f.bf.weakpw.rem"));
                f.setHttpResponse(r.bodySnippet);
                f.setCvssScore(8.1);
                findings.add(f);
                return findings; // success is the headline finding
            }
            if (r.statusCode == 429 || body.contains("locked") || body.contains("too many")
                    || body.contains("rate limit") || body.contains("try again later")) {
                blocked++;
            }
        }
        if (attempts >= MAX_ATTEMPTS && blocked == 0) {
            // Weak signal: a handful of attempts with no lockout is suggestive, not proof — many sites
            // only lock out after 10+ tries or rely on a CAPTCHA that this probe does not exercise. Report
            // Low / inconclusive so it does not inflate the report as a confirmed High/Medium.
            Finding f = new Finding("Missing Brute-Force Protection", "Low", 0.4,
                    I18n.t("f.bf.noprotect.desc", attempts),
                    "", I18n.t("f.bf.noprotect.ev", attempts),
                    I18n.t("f.bf.noprotect.exp"),
                    I18n.t("f.bf.noprotect.rem"));
            f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            findings.add(f);
        }
        return findings;
    }

    /** Heuristic: did a guess yield an authenticated response (not merely a session cookie)? */
    private boolean isLoginSuccess(int sc, String bodyLower, String hdrsLower) {
        boolean strongBody = bodyLower.contains("usergroups") || bodyLower.contains("allowedsections")
                || bodyLower.contains("\"access_token\"") || bodyLower.contains("\"token\"")
                || bodyLower.contains("\"success\":true") || bodyLower.contains("\"isauthenticated\":true");
        boolean authCookie = hdrsLower.contains("set-cookie:")
                && (hdrsLower.contains("auth") || hdrsLower.contains(".aspxauth") || hdrsLower.contains("jwt"));
        if ((sc == 200 || sc == 302) && strongBody) return true;
        return sc == 302 && authCookie; // redirect-after-login carrying an auth cookie
    }

    private IParameter passwordParam(Baseline b) {
        for (IParameter p : b.parameters) {
            byte t = p.getType();
            if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) continue;
            if (PW_NAMES.contains(p.getName().toLowerCase())) return p;
        }
        return null;
    }
}
