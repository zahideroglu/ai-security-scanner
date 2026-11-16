package burp.authz;

import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.i18n.I18n;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Deterministic access-control policy: classifies a response as GRANTED / DENIED,
 * ranks roles by trust, recognises privileged/protected paths, and turns a filled
 * {@link AuthMatrix} into a list of {@link AuthMatrix.Violation}s (no AI).
 *
 * @author Zahid Eroglu
 */
public class AccessOracle {

    private final IExtensionHelpers helpers;

    public AccessOracle(IExtensionHelpers helpers) { this.helpers = helpers; }

    private static final Pattern LOGIN = Pattern.compile(
            "(<umb-auth|type=[\"']password[\"']|name=[\"']password[\"']|\"loginurl\"|>\\s*sign in|>\\s*log in|"
            + "oturum aç|giriş yap|"
            // session-EXPIRED signals (a 200 body that says the session died — e.g. Gateway WCF). Without
            // these, a dead body-carried session reads as GRANTED and the scanner keeps testing on it.
            + "oturum(unuz)?\\s*(sonlan|sona\\s*er|zaman\\s*aşım|geçersiz|kapan)|lütfen\\s*(tekrar|yeniden)\\s*giriş|"
            + "session\\s*(has\\s*)?(expired|ended|timed?\\s*out|not\\s*found|is\\s*(no\\s*longer\\s*)?valid|invalid)|"
            + "sessionnotfound|please\\s*(re-?)?(login|log\\s*in|sign\\s*in)\\s*again)", Pattern.CASE_INSENSITIVE);

    private static final Pattern PRIV_PATH = Pattern.compile(
            "(/umbraco(?!/api/(pagination|form))|/admin|/administrator|/manage|/management|/internal|/backoffice|"
            + "/api/[^?]*(admin|manage|internal|delete|create|update))", Pattern.CASE_INSENSITIVE);

    private static final Pattern PROTECTED_PATH = Pattern.compile(
            "(/umbraco|/admin|/manage|/internal|/backoffice|/account|/profile|/settings|/dashboard|/api/)",
            Pattern.CASE_INSENSITIVE);

    // Endpoints that are PUBLIC/benign by design — reaching them is never an access-control violation.
    // (logout/signout are idempotent & public; 404/403/error pages and assets are not "protected resources".)
    // Also PRE-AUTH endpoints (login, captcha, token issuance, warmup, language switch, register/reset):
    // anonymous access to these is CORRECT behaviour, not a flaw — flagging them was a major FP source.
    // Anchored to SPECIFIC pre-auth endpoints — NOT broad substrings. Earlier bare terms like "public",
    // "version", "language", "locale" matched real object sub-resources (/users/12/public-profile,
    // /orders/9/version, /account/7/language-preferences) and silently dropped them from access testing.
    private static final Pattern BENIGN_PATH = Pattern.compile(
            "(logout|log-?off|sign-?out|signout|/404|/403|/401|/500|/error|/not-?found|favicon\\.ico|"
            + "login|captcha|get-?token|refresh-?token|get-?login|logincommunication|"
            + "warmup|warm-?up|keep-?alive|heartbeat|/ping|/health|"
            + "change-?language|set-?language|change-?culture|set-?culture|getculture|getlanguage|"
            + "register|sign-?up|signup|forgot-?password|reset-?password|resetpassword|/otp|verify-?email|"
            + "/public/|\\.well-known)",
            Pattern.CASE_INSENSITIVE);

    public boolean isBenignPath(String path) { return path != null && BENIGN_PATH.matcher(path).find(); }

    private static final int MAX_PER_TYPE = 25;

    /** Trust rank of a role by name: anonymous=0, basic user=1, editor/manager=2, admin=3. */
    public static int rank(String roleName) {
        if (roleName == null) return 1;
        String r = roleName.toLowerCase();
        if (r.contains("anon")) return 0;
        if (r.contains("admin") || r.contains("root") || r.contains("super") || r.contains("owner")) return 3;
        if (r.contains("editor") || r.contains("author") || r.contains("manager") || r.contains("staff")
                || r.contains("operator") || r.contains("moderator")) return 2;
        return 1; // user / guest / member / customer / basic / default
    }

    public boolean isPrivilegedPath(String path) { return path != null && PRIV_PATH.matcher(path).find(); }
    public boolean isProtectedPath(String path) { return path != null && PROTECTED_PATH.matcher(path).find(); }

    /** Classify a raw response. */
    public AuthMatrix.Verdict verdict(byte[] response) {
        if (response == null) return AuthMatrix.Verdict.ERROR;
        try {
            IResponseInfo ri = helpers.analyzeResponse(response);
            int sc = ri.getStatusCode();
            int off = ri.getBodyOffset();
            String body = new String(response, off, Math.max(0, response.length - off));
            return verdict(sc, body, ri.getHeaders());
        } catch (Exception e) {
            return AuthMatrix.Verdict.ERROR;
        }
    }

    public AuthMatrix.Verdict verdict(int sc, String body, List<String> headers) {
        if (sc == 401 || sc == 403) return AuthMatrix.Verdict.DENIED;
        if (sc >= 300 && sc < 400) return AuthMatrix.Verdict.DENIED;          // redirect (often to login)
        if (sc >= 200 && sc < 300) {
            // A 200 that is actually a login page is NOT granted access.
            if (body != null && body.length() < 40000 && LOGIN.matcher(body).find()) {
                return AuthMatrix.Verdict.DENIED;
            }
            return AuthMatrix.Verdict.GRANTED;
        }
        return AuthMatrix.Verdict.DENIED; // other 4xx/5xx
    }

    /** Turn the filled matrix into violations. */
    public List<AuthMatrix.Violation> detectViolations(AuthMatrix matrix) {
        List<AuthMatrix.Violation> out = new ArrayList<>();
        int maxRank = 0;
        boolean hasAuthedRole = false;
        for (String role : matrix.roles) {
            maxRank = Math.max(maxRank, rank(role));
            if (!"anonymous".equalsIgnoreCase(role)) hasAuthedRole = true;
        }
        int v1 = 0, v2 = 0, v3 = 0;

        for (AuthMatrix.Row row : matrix.rows) {
            // Skip public/benign endpoints (logout, 404/error, assets): reaching them is not a violation.
            // This kills deterministic false positives like "PostLogout -> 200 = Broken Access Control".
            if (isBenignPath(row.path)) continue;

            AuthMatrix.Cell anon = row.cell("anonymous");

            // V1: anonymous reaches a protected path. REQUIRES an authenticated baseline in the matrix:
            // with an anonymous-only run there is no proof the path is actually protected (it may be
            // public by design), so "anonymous got 200" proves nothing. Suppress entirely when no
            // authenticated role exists — this killed the bulk of the unauthenticated-BAC false positives.
            if (v1 < MAX_PER_TYPE && hasAuthedRole && anon != null && anon.verdict == AuthMatrix.Verdict.GRANTED
                    && isProtectedPath(row.path)) {
                out.add(make(row, "Broken Access Control (Unauthenticated)", "High", 0.85,
                        I18n.t("f.ao.v1.ev", anon.status),
                        I18n.t("f.ao.v1.desc", row.method, row.path),
                        I18n.t("f.ao.v1.rem")));
                v1++;
            }

            // Granted authenticated roles on this row.
            List<String> grantedAuthed = new ArrayList<>();
            for (String role : matrix.roles) {
                if ("anonymous".equals(role)) continue;
                AuthMatrix.Cell c = row.cell(role);
                if (c != null && c.verdict == AuthMatrix.Verdict.GRANTED) grantedAuthed.add(role);
            }

            // V2: a low-privilege role reaches a privileged path.
            if (isPrivilegedPath(row.path)) {
                for (String role : grantedAuthed) {
                    if (v2 >= MAX_PER_TYPE) break;
                    if (rank(role) < 3) {
                        AuthMatrix.Cell c = row.cell(role);
                        out.add(make(row, "Vertical Privilege Escalation", "High", 0.75,
                                I18n.t("f.ao.v2.ev", role, rank(role), c.status),
                                I18n.t("f.ao.v2.desc", row.method, row.path),
                                I18n.t("f.ao.v2.rem")));
                        v2++;
                    }
                }
            }

            // V3: object-bearing endpoint reachable by >= 2 distinct identities -> AI compares bodies.
            if (v3 < MAX_PER_TYPE && row.hasResourceId && grantedAuthed.size() >= 2) {
                String a = grantedAuthed.get(0), b = grantedAuthed.get(1);
                AuthMatrix.Cell ca = row.cell(a), cb = row.cell(b);
                if (ca != null && cb != null) {
                    AuthMatrix.Violation viol = make(row, "Horizontal Access (BOLA)", "Medium", 0.5,
                            I18n.t("f.ao.v3.ev", a, b),
                            I18n.t("f.ao.v3.desc", row.method, row.path),
                            I18n.t("f.ao.v3.rem"));
                    viol.baselineBody = ca.bodySnippet;
                    viol.manipulatedBody = cb.bodySnippet;
                    viol.controlBody = (anon != null ? anon.bodySnippet : null); // negative control: what an unauth caller sees
                    out.add(viol);
                    v3++;
                }
            }
        }
        return out;
    }

    private AuthMatrix.Violation make(AuthMatrix.Row row, String type, String sev, double conf,
                                      String evidence, String desc, String remediation) {
        AuthMatrix.Violation v = new AuthMatrix.Violation();
        v.type = type; v.severity = sev; v.confidence = conf;
        v.endpoint = row.method + " " + row.path; v.url = row.url;
        v.evidence = evidence; v.description = desc; v.remediation = remediation;
        v.base = row.base;
        return v;
    }
}
