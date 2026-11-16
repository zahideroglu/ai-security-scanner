package burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import burp.MultiSessionTester;
import burp.engine.DetectionStage;
import burp.engine.StageListener;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Executes {@link LoginProfile} recipes to mint FRESH sessions: performs the login request, extracts
 * the token (JSON dot-path or regex), and registers a {@link MultiSessionTester} session with the
 * token applied as the configured auth header. The durable fix for expired harvested tokens — the
 * authorization matrix / BOLA hunts can then run as real, currently-authenticated identities.
 *
 * @author Zahid Eroglu
 */
public class LoginManager {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    public LoginManager(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                        PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /** Result of a single login attempt — for the "Test Login" UI button. */
    public static class LoginResult {
        public final boolean ok;
        public final String detail;     // token preview on success, error on failure
        LoginResult(boolean ok, String detail) { this.ok = ok; this.detail = detail; }
    }

    /** A minted session: the token applied as header(s) and/or injected into request-body field(s). */
    public static class SessionAuth {
        public final Map<String, String> headers;     // headerName → value (may be empty)
        public final Map<String, String> bodyTokens;  // JSON body field → token value (may be empty)
        public final String token;                     // raw token, for previews
        SessionAuth(Map<String, String> headers, Map<String, String> bodyTokens, String token) {
            this.headers = headers; this.bodyTokens = bodyTokens; this.token = token;
        }
    }

    /** Log in for each profile and register a fresh session in {@code mtester}. Returns count added. */
    public int loginAll(List<LoginProfile> profiles, MultiSessionTester mtester, StageListener l) {
        int ok = 0;
        if (profiles == null) return 0;
        for (LoginProfile p : profiles) {
            if (p == null || !p.isValid()) continue;
            try {
                SessionAuth auth = loginSession(p);
                if (auth != null && (!auth.headers.isEmpty() || !auth.bodyTokens.isEmpty())) {
                    mtester.addSession(p.roleName, "login-profili (taze)", auth.headers, auth.bodyTokens);
                    ok++;
                    if (l != null) l.onStageProgress(DetectionStage.RECON,
                            "🔑 " + p.roleName + " login başarılı — taze oturum eklendi"
                                    + (auth.bodyTokens.isEmpty() ? "" : " (gövde: " + auth.bodyTokens.keySet() + ")"));
                } else if (l != null) {
                    l.onStageProgress(DetectionStage.RECON,
                            "✗ " + p.roleName + " login başarısız (token çıkarılamadı)");
                }
            } catch (Exception e) {
                if (l != null) l.onStageProgress(DetectionStage.RECON,
                        "✗ " + p.roleName + " login hata: " + e.getMessage());
                if (stderr != null) stderr.println("[LoginManager] " + p.roleName + ": " + e);
            }
        }
        return ok;
    }

    /** Perform one login and return the auth-header map ({headerName: value}), or null on failure. */
    public Map<String, String> login(LoginProfile p) throws Exception {
        SessionAuth s = loginSession(p);
        return s == null ? null : s.headers;
    }

    /**
     * Perform one login and return the full {@link SessionAuth}: the token applied as a header (unless
     * {@code authHeaderName} is blank) and/or injected into a request-body field ({@code tokenBodyField},
     * for body-carried sessions like Gateway's {@code sessionToken}). Null on failure.
     */
    public SessionAuth loginSession(LoginProfile p) throws Exception {
        if (p.isMultiStep()) return loginSessionMultiStep(p);

        HttpResult r = send(p);
        if (r.body == null) { log("✗ " + p.roleName + ": sunucudan yanıt yok (WAF/bağlantı?)"); return null; }

        String token = extractToken(r.body, p);
        if (token == null || token.isEmpty()) {
            log("✗ " + p.roleName + ": HTTP " + r.status + " — token yok/boş (yol='" + effPath(p)
                    + "', success=" + successFlag(r.body) + "). Tek-kullanımlık OTP/STS login olabilir.");
            return null;
        }
        log("🔑 " + p.roleName + ": HTTP " + r.status + " — token alındı (" + token.length() + "B)");
        return buildSessionAuth(p, token);
    }

    /** Apply {@code token} to header(s) and/or the body-carried session field per the profile config. */
    private SessionAuth buildSessionAuth(LoginProfile p, String token) {
        Map<String, String> headers = new HashMap<>();
        String headerName = p.authHeaderName == null ? "" : p.authHeaderName.trim();
        if (!headerName.isEmpty()) {
            String value = (p.authValueTemplate == null || p.authValueTemplate.isEmpty()
                    ? "Bearer {token}" : p.authValueTemplate).replace("{token}", token);
            headers.put(headerName, value);
        }

        Map<String, String> bodyTokens = new HashMap<>();
        if (p.tokenBodyField != null && !p.tokenBodyField.trim().isEmpty()) {
            bodyTokens.put(p.tokenBodyField.trim(), token);
        }
        // If neither a header nor a body field is configured, fall back to the default Authorization header.
        if (headers.isEmpty() && bodyTokens.isEmpty()) {
            headers.put("Authorization", "Bearer " + token);
        }
        return new SessionAuth(headers, bodyTokens, token);
    }

    /**
     * Run a multi-step login chain (e.g. Gateway multi-step: Login → VerifyOtp → Complete):
     * send each step in order, carry cookies across steps, capture named variables from each response
     * (JSON dot-path) so later steps can reference them via {@code {var}}, then apply the designated
     * {@code sessionTokenVar} as the session token. Null on any hard failure.
     */
    public SessionAuth loginSessionMultiStep(LoginProfile p) throws Exception {
        Map<String, String> vars = new HashMap<>();
        vars.put("user", p.username == null ? "" : p.username);
        vars.put("pass", p.password == null ? "" : p.password);

        CookieJar jar = new CookieJar();
        int i = 0;
        for (LoginStep st : p.steps) {
            i++;
            if (st == null || !st.isValid()) continue;
            String label = (st.name == null || st.name.trim().isEmpty()) ? ("adım " + i) : st.name;
            String body = substitute(st.bodyTemplate, vars);
            StepResult r = sendStep(st, body, jar);
            if (r.body == null) {
                log("✗ " + p.roleName + " / " + label + ": sunucudan yanıt yok (WAF/bağlantı?)");
                return null;
            }
            int got = 0;
            for (Map.Entry<String, String> e : st.captures.entrySet()) {
                String v = jsonPathValue(r.body, e.getValue());
                if (v != null && !v.isEmpty()) { vars.put(e.getKey(), v); got++; }
            }
            log("→ " + p.roleName + " / " + label + ": HTTP " + r.status + " success=" + successFlag(r.body)
                    + (got > 0 ? " (yakalanan: " + got + ")" : ""));
        }

        String tokenVar = p.sessionTokenVar == null ? "" : p.sessionTokenVar.trim();
        String token = tokenVar.isEmpty() ? null : vars.get(tokenVar);
        if (token == null || token.isEmpty()) {
            log("✗ " + p.roleName + ": çok-adımlı zincir bitti ama oturum değişkeni '" + tokenVar
                    + "' boş/yok. Yakalama JSON-yolunu, adım sırasını ve token değişken adını kontrol edin.");
            return null;
        }
        log("🔑 " + p.roleName + ": çok-adımlı login OK — oturum token '" + tokenVar + "' (" + token.length() + "B)");
        return buildSessionAuth(p, token);
    }

    /** Replace every {@code {key}} placeholder in {@code template} with vars[key] (literal, not regex). */
    private static String substitute(String template, Map<String, String> vars) {
        if (template == null || template.isEmpty()) return "";
        String out = template;
        for (Map.Entry<String, String> e : vars.entrySet()) {
            out = out.replace("{" + e.getKey() + "}", e.getValue() == null ? "" : e.getValue());
        }
        return out;
    }

    /** Scalar value at a JSON dot-path (e.g. {@code LoginResponse.token}); null if absent or non-scalar. */
    static String jsonPathValue(String body, String dotPath) {
        if (body == null || dotPath == null || dotPath.trim().isEmpty()) return null;
        try {
            Object cur = new JSONObject(body);
            for (String seg : dotPath.trim().split("\\.")) {
                if (!(cur instanceof JSONObject)) return null;
                cur = ((JSONObject) cur).opt(seg);
                if (cur == null) return null;
            }
            return (cur instanceof JSONObject || cur instanceof JSONArray) ? null : String.valueOf(cur);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Send the login request and return the raw response body (no token extraction). Used by the
     * settings wizard's "Test" button to auto-detect the {@code tokenJsonPath} when the user left it
     * blank. Returns null only if the server sent no response.
     */
    public String fetchResponseBody(LoginProfile p) throws Exception {
        return send(p).body;
    }

    /** Send the login request; returns HTTP status + body (body null only if the server sent nothing). */
    private HttpResult send(LoginProfile p) throws Exception {
        URL u = new URL(p.loginUrl);
        boolean https = "https".equalsIgnoreCase(u.getProtocol());
        int port = u.getPort() != -1 ? u.getPort() : (https ? 443 : 80);
        IHttpService svc = helpers.buildHttpService(u.getHost(), port, https);

        String path = u.getPath();
        if (path == null || path.isEmpty()) path = "/";
        if (u.getQuery() != null) path += "?" + u.getQuery();

        String body = (p.bodyTemplate == null ? "" : p.bodyTemplate)
                .replace("{user}", p.username == null ? "" : p.username)
                .replace("{pass}", p.password == null ? "" : p.password);

        List<String> headers = new ArrayList<>();
        headers.add((p.method == null ? "POST" : p.method.trim().toUpperCase()) + " " + path + " HTTP/1.1");
        headers.add("Host: " + u.getHost());
        // WAF gotcha: the gateway/WAF blocks the default Java User-Agent — always send a browser UA.
        headers.add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36");
        headers.add("Accept: application/json, */*");
        if (p.contentType != null && !p.contentType.trim().isEmpty()) {
            headers.add("Content-Type: " + p.contentType.trim());
        }
        headers.add("Connection: close");

        byte[] req = helpers.buildHttpMessage(headers, body.getBytes("UTF-8"));
        IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
        byte[] resp = rr.getResponse();
        if (resp == null) return new HttpResult(0, null);
        IResponseInfo ri = helpers.analyzeResponse(resp);
        String rb = new String(resp, ri.getBodyOffset(), resp.length - ri.getBodyOffset(), "UTF-8");
        return new HttpResult(ri.getStatusCode(), rb);
    }

    // ---- multi-step chain plumbing -----------------------------------------

    /** Result of one chain step (status + body; body null only if the server sent nothing). */
    private static final class StepResult {
        final int status; final String body;
        StepResult(int status, String body) { this.status = status; this.body = body; }
    }

    /** Send one chain step, carrying + updating the shared cookie jar; returns status + body. */
    private StepResult sendStep(LoginStep st, String body, CookieJar jar) throws Exception {
        URL u = new URL(st.url);
        boolean https = "https".equalsIgnoreCase(u.getProtocol());
        int port = u.getPort() != -1 ? u.getPort() : (https ? 443 : 80);
        IHttpService svc = helpers.buildHttpService(u.getHost(), port, https);

        String path = u.getPath();
        if (path == null || path.isEmpty()) path = "/";
        if (u.getQuery() != null) path += "?" + u.getQuery();

        List<String> headers = new ArrayList<>();
        headers.add((st.method == null ? "POST" : st.method.trim().toUpperCase()) + " " + path + " HTTP/1.1");
        headers.add("Host: " + u.getHost());
        // WAF gotcha: the gateway/WAF blocks the default Java User-Agent — always send a browser UA.
        headers.add("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36");
        headers.add("Accept: application/json, */*");
        if (st.contentType != null && !st.contentType.trim().isEmpty()) {
            headers.add("Content-Type: " + st.contentType.trim());
        }
        String cookie = jar.header();
        if (cookie != null) headers.add("Cookie: " + cookie);
        headers.add("Connection: close");

        byte[] req = helpers.buildHttpMessage(headers, (body == null ? "" : body).getBytes("UTF-8"));
        IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
        byte[] resp = rr.getResponse();
        if (resp == null) return new StepResult(0, null);
        IResponseInfo ri = helpers.analyzeResponse(resp);
        jar.addFromResponse(ri.getHeaders());   // carry server session/stickiness cookies into the next step
        String rb = new String(resp, ri.getBodyOffset(), resp.length - ri.getBodyOffset(), "UTF-8");
        return new StepResult(ri.getStatusCode(), rb);
    }

    /** Accumulates Set-Cookie name=value pairs across chain steps and renders the Cookie request header. */
    private static final class CookieJar {
        private final LinkedHashMap<String, String> cookies = new LinkedHashMap<>();

        void addFromResponse(List<String> respHeaders) {
            if (respHeaders == null) return;
            for (String h : respHeaders) {
                if (h == null) continue;
                int c = h.indexOf(':');
                if (c < 0 || !h.substring(0, c).trim().equalsIgnoreCase("Set-Cookie")) continue;
                String cookie = h.substring(c + 1).trim();
                int semi = cookie.indexOf(';');
                if (semi >= 0) cookie = cookie.substring(0, semi);   // drop attributes (Path/Domain/Max-Age…)
                int eq = cookie.indexOf('=');
                if (eq <= 0) continue;
                cookies.put(cookie.substring(0, eq).trim(), cookie.substring(eq + 1).trim());
            }
        }

        String header() {
            if (cookies.isEmpty()) return null;
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : cookies.entrySet()) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(e.getKey()).append('=').append(e.getValue());
            }
            return sb.toString();
        }
    }

    /** Run + report a multi-step chain for the "Test Login" UI (per-step status is logged to Extender output). */
    private LoginResult testMultiStep(LoginProfile p) {
        try {
            SessionAuth a = loginSessionMultiStep(p);
            if (a == null) {
                return new LoginResult(false, "Çok-adımlı login başarısız — ayrıntı için Extender çıktısına "
                        + "(LoginManager) bakın. Adım sırası, yakalama JSON-yolu ve oturum token değişkenini kontrol edin.");
            }
            String t = (a.token != null && a.token.length() > 40) ? a.token.substring(0, 40) + "…" : a.token;
            String how = !a.bodyTokens.isEmpty() ? ("gövde alanı: " + a.bodyTokens.keySet())
                                                 : ("başlık: " + a.headers.keySet());
            return new LoginResult(true, p.steps.size() + " adım OK · oturum token=" + t + " → " + how);
        } catch (Exception e) {
            return new LoginResult(false, String.valueOf(e.getMessage()));
        }
    }

    /**
     * Login and return a UI-friendly result (token preview / actionable error), without registering a
     * session. Sends ONE request itself (rather than via {@link #loginSession}) so it can report the HTTP
     * status, the {@code Success} flag, whether the token field resolved-but-was-empty, and a body preview
     * — the info the user needs when "token çıkarılamadı" would otherwise be a dead end.
     */
    public LoginResult test(LoginProfile p) {
        if (p.isMultiStep()) return testMultiStep(p);
        try {
            HttpResult r = send(p);
            if (r.body == null) {
                log("✗ TEST " + p.roleName + ": sunucudan yanıt yok");
                return new LoginResult(false, "Sunucudan yanıt yok (WAF/bağlantı engeli olabilir).");
            }
            String path = effPath(p);
            String raw = resolvePathRaw(r.body, p);           // value at the JSON path (maybe ""), or null if absent
            log("TEST " + p.roleName + ": HTTP " + r.status + ", " + r.body.length() + "B, success="
                    + successFlag(r.body) + ", yol='" + path + "' → " + describe(raw));

            String token = extractToken(r.body, p);
            if (token == null || token.isEmpty()) {
                String hint;
                if (raw != null && raw.isEmpty()) {
                    hint = "'" + path + "' alanı BOŞ döndü. Muhtemelen tek-kullanımlık STS/OTP login yakaladınız "
                         + "(gövdede IsStsLogin:true veya StsLoginOtp var). Düz login isteğini yakalayın "
                         + "(IsStsLogin:false, sadece CustomerId + Password).";
                } else if (raw == null && (p.tokenRegex == null || p.tokenRegex.trim().isEmpty())) {
                    hint = "'" + path + "' yolu yanıtta bulunamadı. Aşağıdaki yanıta bakıp Token JSON yolunu düzeltin.";
                } else {
                    hint = "Token boş/çıkarılamadı.";
                }
                return new LoginResult(false, "HTTP " + r.status + " — " + hint + "\n\nYanıt: " + preview(r.body, 400));
            }
            String t = token.length() > 40 ? token.substring(0, 40) + "…" : token;
            if (p.tokenBodyField != null && !p.tokenBodyField.trim().isEmpty()) {
                t += "  → gövde alanı: " + p.tokenBodyField.trim();
            }
            log("✔ TEST " + p.roleName + ": token OK (" + token.length() + "B)");
            return new LoginResult(true, t);
        } catch (Exception e) {
            log("✗ TEST " + p.roleName + ": " + e);
            return new LoginResult(false, String.valueOf(e.getMessage()));
        }
    }

    private String extractToken(String body, LoginProfile p) {
        if (body == null) return null;
        // 1) JSON dot path (preferred): e.g. "authentication.token"
        if (p.tokenJsonPath != null && !p.tokenJsonPath.trim().isEmpty()) {
            try {
                Object cur = new JSONObject(body);
                for (String seg : p.tokenJsonPath.trim().split("\\.")) {
                    if (!(cur instanceof JSONObject)) { cur = null; break; }
                    cur = ((JSONObject) cur).opt(seg);
                    if (cur == null) break;
                }
                if (cur != null && !(cur instanceof JSONObject)) return String.valueOf(cur);
            } catch (Exception ignore) {
            }
        }
        // 2) regex fallback (group 1 if present, else whole match)
        if (p.tokenRegex != null && !p.tokenRegex.trim().isEmpty()) {
            try {
                Matcher m = Pattern.compile(p.tokenRegex).matcher(body);
                if (m.find()) return m.groupCount() >= 1 ? m.group(1) : m.group(0);
            } catch (Exception ignore) {
            }
        }
        return null;
    }

    // ---- diagnostics --------------------------------------------------------

    /** Raw login response holder (status + body) for diagnostics. */
    private static final class HttpResult {
        final int status; final String body;
        HttpResult(int status, String body) { this.status = status; this.body = body; }
    }

    /** The token locator actually in effect, for log/UI messages. */
    private static String effPath(LoginProfile p) {
        if (p.tokenJsonPath != null && !p.tokenJsonPath.trim().isEmpty()) return p.tokenJsonPath.trim();
        if (p.tokenRegex != null && !p.tokenRegex.trim().isEmpty()) return "regex:" + p.tokenRegex.trim();
        return "(auto)";
    }

    /** The response's top-level {@code Success} value as text (gateway returns this), or "?" if unparseable. */
    private static String successFlag(String body) {
        try { return String.valueOf(new JSONObject(body).opt("Success")); } catch (Exception e) { return "?"; }
    }

    /** Raw string at the configured JSON dot-path — may be "" (present but empty) — or null if it doesn't resolve. */
    private static String resolvePathRaw(String body, LoginProfile p) {
        if (p.tokenJsonPath == null || p.tokenJsonPath.trim().isEmpty()) return null;
        try {
            Object cur = new JSONObject(body);
            for (String seg : p.tokenJsonPath.trim().split("\\.")) {
                if (!(cur instanceof JSONObject)) return null;
                cur = ((JSONObject) cur).opt(seg);
                if (cur == null) return null;
            }
            return (cur instanceof JSONObject) ? null : String.valueOf(cur);
        } catch (Exception e) {
            return null;
        }
    }

    private static String describe(String raw) {
        if (raw == null) return "(yol yok)";
        if (raw.isEmpty()) return "(BOŞ)";
        return "(" + raw.length() + "B dolu)";
    }

    /** A single-line, length-capped preview of a response body for error messages / logs. */
    private static String preview(String body, int max) {
        String s = body.replaceAll("\\s+", " ").trim();
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    private void log(String msg) {
        if (stdout != null) stdout.println("[LoginManager] " + msg);
    }
}
