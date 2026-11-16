package burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.MultiSessionTester;
import burp.MultiSessionTester.UserSession;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Autonomous role discovery: scans Burp proxy history for the target host, extracts
 * the distinct authenticated sessions (auth cookies / Authorization / token headers),
 * dedups them by identity fingerprint, auto-labels each (decoding JWT claims when
 * present), and validates them in the background. Removes the manual "Add Session"
 * step from the {@link AuthMatrixEngine} workflow.
 *
 * <p>Identity is keyed by the JWT <em>subject</em> (id/email/sub claim) when a token is
 * present, so the same user's multiple tokens (re-logins / refreshes) collapse to one
 * role and the <em>freshest</em> token is kept. Validation is tri-state: a token that is
 * explicitly rejected (401/403/login) is dropped as expired, but a token we simply
 * cannot confirm (target down / 5xx / no response) is kept (UNKNOWN) — dropping an
 * identity because the server hiccuped would silently reduce the matrix to anonymous-only.
 *
 * @author Zahid Eroglu
 */
public class SessionHarvester {

    /** Outcome of replaying a harvested session against the live target. */
    public enum Validity {
        VALID,    // replay returned authenticated content (2xx, not a login page)
        EXPIRED,  // token explicitly rejected: 401/403, login page, or redirect-to-login
        UNKNOWN   // could not tell: target down / 5xx / connection error / no response
    }

    private static final Set<String> AUTH_COOKIE_HINTS = new HashSet<>(Arrays.asList(
            "session", "sessionid", "sid", "auth", "token", "jwt", "aspxauth", "asp.net",
            "identity", "sso", "access_token", "accesstoken", "connect.sid", "phpsessid",
            "jsessionid", "laravel_session", "remember", "bearer"));

    // Cookie names that look auth-ish by substring but are NOT a session (avoid phantom identities).
    private static final Set<String> COOKIE_NAME_DENY = new HashSet<>(Arrays.asList(
            "csrf", "xsrf", "antiforgery", "csrftoken", "consent", "cookieconsent",
            "continuecode", "welcomebanner"));

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public SessionHarvester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    /** A candidate role discovered from history. */
    public static class DiscoveredRole {
        public UserSession session;
        public IHttpRequestResponse sample; // representative request (preferably a GET) for validation
        public int backing;                 // how many history requests share this identity
        public String detail = "";
        public Validity validity = Validity.UNKNOWN; // filled by checkValidity()
        public List<IHttpRequestResponse> requests = new ArrayList<>(); // all history requests for this identity
        long freshness;                     // JWT iat (or history order) of the kept token — internal
    }

    /** Scan history (no network) and return the distinct sessions for {@code host}. */
    public List<DiscoveredRole> harvest(String host) {
        Map<String, DiscoveredRole> byId = new LinkedHashMap<>();
        IHttpRequestResponse[] hist = callbacks.getProxyHistory();
        if (hist == null) return new ArrayList<>();

        long order = 0;
        for (IHttpRequestResponse h : hist) {
            order++;
            try {
                if (h.getRequest() == null) continue;
                IRequestInfo ri = helpers.analyzeRequest(h);
                if (ri.getUrl() == null || !host.equalsIgnoreCase(ri.getUrl().getHost())) continue;

                String cookie = null, authorization = null;
                Map<String, String> extra = new LinkedHashMap<>();
                for (String hdr : ri.getHeaders()) {
                    String low = hdr.toLowerCase();
                    if (low.startsWith("cookie:")) cookie = hdr.substring(7).trim();
                    else if (low.startsWith("authorization:")) authorization = hdr.substring(14).trim();
                    else if (low.startsWith("x-auth-token:")) extra.put("X-Auth-Token", hdr.substring(13).trim());
                    else if (low.startsWith("x-api-key:")) extra.put("X-API-Key", hdr.substring(10).trim());
                    else if (low.startsWith("x-access-token:")) extra.put("X-Access-Token", hdr.substring(15).trim());
                }

                String authCookieFp = authCookieFingerprint(cookie);
                boolean hasAuth = (authorization != null && !authorization.isEmpty())
                        || !authCookieFp.isEmpty() || !extra.isEmpty();
                if (!hasAuth) continue; // anonymous request — engine adds a synthetic anon role

                // Identity key + freshness: prefer the JWT subject (stable across token refreshes);
                // fall back to the raw token material when no decodable JWT is present.
                JwtInfo jwt = parseJwt(extractJwt(authorization, cookie));
                String id;
                long fresh;
                if (jwt != null && jwt.subjectKey != null) {
                    id = "subj:" + jwt.subjectKey;
                    fresh = jwt.iat > 0 ? jwt.iat : order;
                } else {
                    id = "raw:" + (authorization == null ? "" : authorization) + "##" + authCookieFp + "##" + extra;
                    fresh = order;
                }

                boolean curGet = "GET".equalsIgnoreCase(ri.getMethod());
                DiscoveredRole dr = byId.get(id);
                if (dr == null) {
                    dr = new DiscoveredRole();
                    dr.sample = h;
                    dr.freshness = fresh;
                    UserSession s = new UserSession();
                    s.authTokens = buildTokens(cookie, authorization, extra);
                    s.description = "auto (history)";
                    s.roleName = jwt != null ? jwt.label : null;
                    dr.session = s;
                    dr.detail = jwt != null ? jwt.detail : "cookie/header session";
                    byId.put(id, dr);
                } else {
                    // Same identity seen again: keep the FRESHEST token so we validate/replay with live creds.
                    if (fresh > dr.freshness) {
                        dr.freshness = fresh;
                        dr.session.authTokens = buildTokens(cookie, authorization, extra);
                        if (jwt != null) { dr.session.roleName = jwt.label; dr.detail = jwt.detail; }
                    }
                    // Prefer a GET sample so validation never mutates (independent of which token we keep —
                    // replayAs() strips the sample's own auth and injects the session tokens).
                    if (curGet && !"GET".equalsIgnoreCase(helpers.analyzeRequest(dr.sample).getMethod())) {
                        dr.sample = h;
                    }
                }
                dr.backing++;
                dr.requests.add(h);
            } catch (Exception ignore) {
            }
        }

        // Name the unlabeled sessions and make role names unique.
        List<DiscoveredRole> out = new ArrayList<>(byId.values());
        int n = 1;
        Set<String> used = new HashSet<>();
        for (DiscoveredRole dr : out) {
            String name = dr.session.roleName;
            if (name == null || name.isEmpty()) name = "session-" + (n++);
            String base = name;
            int k = 2;
            while (used.contains(name)) name = base + "#" + (k++);
            used.add(name);
            dr.session.roleName = name;
        }
        if (stdout != null) stdout.println("[SessionHarvester] " + out.size() + " distinct session(s) for " + host);
        return out;
    }

    /**
     * Replay the sample with its own tokens and classify the outcome. A clean authenticated
     * response means VALID; an explicit auth rejection means EXPIRED; anything we cannot
     * attribute to the token (target down, 5xx, connection error) means UNKNOWN.
     */
    public Validity checkValidity(DiscoveredRole dr, MultiSessionTester mtester) {
        try {
            IHttpRequestResponse rr = mtester.replayAs(dr.sample, dr.session);
            byte[] resp = rr != null ? rr.getResponse() : null;
            if (resp == null) return Validity.UNKNOWN;                 // no response — target unreachable
            IResponseInfo ri = helpers.analyzeResponse(resp);
            int sc = ri.getStatusCode();
            if (sc == 401) return Validity.EXPIRED;                    // token rejected → not authenticated
            // 403 = authenticated but FORBIDDEN for THIS resource — NOT "expired". The token is still a real
            // identity (it got past auth), which is exactly what cross-user BOLA needs. Conflating it with 401
            // silently dropped valid sessions and collapsed the matrix/BOLA to anonymous-only.
            if (sc == 403) return Validity.VALID;
            if (new AccessOracle(helpers).verdict(resp) == AuthMatrix.Verdict.GRANTED) return Validity.VALID;
            if (sc >= 200 && sc < 400) return Validity.EXPIRED;        // 2xx-login-page or redirect-to-login
            return Validity.UNKNOWN;                                   // 5xx / 0 / weird — can't blame the token
        } catch (Exception e) {
            return Validity.UNKNOWN;
        }
    }

    /** Back-compat: a session is "valid" only when its replay confirms authenticated access. */
    public boolean validate(DiscoveredRole dr, MultiSessionTester mtester) {
        return checkValidity(dr, mtester) == Validity.VALID;
    }

    private Map<String, String> buildTokens(String cookie, String authorization, Map<String, String> extra) {
        Map<String, String> tokens = new LinkedHashMap<>();
        if (cookie != null && !cookie.isEmpty()) tokens.put("Cookie", cookie);
        if (authorization != null && !authorization.isEmpty()) tokens.put("Authorization", authorization);
        if (extra != null) tokens.putAll(extra);
        return tokens;
    }

    /**
     * Auth-relevant cookie values (sorted) as an identity fingerprint. A cookie counts when its
     * name hints at a session OR its value is JWT-shaped; known non-session cookies (csrf, consent,
     * continueCode, …) are always excluded so they never create a phantom identity.
     */
    private String authCookieFingerprint(String cookieHeader) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return "";
        TreeSet<String> vals = new TreeSet<>();
        for (String c : cookieHeader.split(";")) {
            int eq = c.indexOf('=');
            if (eq <= 0) continue;
            String name = c.substring(0, eq).trim().toLowerCase();
            String val = c.substring(eq + 1).trim();
            if (val.isEmpty() || isDeniedCookie(name)) continue;
            boolean hinted = false;
            for (String hint : AUTH_COOKIE_HINTS) {
                if (name.contains(hint)) { hinted = true; break; }
            }
            if (hinted || looksJwt(val)) vals.add(name + "=" + val);
        }
        return String.join("|", vals);
    }

    private boolean isDeniedCookie(String name) {
        for (String deny : COOKIE_NAME_DENY) if (name.contains(deny)) return true;
        return false;
    }

    /** The first JWT-looking token in the request: Authorization bearer first, then any auth cookie value. */
    private String extractJwt(String authorization, String cookieHeader) {
        if (authorization != null) {
            String a = authorization.trim();
            if (a.regionMatches(true, 0, "bearer ", 0, 7)) a = a.substring(7).trim();
            if (looksJwt(a)) return a;
        }
        if (cookieHeader != null) {
            for (String c : cookieHeader.split(";")) {
                int eq = c.indexOf('=');
                if (eq <= 0) continue;
                String name = c.substring(0, eq).trim().toLowerCase();
                if (isDeniedCookie(name)) continue;
                String val = c.substring(eq + 1).trim();
                if (looksJwt(val)) return val;
            }
        }
        return null;
    }

    /** Decoded identity hints from a JWT: a stable subject key, a display label, a detail, and iat. */
    private static class JwtInfo {
        String subjectKey; // id/email/sub — used to dedup the same user across tokens
        String label;      // role (preferred) else who else "jwt"
        String detail;     // human-readable summary
        long iat;          // issued-at (seconds) for freshness; 0 if absent
    }

    /** Decode a JWT payload (claims may be nested under data/user/…) into identity hints. */
    private JwtInfo parseJwt(String jwt) {
        if (jwt == null) return null;
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;
            byte[] payload = Base64.getUrlDecoder().decode(pad(parts[1]));
            JSONObject claims = flatten(new JSONObject(new String(payload, "UTF-8")));
            String role = firstClaim(claims, "role", "roles", "scope", "scp", "groups", "authorities", "type");
            String who = firstClaim(claims, "preferred_username", "unique_name", "upn", "email", "name", "sub",
                    "username", "user");
            String idClaim = firstClaim(claims, "id", "user_id", "userid", "uid", "sub", "email",
                    "preferred_username", "unique_name");
            JwtInfo info = new JwtInfo();
            info.subjectKey = idClaim != null ? (idClaim + "|" + (role == null ? "" : role)) : null;
            info.label = role != null ? clip(role, 24) : (who != null ? clip(who, 24) : "jwt");
            info.detail = "JWT" + (role != null ? " role=" + role : "")
                    + (who != null ? " user=" + who : "")
                    + (idClaim != null && !idClaim.equals(who) ? " id=" + idClaim : "");
            info.iat = optLong(claims, "iat");
            return info;
        } catch (Exception e) {
            JwtInfo info = new JwtInfo();
            info.label = "jwt";
            info.detail = "JWT (decode failed)";
            return info;
        }
    }

    /** Merge a claims object with its common nested wrappers so id/email/role are found regardless of depth. */
    private JSONObject flatten(JSONObject root) {
        JSONObject merged = new JSONObject();
        copyInto(root, merged);
        for (String wrap : new String[]{"data", "user", "payload", "userData", "account", "claims"}) {
            if (root.has(wrap)) {
                Object v = root.get(wrap);
                if (v instanceof JSONObject) copyInto((JSONObject) v, merged); // nested overrides (more specific)
            }
        }
        return merged;
    }

    private void copyInto(JSONObject src, JSONObject dst) {
        for (Iterator<String> it = src.keys(); it.hasNext(); ) {
            String k = it.next();
            dst.put(k, src.get(k));
        }
    }

    private long optLong(JSONObject o, String key) {
        try { return o.has(key) ? Long.parseLong(String.valueOf(o.get(key)).trim()) : 0L; }
        catch (Exception e) { return 0L; }
    }

    private boolean looksJwt(String s) {
        if (s == null) return false;
        String[] p = s.split("\\.");
        return p.length == 3 && p[0].length() > 4 && p[1].length() > 4;
    }

    private String pad(String b64url) {
        int m = b64url.length() % 4;
        if (m == 2) return b64url + "==";
        if (m == 3) return b64url + "=";
        return b64url;
    }

    private String firstClaim(JSONObject o, String... keys) {
        for (String k : keys) {
            if (!o.has(k)) continue;
            Object v = o.get(k);
            if (v instanceof JSONArray) {
                JSONArray arr = (JSONArray) v;
                if (arr.length() > 0) return String.valueOf(arr.get(0));
            } else {
                String s = String.valueOf(v).trim();
                if (!s.isEmpty() && !"null".equalsIgnoreCase(s)) return s;
            }
        }
        return null;
    }

    private String clip(String s, int n) {
        return s == null ? null : (s.length() <= n ? s : s.substring(0, n));
    }
}
