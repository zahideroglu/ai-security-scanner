package burp.session;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import burp.MultiSessionTester;
import burp.authz.AccessOracle;
import burp.authz.AuthMatrix;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Keeps authenticated sessions FRESH so the scanner never makes wrong decisions on a dead session
 * (a logged-out session returns 401/redirect/login-page for everything, which an oracle would
 * mis-read as "access denied / secure"). Liveness is checked with a canary replay classified by
 * {@link AccessOracle}; on death it attempts capture-and-replay auto-relogin from a stored
 * {@link LoginProfile}, else reports that manual re-login is needed.
 *
 * @author Zahid Eroglu
 */
public class SessionKeeper {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final MultiSessionTester mtester;
    private final AccessOracle oracle;
    private final CredentialStore store;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    public SessionKeeper(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                         MultiSessionTester mtester, CredentialStore store,
                         PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.mtester = mtester;
        this.store = store;
        this.oracle = new AccessOracle(helpers);
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /** Classify a raw response as still-authenticated (true) or logged-out/denied (false). */
    public boolean looksAuthenticated(byte[] response) {
        return oracle.verdict(response) == AuthMatrix.Verdict.GRANTED;
    }

    /**
     * Canary: replay a known-good authenticated sample under this session and check it is still GRANTED.
     * {@code sample} should be a request that returns the user's own authenticated content.
     */
    public boolean isAlive(MultiSessionTester.UserSession s, IHttpRequestResponse sample) {
        if (s == null || sample == null) return false;
        try {
            IHttpRequestResponse rr = mtester.replayAs(sample, s);
            return rr != null && looksAuthenticated(rr.getResponse());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Ensure the session is fresh. If the canary fails, try auto-relogin from a stored profile for
     * {@code host}. Returns true if alive (or successfully refreshed), false if dead and unrecoverable
     * (caller should then PAUSE and notify the user instead of testing on a dead session).
     */
    public boolean ensureFresh(MultiSessionTester.UserSession s, IHttpRequestResponse sample, String host) {
        if (isAlive(s, sample)) return true;
        if (stdout != null) stdout.println("[SessionKeeper] session looks dead: "
                + (s != null ? s.roleName : "?") + " — attempting re-login");
        LoginProfile p = (store != null && host != null) ? safeLoad(host) : null;
        if (p == null) {
            if (stdout != null) stdout.println("[SessionKeeper] no stored login profile for " + host
                    + " — manual re-login required.");
            return false;
        }
        if (relogin(s, p) && isAlive(s, sample)) {
            if (stdout != null) stdout.println("[SessionKeeper] re-login OK: " + s.roleName);
            return true;
        }
        if (stdout != null) stdout.println("[SessionKeeper] re-login FAILED: " + s.roleName + " — manual re-login required.");
        return false;
    }

    /** Replay the captured login request and harvest the fresh Cookie/token into the session. */
    public boolean relogin(MultiSessionTester.UserSession s, LoginProfile p) {
        try {
            if (s == null || p == null || p.capturedLoginRequest == null) return false;
            IHttpService svc = helpers.buildHttpService(
                    p.loginHost != null && !p.loginHost.isEmpty() ? p.loginHost : p.host,
                    p.loginPort, p.loginHttps);
            IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, p.capturedLoginRequest);
            Map<String, String> fresh = extractFreshTokens(rr);
            if (fresh.isEmpty()) return false;
            if (s.authTokens == null) s.authTokens = new LinkedHashMap<>();
            s.authTokens.clear();
            s.authTokens.putAll(fresh);
            return true;
        } catch (Exception e) {
            if (stderr != null) stderr.println("[SessionKeeper] relogin error: " + e.getMessage());
            return false;
        }
    }

    private Map<String, String> extractFreshTokens(IHttpRequestResponse rr) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            byte[] resp = rr == null ? null : rr.getResponse();
            if (resp == null) return out;
            IResponseInfo ri = helpers.analyzeResponse(resp);
            StringBuilder cookie = new StringBuilder();
            for (String h : ri.getHeaders()) {
                if (h.toLowerCase().startsWith("set-cookie:")) {
                    String c = h.substring(h.indexOf(':') + 1).trim();
                    int sc = c.indexOf(';');
                    String pair = (sc >= 0 ? c.substring(0, sc) : c).trim();
                    if (!pair.isEmpty()) {
                        if (cookie.length() > 0) cookie.append("; ");
                        cookie.append(pair);
                    }
                }
            }
            if (cookie.length() > 0) out.put("Cookie", cookie.toString());

            int off = ri.getBodyOffset();
            String body = new String(resp, off, Math.max(0, resp.length - off), StandardCharsets.UTF_8);
            String tok = jsonField(body, "access_token");
            if (tok == null) tok = jsonField(body, "token");
            if (tok != null && !tok.isEmpty()) out.put("Authorization", "Bearer " + tok);
        } catch (Exception ignore) {
        }
        return out;
    }

    private String jsonField(String body, String field) {
        try {
            JSONObject o = new JSONObject(body);
            return o.has(field) ? o.getString(field) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private LoginProfile safeLoad(String host) {
        try { return store.load(host); } catch (Exception e) { return null; }
    }
}
