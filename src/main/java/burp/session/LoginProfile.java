package burp.session;

import org.json.JSONObject;

import java.util.Base64;

/**
 * A per-target login profile: enough to RE-authenticate automatically when a session dies.
 * The primary mechanism is "capture-and-replay" — a captured login HTTP request (which already
 * carries the credentials) is stored ENCRYPTED via {@link CredentialStore} and replayed on logout.
 *
 * @author Zahid Eroglu
 */
public class LoginProfile {

    public String host;              // target host this profile belongs to (key)
    public String roleLabel;         // identity label; matches MultiSessionTester.UserSession.roleName
    public String username = "";     // optional, for display/audit only
    public String password = "";     // optional; the captured request usually already contains it

    public byte[] capturedLoginRequest; // the login HTTP request to replay (contains credentials)
    public String loginHost;         // service host for the captured request
    public int loginPort = 443;
    public boolean loginHttps = true;

    public JSONObject toJson() {
        JSONObject o = new JSONObject();
        o.put("host", n(host));
        o.put("roleLabel", n(roleLabel));
        o.put("username", n(username));
        o.put("password", n(password));
        o.put("loginHost", n(loginHost));
        o.put("loginPort", loginPort);
        o.put("loginHttps", loginHttps);
        o.put("capturedLoginRequest",
                capturedLoginRequest == null ? "" : Base64.getEncoder().encodeToString(capturedLoginRequest));
        return o;
    }

    public static LoginProfile fromJson(JSONObject o) {
        LoginProfile p = new LoginProfile();
        p.host = o.optString("host", "");
        p.roleLabel = o.optString("roleLabel", "");
        p.username = o.optString("username", "");
        p.password = o.optString("password", "");
        p.loginHost = o.optString("loginHost", "");
        p.loginPort = o.optInt("loginPort", 443);
        p.loginHttps = o.optBoolean("loginHttps", true);
        String b64 = o.optString("capturedLoginRequest", "");
        p.capturedLoginRequest = (b64 == null || b64.isEmpty()) ? null : Base64.getDecoder().decode(b64);
        return p;
    }

    private static String n(String s) { return s == null ? "" : s; }
}
