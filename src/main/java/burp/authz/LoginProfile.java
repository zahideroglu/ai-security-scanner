package burp.authz;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A self-login recipe for one role: how to log in (URL / method / body + credentials), where to
 * find the token in the login response, and how to apply it to subsequent requests. Used by
 * {@link LoginManager} to mint FRESH sessions so the authorization matrix / BOLA hunts no longer
 * depend on (often expired) tokens harvested from proxy history.
 *
 * Stored in {@code Settings.loginProfilesJson} as a JSON array of these objects.
 *
 * @author Zahid Eroglu
 */
public class LoginProfile {

    public String roleName = "";
    public String loginUrl = "";
    public String method = "POST";
    public String contentType = "application/json";
    public String bodyTemplate = "";                       // placeholders: {user} {pass}
    public String username = "";
    public String password = "";
    public String tokenJsonPath = "";                      // dot path, e.g. authentication.token (preferred)
    public String tokenRegex = "";                         // fallback: regex, group 1 = token
    public String authHeaderName = "Authorization";        // header applied to subsequent requests
    public String authValueTemplate = "Bearer {token}";    // {token} substituted
    public String tokenBodyField = "";                     // body-carried session (gateway): inject the token into this
                                                           // JSON field of every replayed request, e.g. sessionToken

    // ---- multi-step login chain (optional) --------------------------------
    // When {@code steps} is non-empty the login is a SEQUENCE (e.g. Gateway multi-step:
    // Login → VerifyOtp → Register) run in order, each capturing variables from its
    // response that later steps reference via {var}. The session token is whichever captured variable
    // {@code sessionTokenVar} names; it is then applied via authHeader/tokenBodyField as usual.
    // Empty steps ⇒ classic single-request login (fully backward compatible).
    public final List<LoginStep> steps = new ArrayList<>();
    public String sessionTokenVar = "";                    // e.g. "sessionKey" (captured from a step's response)

    public boolean isMultiStep() {
        return steps != null && !steps.isEmpty();
    }

    public boolean isValid() {
        boolean hasEntry = (loginUrl != null && !loginUrl.trim().isEmpty()) || isMultiStep();
        return roleName != null && !roleName.trim().isEmpty() && hasEntry;
    }

    public JSONObject toJSON() {
        JSONObject o = new JSONObject();
        o.put("roleName", roleName);
        o.put("loginUrl", loginUrl);
        o.put("method", method);
        o.put("contentType", contentType);
        o.put("bodyTemplate", bodyTemplate);
        o.put("username", username);
        o.put("password", password);
        o.put("tokenJsonPath", tokenJsonPath);
        o.put("tokenRegex", tokenRegex);
        o.put("authHeaderName", authHeaderName);
        o.put("authValueTemplate", authValueTemplate);
        o.put("tokenBodyField", tokenBodyField);
        if (isMultiStep()) {
            JSONArray stepsArr = new JSONArray();
            for (LoginStep s : steps) stepsArr.put(s.toJSON());
            o.put("steps", stepsArr);
            o.put("sessionTokenVar", sessionTokenVar);
        }
        return o;
    }

    public static LoginProfile fromJSON(JSONObject o) {
        LoginProfile p = new LoginProfile();
        p.roleName = o.optString("roleName", "");
        p.loginUrl = o.optString("loginUrl", "");
        p.method = o.optString("method", "POST");
        p.contentType = o.optString("contentType", "application/json");
        p.bodyTemplate = o.optString("bodyTemplate", "");
        p.username = o.optString("username", "");
        p.password = o.optString("password", "");
        p.tokenJsonPath = o.optString("tokenJsonPath", "");
        p.tokenRegex = o.optString("tokenRegex", "");
        p.authHeaderName = o.optString("authHeaderName", "Authorization");
        p.authValueTemplate = o.optString("authValueTemplate", "Bearer {token}");
        p.tokenBodyField = o.optString("tokenBodyField", "");
        p.steps.addAll(LoginStep.listFromJson(o.optJSONArray("steps")));
        p.sessionTokenVar = o.optString("sessionTokenVar", "");
        return p;
    }

    /** Parse a JSON array string into the valid profiles it contains (invalid/blank ones dropped). */
    public static List<LoginProfile> listFromJson(String json) {
        List<LoginProfile> out = new ArrayList<>();
        if (json == null || json.trim().isEmpty()) return out;
        try {
            JSONArray arr = new JSONArray(json.trim());
            for (int i = 0; i < arr.length(); i++) {
                LoginProfile p = fromJSON(arr.getJSONObject(i));
                if (p.isValid()) out.add(p);
            }
        } catch (Exception ignore) {
        }
        return out;
    }
}
