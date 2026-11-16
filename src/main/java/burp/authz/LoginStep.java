package burp.authz;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One request in a multi-step login chain (e.g. Gateway multi-step:
 * Login → VerifyOtp → Register). Each step sends a request whose body may reference
 * {@code {var}} placeholders resolved from values captured by earlier steps (plus {@code {user}}/{@code {pass}}),
 * then captures its own named variables from the response via JSON dot-paths.
 *
 * The chain's session token is whichever captured variable {@link LoginProfile#sessionTokenVar} names
 * (e.g. {@code sessionKey} ← {@code LoginResponse.token}); it is then applied exactly like a
 * single-request login (Authorization header and/or {@link LoginProfile#tokenBodyField}).
 *
 * Serialized inside {@link LoginProfile#toJSON()} as the {@code steps} array.
 *
 * @author Zahid Eroglu
 */
public class LoginStep {

    public String name = "";                                    // display label, e.g. "Login"
    public String url = "";
    public String method = "POST";
    public String contentType = "application/json";
    public String bodyTemplate = "";                            // placeholders: {user} {pass} {capturedVar}
    /** capturedVarName → JSON dot-path in THIS step's response (e.g. sessionKey → LoginResponse.token). */
    public final LinkedHashMap<String, String> captures = new LinkedHashMap<>();

    public boolean isValid() {
        return url != null && !url.trim().isEmpty();
    }

    public JSONObject toJSON() {
        JSONObject o = new JSONObject();
        o.put("name", name);
        o.put("url", url);
        o.put("method", method);
        o.put("contentType", contentType);
        o.put("bodyTemplate", bodyTemplate);
        JSONObject caps = new JSONObject();
        for (Map.Entry<String, String> e : captures.entrySet()) caps.put(e.getKey(), e.getValue());
        o.put("captures", caps);
        return o;
    }

    public static LoginStep fromJSON(JSONObject o) {
        LoginStep s = new LoginStep();
        s.name = o.optString("name", "");
        s.url = o.optString("url", "");
        s.method = o.optString("method", "POST");
        s.contentType = o.optString("contentType", "application/json");
        s.bodyTemplate = o.optString("bodyTemplate", "");
        JSONObject caps = o.optJSONObject("captures");
        if (caps != null) {
            for (String k : caps.keySet()) {
                String v = caps.optString(k, "");
                if (!k.trim().isEmpty() && !v.trim().isEmpty()) s.captures.put(k.trim(), v.trim());
            }
        }
        return s;
    }

    /** Parse a JSON array of steps (invalid entries dropped). */
    public static List<LoginStep> listFromJson(JSONArray arr) {
        List<LoginStep> out = new ArrayList<>();
        if (arr == null) return out;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.optJSONObject(i);
            if (o == null) continue;
            LoginStep s = fromJSON(o);
            if (s.isValid()) out.add(s);
        }
        return out;
    }

    /** Deep copy via JSON round-trip. */
    public LoginStep copy() {
        return fromJSON(toJSON());
    }
}
