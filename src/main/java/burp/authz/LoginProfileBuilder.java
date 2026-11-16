package burp.authz;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Turns a captured login request/response into a best-guess {@link LoginProfile} so the user never
 * has to hand-write the escaped-JSON recipe. The hard parts are done automatically:
 * <ul>
 *   <li>the request body's username/password values are detected by key name and replaced with the
 *       {@code {user}} / {@code {pass}} placeholders (their literals go into the username/password
 *       fields);</li>
 *   <li>the response body is scanned for the token and the matching {@code tokenJsonPath} dot-path
 *       (e.g. {@code authentication.token}) is inferred — the single field users most often get
 *       wrong.</li>
 * </ul>
 * Pure logic, no Swing — so it can be unit-tested and reused by the settings wizard.
 *
 * @author Zahid Eroglu
 */
public final class LoginProfileBuilder {

    private LoginProfileBuilder() {}

    /** Request-body keys whose value is the username/identifier (matched as a substring, lower-case). */
    private static final String[] USER_KEYS = {
            "email", "mail", "username", "user_name", "user", "userid", "user_id", "uid",
            "login", "loginname", "account", "phone", "msisdn", "identifier", "identity", "j_username",
            // banking / Turkish logins: the customer number IS the "username" (e.g. Gateway customerId)
            "customer", "musteri", "müşteri", "tckn", "tcno", "tckimlik", "nationalid"
    };
    /** Request-body keys whose value is the secret. */
    private static final String[] PASS_KEYS = {
            "password", "passwd", "pass", "pwd", "passphrase", "secret", "credential", "j_password"
    };

    private static final Pattern JWT =
            Pattern.compile("^[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{4,}$");
    /** A flat {@code k=v&k=v} form body (no spaces, at least one pair). */
    private static final Pattern FORM_BODY =
            Pattern.compile("^[^=&\\s]+=[^&]*(&[^=&\\s]+=[^&]*)*$");

    // ---- public API ---------------------------------------------------------

    /** Best-guess profile from a captured login request (and its response, if present). Never null. */
    public static LoginProfile draftFromRequest(IHttpRequestResponse rr, IExtensionHelpers helpers) {
        LoginProfile p = new LoginProfile();
        if (rr == null || helpers == null) return p;
        try {
            IRequestInfo info = helpers.analyzeRequest(rr);
            if (info.getUrl() != null) p.loginUrl = info.getUrl().toString();
            if (info.getMethod() != null && !info.getMethod().trim().isEmpty()) p.method = info.getMethod();
            String ctype = headerValue(info.getHeaders(), "content-type");
            if (ctype != null && !ctype.isEmpty()) p.contentType = ctype;

            String body = bodyOf(rr.getRequest(), info.getBodyOffset());
            String[] creds = new String[2]; // [0]=user, [1]=pass
            p.bodyTemplate = templatizeBody(body, p.contentType, creds);
            p.username = creds[0] == null ? "" : creds[0];
            p.password = creds[1] == null ? "" : creds[1];
            p.roleName = guessRole(p.username);

            // Infer the token dot-path from the captured response — the field users most often miss.
            byte[] resp = rr.getResponse();
            if (resp != null) {
                IResponseInfo ri = helpers.analyzeResponse(resp);
                String respBody = bodyOf(resp, ri.getBodyOffset());
                String path = detectTokenPath(respBody);
                if (path != null) {
                    p.tokenJsonPath = path;
                    // Body-carried session (Gateway): if the SAME token value already appears in a field of
                    // the LOGIN REQUEST body (e.g. sessionToken == response SessionKey), the session is carried
                    // in the body, not an Authorization header. Configure injection into that field and drop the
                    // header so replays authenticate the way the real app does.
                    String tokenVal = readJsonPath(respBody, path);
                    if (tokenVal != null && tokenVal.length() >= 8) {
                        // Body-carried session ONLY when the SAME token value ALREADY appears in the login
                        // REQUEST body (a genuine signal). Otherwise default to Bearer (Authorization header) —
                        // the session is tracked by the Bearer token, NOT by an empty sessionToken field.
                        // (Guessing an empty session-field wrongly dropped the header → all replays got
                        //  "SessionNotFound / Oturumunuz sonlanmıştır".)
                        String field = findBodyFieldWithValue(body, tokenVal);
                        if (field != null) {
                            p.tokenBodyField = field;
                            p.authHeaderName = "";
                            p.authValueTemplate = "";
                        }
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return p;
    }

    /**
     * Find the dot-path to the auth token inside a JSON response body, or null. Only descends through
     * JSON objects (not arrays) so the result is compatible with {@code LoginManager}'s extractor.
     */
    public static String detectTokenPath(String responseBody) {
        if (responseBody == null) return null;
        String t = responseBody.trim();
        if (!t.startsWith("{")) return null;
        try {
            List<Cand> out = new ArrayList<>();
            walk(new JSONObject(t), "", 0, out);
            Cand best = null;
            for (Cand c : out) if (best == null || c.score > best.score) best = c;
            return (best != null && best.score > 0) ? best.path : null;
        } catch (JSONException e) {
            return null;
        }
    }

    /** Heuristic: does this look like an authentication request? Used to sort the picker. */
    public static boolean looksLikeLoginRequest(IRequestInfo info, IHttpRequestResponse rr) {
        try {
            if (info == null) return false;
            String url = info.getUrl() == null ? "" : info.getUrl().toString().toLowerCase(Locale.ROOT);
            boolean urlHit = url.contains("login") || url.contains("signin") || url.contains("sign-in")
                    || url.contains("logon") || url.contains("/auth") || url.contains("authenticate")
                    || url.contains("oauth") || url.contains("/token") || url.contains("session");
            String m = info.getMethod() == null ? "" : info.getMethod().toUpperCase(Locale.ROOT);
            boolean bodyHit = false;
            if (("POST".equals(m) || "PUT".equals(m)) && rr != null) {
                String body = bodyOf(rr.getRequest(), info.getBodyOffset()).toLowerCase(Locale.ROOT);
                bodyHit = body.contains("password") || body.contains("passwd")
                        || body.contains("\"pass\"") || body.contains("pwd");
            }
            return urlHit || bodyHit;
        } catch (Exception e) {
            return false;
        }
    }

    // ---- body templating ----------------------------------------------------

    /** Replace detected user/pass values with placeholders; fills creds[0]=user, creds[1]=pass. */
    static String templatizeBody(String body, String contentType, String[] creds) {
        if (body == null || body.trim().isEmpty()) return body == null ? "" : body;
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);

        if (ct.contains("json") || body.trim().startsWith("{")) {
            try {
                JSONObject o = new JSONObject(body);
                if (templatizeJson(o, creds)) return o.toString();
            } catch (JSONException ignore) {
            }
        }
        if (ct.contains("x-www-form-urlencoded") || FORM_BODY.matcher(body.trim()).matches()) {
            String t = templatizeForm(body, creds);
            if (t != null) return t;
        }
        return body; // unparseable — leave as-is, the user can mark {user}/{pass} by hand
    }

    private static boolean templatizeJson(JSONObject o, String[] creds) {
        boolean found = false;
        List<String> keys = new ArrayList<>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) keys.add(it.next());
        for (String key : keys) {
            Object v = o.opt(key);
            if (v instanceof JSONObject) {
                found |= templatizeJson((JSONObject) v, creds);
            } else if (v instanceof String) {
                String lk = key.toLowerCase(Locale.ROOT);
                if (creds[0] == null && matchesAny(lk, USER_KEYS)) {
                    creds[0] = (String) v;
                    o.put(key, "{user}");
                    found = true;
                } else if (creds[1] == null && matchesAny(lk, PASS_KEYS)) {
                    creds[1] = (String) v;
                    o.put(key, "{pass}");
                    found = true;
                }
            } else if (v instanceof Number && creds[0] == null
                    && matchesAny(key.toLowerCase(Locale.ROOT), USER_KEYS)) {
                // Numeric identifier (gateway customerId is often an unquoted number): capture it for the
                // Kullanıcı field + role, but leave it in the body AS A NUMBER — quoting it "{user}"
                // could make a strict server reject the type on replay.
                creds[0] = String.valueOf(v);
                found = true;
            }
        }
        return found;
    }

    private static String templatizeForm(String body, String[] creds) {
        String[] pairs = body.split("&");
        boolean found = false;
        StringBuilder sb = new StringBuilder();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (sb.length() > 0) sb.append('&');
            if (eq < 0) {
                sb.append(pair);
                continue;
            }
            String k = pair.substring(0, eq);
            String v = pair.substring(eq + 1);
            String lk = k.toLowerCase(Locale.ROOT);
            if (creds[0] == null && matchesAny(lk, USER_KEYS)) {
                creds[0] = v;
                v = "{user}";
                found = true;
            } else if (creds[1] == null && matchesAny(lk, PASS_KEYS)) {
                creds[1] = v;
                v = "{pass}";
                found = true;
            }
            sb.append(k).append('=').append(v);
        }
        return found ? sb.toString() : null;
    }

    // ---- token detection ----------------------------------------------------

    private static final class Cand {
        final String path;
        final int score;
        Cand(String path, int score) { this.path = path; this.score = score; }
    }

    private static void walk(JSONObject o, String prefix, int depth, List<Cand> out) {
        if (depth > 6) return;
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            String key = it.next();
            Object v = o.opt(key);
            String path = prefix.isEmpty() ? key : prefix + "." + key;
            if (v instanceof JSONObject) {
                walk((JSONObject) v, path, depth + 1, out);
            } else if (v instanceof String) {
                int s = scoreToken(key, (String) v, depth);
                if (s > 0) out.add(new Cand(path, s));
            }
        }
    }

    private static int scoreToken(String key, String val, int depth) {
        if (val == null) return 0;
        String lk = key.toLowerCase(Locale.ROOT);
        int s;
        if (lk.equals("token")) s = 100;
        else if (lk.equals("access_token") || lk.equals("accesstoken")) s = 98;
        else if (lk.equals("jwt")) s = 95;
        else if (lk.equals("auth_token") || lk.equals("authtoken")) s = 90;
        else if (lk.equals("sessionkey") || lk.equals("session_key")) s = 88;  // gateway mints a SessionKey here
        else if (lk.equals("authorization")) s = 80;
        else if (lk.equals("id_token") || lk.equals("idtoken")) s = 75;
        else if (lk.equals("session_token") || lk.equals("sessiontoken")) s = 72;
        else if (lk.equals("bearer")) s = 70;
        else if (lk.equals("api_token") || lk.equals("apitoken")) s = 70;
        else if (lk.equals("apikey") || lk.equals("api_key")
                || lk.equals("accesskey") || lk.equals("access_key")) s = 68;
        else if (lk.equals("sessionid") || lk.equals("session_id")) s = 66;    // gateway fallback (id, not the secret)
        else if (lk.equals("ticket")) s = 55;
        else if (lk.endsWith("token")) s = 60;
        else if (lk.endsWith("sessionkey")) s = 58;
        else if (lk.contains("token") || lk.contains("jwt")) s = 50;
        else if (lk.endsWith("key") && !lk.contains("public") && !lk.contains("device")) s = 42; // generic *Key secret
        else return 0;

        int len = val.length();
        if (len < 8) return 0;                          // "true"/short ids aren't tokens
        if (JWT.matcher(val).matches()) s += 40;        // looks like a real JWT
        else if (len >= 20) s += 10;
        if (lk.contains("refresh")) s -= 35;            // prefer the access token
        if (lk.contains("csrf") || lk.contains("xsrf")) s -= 60;
        s -= depth * 2;                                 // prefer shallower paths
        return s;
    }

    // ---- small helpers ------------------------------------------------------

    private static boolean matchesAny(String lowerKey, String[] patterns) {
        for (String p : patterns) if (lowerKey.contains(p)) return true;
        return false;
    }

    /** Read a dot-path string value out of a JSON body (objects only), or null. */
    private static String readJsonPath(String json, String dotPath) {
        if (json == null || dotPath == null) return null;
        try {
            Object cur = new JSONObject(json);
            for (String seg : dotPath.split("\\.")) {
                if (!(cur instanceof JSONObject)) return null;
                cur = ((JSONObject) cur).opt(seg);
                if (cur == null) return null;
            }
            return (cur instanceof JSONObject) ? null : String.valueOf(cur);
        } catch (Exception e) {
            return null;
        }
    }

    /** Name of the first JSON field (any depth) whose string value equals {@code value}, or null. */
    private static String findBodyFieldWithValue(String body, String value) {
        if (body == null || value == null) return null;
        String t = body.trim();
        if (!t.startsWith("{")) return null;
        try {
            return searchValue(new JSONObject(t), value);
        } catch (Exception e) {
            return null;
        }
    }

    private static String searchValue(JSONObject o, String value) {
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            String k = it.next();
            Object v = o.opt(k);
            if (v instanceof String && value.equals(v)) return k;
            if (v instanceof JSONObject) {
                String r = searchValue((JSONObject) v, value);
                if (r != null) return r;
            }
        }
        return null;
    }

    // ---- explicit field mapping (user picks WHICH body field is {user}/{pass}) ----------------------
    // gateway login bodies carry several id/secret-looking fields (UserName, CustomerId, ExtUPassword,
    // Password …) and auto-detection can pick the wrong one — so the editor lets the user choose.

    /** Ordered, de-duplicated leaf field names (string/number values, any depth) of a JSON body. */
    public static List<String> leafFieldNames(String body) {
        List<String> names = new ArrayList<>();
        if (body == null || body.trim().isEmpty()) return names;
        try {
            collectNames(new JSONObject(body.trim()), names);
        } catch (Exception ignore) {
        }
        return names;
    }

    private static void collectNames(JSONObject o, List<String> names) {
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            String k = it.next();
            Object v = o.opt(k);
            if (v instanceof JSONObject) collectNames((JSONObject) v, names);
            else if ((v instanceof String || v instanceof Number) && !names.contains(k)) names.add(k);
        }
    }

    /** The (first) key whose value is exactly {@code placeholder} (e.g. "{user}"), or null. */
    public static String keyOfPlaceholder(String body, String placeholder) {
        if (body == null) return null;
        try {
            return findKeyByValue(new JSONObject(body.trim()), placeholder);
        } catch (Exception e) {
            return null;
        }
    }

    private static String findKeyByValue(JSONObject o, String value) {
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            String k = it.next();
            Object v = o.opt(k);
            if (v instanceof JSONObject) {
                String r = findKeyByValue((JSONObject) v, value);
                if (r != null) return r;
            } else if (v != null && value.equals(String.valueOf(v))) {
                return k;
            }
        }
        return null;
    }

    /** Reverse of templating: substitute {user}/{pass} back to their literals to recover the original
     *  captured body — the IMMUTABLE source the field-mapping combos re-derive from. */
    public static String detemplatize(String template, String user, String pass) {
        if (template == null) return "";
        String out = template;
        if (user != null) out = out.replace("{user}", user);
        if (pass != null) out = out.replace("{pass}", pass);
        return out;
    }

    /**
     * Re-templatize {@code rawBody} from scratch for an explicit user/pass field choice: EVERY field keeps
     * its original raw value except {@code userKey}→{user} and {@code passKey}→{pass} (their literals go to
     * {@code creds[0]}/{@code creds[1]}). Because it ALWAYS starts from the untouched rawBody, switching one
     * mapping can never corrupt a previously-mapped field (e.g. the app-channel ExtUPassword secret being
     * overwritten with the user's password). JSON only.
     */
    public static String retemplatizeByKeys(String rawBody, String userKey, String passKey, String[] creds) {
        if (rawBody == null) return "";
        try {
            JSONObject o = new JSONObject(rawBody.trim());
            applyKeyMapping(o, userKey, passKey, creds);
            return o.toString();
        } catch (JSONException e) {
            return rawBody;
        }
    }

    private static void applyKeyMapping(JSONObject o, String userKey, String passKey, String[] creds) {
        for (Iterator<String> it = o.keys(); it.hasNext(); ) {
            String k = it.next();
            Object v = o.opt(k);
            if (v instanceof JSONObject) {
                applyKeyMapping((JSONObject) v, userKey, passKey, creds);
            } else if (!(v instanceof org.json.JSONArray)) {
                if (userKey != null && !userKey.isEmpty() && k.equalsIgnoreCase(userKey)) {
                    creds[0] = String.valueOf(v);
                    o.put(k, "{user}");
                } else if (passKey != null && !passKey.isEmpty() && k.equalsIgnoreCase(passKey)) {
                    creds[1] = String.valueOf(v);
                    o.put(k, "{pass}");
                }
            }
        }
    }

    private static String guessRole(String username) {
        if (username == null || username.trim().isEmpty()) return "user1";
        String u = username.trim();
        int at = u.indexOf('@');
        if (at > 0) u = u.substring(0, at);
        u = u.replaceAll("[^A-Za-z0-9._-]", "");
        if (u.isEmpty()) return "user1";
        return u.length() > 24 ? u.substring(0, 24) : u;
    }

    private static String bodyOf(byte[] msg, int bodyOffset) {
        if (msg == null || bodyOffset < 0 || bodyOffset >= msg.length) return "";
        return new String(msg, bodyOffset, msg.length - bodyOffset, StandardCharsets.UTF_8);
    }

    private static String headerValue(List<String> headers, String name) {
        if (headers == null) return null;
        String n = name.toLowerCase(Locale.ROOT) + ":";
        for (String h : headers) {
            if (h != null && h.toLowerCase(Locale.ROOT).startsWith(n)) {
                int c = h.indexOf(':');
                return c >= 0 ? h.substring(c + 1).trim() : "";
            }
        }
        return null;
    }
}
