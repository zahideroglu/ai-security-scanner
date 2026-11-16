package burp.scan;

import java.util.regex.Pattern;

/**
 * Canonical endpoint key used to deduplicate proxy-history requests BEFORE they are
 * handed to the (expensive) AI engines.
 *
 * <p>Two requests that hit the same endpoint <em>template</em> — differing only in a
 * dynamic path segment such as a numeric id, UUID, hash or long opaque token — collapse
 * to one key. So the AI agent runs once per endpoint shape (e.g. {@code GET /accounts/{id}})
 * instead of once per concrete id ({@code /accounts/1001}, {@code /accounts/1002}, …),
 * which is the main source of duplicate AI work when scanning a busy proxy history.
 *
 * <p>The query string is intentionally ignored — callers already key on path only, and the
 * detection engines vary parameters themselves. Picking one representative concrete request
 * is enough; an IDOR/BOLA test does not need every observed id pre-seeded.
 *
 * @author Zahid Eroglu
 */
public final class EndpointKey {

    private EndpointKey() {
    }

    private static final Pattern UUID = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern DIGITS = Pattern.compile("^\\d+$");
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]{12,}$");
    private static final Pattern TOKEN = Pattern.compile("^[A-Za-z0-9_-]+$");

    /** The dedup identity ("{METHOD} {normalized-path}") shared across the AI-feeding paths. */
    public static String of(String method, String path) {
        return (method == null ? "" : method.toUpperCase()) + " " + normalizePath(path);
    }

    /** Replace dynamic path segments (ids, uuids, hashes, long opaque tokens) with {@code {id}}. */
    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) return "/";
        String[] segs = path.split("/", -1);
        StringBuilder sb = new StringBuilder(path.length());
        for (int i = 0; i < segs.length; i++) {
            if (i > 0) sb.append('/');
            sb.append(isDynamic(segs[i]) ? "{id}" : segs[i]);
        }
        String out = sb.toString();
        return out.isEmpty() ? "/" : out;
    }

    /** True when a single path segment looks like a per-resource identifier rather than a route name. */
    private static boolean isDynamic(String s) {
        if (s == null || s.isEmpty()) return false;
        if (DIGITS.matcher(s).matches()) return true;   // 1001, 42 — numeric id / version
        if (UUID.matcher(s).matches()) return true;     // canonical UUID
        if (HEX.matcher(s).matches()) return true;      // long hex object-id / hash
        // Long opaque token containing a digit (mongo/base64-ish id) — but not a normal route word.
        return s.length() >= 20 && hasDigit(s) && TOKEN.matcher(s).matches();
    }

    private static boolean hasDigit(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isDigit(s.charAt(i))) return true;
        }
        return false;
    }
}
