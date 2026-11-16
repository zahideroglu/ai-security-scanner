package burp.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Shared deterministic detection signals (no AI). Centralizes the SQL/error/
 * header heuristics previously scattered in ResponseAnalyzer + ScanManager.
 *
 * @author Zahid Eroglu
 */
public final class Signals {

    private Signals() {}

    private static final Pattern SQL_ERROR = Pattern.compile(
            "(you have an error in your sql syntax|warning:\\s*mysql|mysql_fetch|mysqli|"
            + "unclosed quotation mark|quoted string not properly terminated|"
            + "ora-\\d{5}|pg::|postgresql.*error|sqlite/jdbcdriver|sqlite3::|"
            + "odbc sql server driver|microsoft ole db provider for sql server|"
            + "syntax error at or near)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PASSWD = Pattern.compile("root:.*:0:0:");

    /** Returns true if the body contains a SQL error signature. */
    public static boolean hasSqlError(String body) {
        return body != null && SQL_ERROR.matcher(body).find();
    }

    /** Returns true if body looks like /etc/passwd content. */
    public static boolean hasPasswdContent(String body) {
        return body != null && PASSWD.matcher(body).find();
    }

    // ---- WAF / block / generic-error page detection (shared FP killer) ----
    // A WAF or load-balancer commonly answers suspicious paths/params with a short, generic
    // "access denied / request blocked" page (often HTTP 200). Treating that page as real
    // content was the #1 source of false "exposed file", "hidden parameter" and "access" findings.
    // Deliberately CONSERVATIVE: only explicit deny/block wording. Bare vendor names (cloudflare/akamai/…)
    // and generic "reference id/incident id" were removed — a normal page that merely loads a
    // cdnjs.cloudflare.com asset or returns a tracking "Reference #" on success would otherwise be
    // mistaken for a block page, silently DROPPING real findings (the worst kind of regression).
    private static final Pattern BLOCK_PAGE = Pattern.compile(
            "(access denied|request (was |has been )?(blocked|rejected|denied)|the requested url was rejected|"
            + "this request (has been|was) blocked|web application firewall|mod_?security|"
            + "blocked by (our|the|your) (security|firewall|waf|network)|denied by (policy|the waf)|"
            + "you (don'?t|do not) have permission to access|not authorized to (view|access) this (page|resource)|"
            + "your (request|ip address)( has been| was| is)? (blocked|flagged|banned)|"
            + "attention required|error 1020|cf-ray|secure entry server|©\\s*citrix|"
            + "this website is using a security service to protect|"
            + "potentially (dangerous|malicious) (request|content|input))",
            Pattern.CASE_INSENSITIVE);

    /**
     * Heuristic: does this look like a WAF/block/generic-deny page rather than the real
     * application content the caller asked for? Used to suppress findings that merely
     * triggered a block page. Conservative — only matches explicit block/deny wording.
     */
    public static boolean looksLikeBlockPage(String body) {
        return body != null && BLOCK_PAGE.matcher(body).find();
    }

    /**
     * Image / font / audio / video only. Use this (NOT {@link #isBinaryOrImageType}) for access-control
     * decisions: a chart/avatar image is public, but a PDF/ZIP/octet-stream export CAN be sensitive
     * user data — excluding those from authz checks would hide real exposures.
     */
    public static boolean isImageOrMediaType(String contentTypeOrMime) {
        if (contentTypeOrMime == null) return false;
        String t = contentTypeOrMime.toLowerCase();
        return t.contains("image/") || t.equals("image") || t.contains("font/") || t.contains("/font")
                || t.contains("application/font") || t.contains("video/") || t.contains("audio/")
                || t.equals("png") || t.equals("jpeg") || t.equals("gif") || t.equals("svg");
    }

    /** True if a Content-Type / inferred-mime string denotes an image or opaque binary (not a JSON/HTML object). */
    public static boolean isBinaryOrImageType(String contentTypeOrMime) {
        if (contentTypeOrMime == null) return false;
        String t = contentTypeOrMime.toLowerCase();
        return t.contains("image/") || t.equals("image") || t.contains("application/octet-stream")
                || t.contains("application/pdf") || t.contains("video/") || t.contains("audio/")
                || t.contains("font/") || t.contains("application/zip") || t.contains("application/x-")
                || t.contains("charset=binary");
    }

    /** Content-Type value from a joined ("\n"-separated) header blob, lower-cased, or "" . */
    public static String contentTypeOf(String joinedHeaders) {
        if (joinedHeaders == null) return "";
        for (String line : joinedHeaders.split("\n")) {
            String l = line.trim().toLowerCase();
            if (l.startsWith("content-type:")) return l.substring(13).trim();
        }
        return "";
    }

    /** Raw (unencoded) reflection of the payload in the body. */
    public static boolean reflectsRaw(String body, String payload) {
        return body != null && payload != null && !payload.isEmpty()
                && body.contains(payload);
    }

    /**
     * Reflection of an XSS payload in an EXECUTABLE markup context — not inside a quoted string
     * value (JSON/attribute) and not inside a data {@code <script type="application/json">} island
     * (e.g. Next.js {@code __NEXT_DATA__}). A raw {@code <svg/onload=1>} echoed into a JSON blob is
     * non-executable and was a recurring false High; this gate keeps only genuinely renderable hits.
     */
    public static boolean reflectsExecutableXss(String body, String payload) {
        if (body == null || payload == null || payload.isEmpty()) return false;
        int idx = body.indexOf(payload);
        while (idx >= 0) {
            if (isExecutableContext(body, idx)) return true;
            idx = body.indexOf(payload, idx + 1);
        }
        return false;
    }

    private static boolean isExecutableContext(String body, int idx) {
        // Immediately preceded by a backslash → JSON/JS-escaped, not markup. (We do NOT exclude a
        // preceding quote: our payload is self-contained markup — `<svg/onload=1>` opens a new tag and
        // executes even when echoed as page text like: You searched for "zxq7m<svg/onload=1>".)
        char before = idx > 0 ? body.charAt(idx - 1) : ' ';
        if (before == '\\') return false;
        // Inside an open data <script ...type="application/json"/__NEXT_DATA__/ld+json/template> block → not executable.
        int scriptOpen = lastIndexOfIgnoreCase(body, "<script", idx);
        if (scriptOpen >= 0) {
            int scriptClose = lastIndexOfIgnoreCase(body, "</script", idx);
            if (scriptClose < scriptOpen) {
                int tagEnd = body.indexOf('>', scriptOpen);
                String tag = (tagEnd > scriptOpen ? body.substring(scriptOpen, tagEnd) : "").toLowerCase();
                if (tag.contains("application/json") || tag.contains("__next_data__")
                        || tag.contains("application/ld+json") || tag.contains("text/template")
                        || tag.contains("text/x-template")) {
                    return false;
                }
            }
        }
        return true;
    }

    private static int lastIndexOfIgnoreCase(String hay, String needle, int from) {
        return hay.toLowerCase().lastIndexOf(needle.toLowerCase(), from);
    }

    public static double lengthDeltaRatio(int baseLen, int len) {
        int max = Math.max(baseLen, len);
        if (max == 0) return 0.0;
        return Math.abs(baseLen - len) / (double) max;
    }

    /** Header present (case-insensitive, "name:" prefix). */
    public static boolean hasHeader(List<String> headers, String name) {
        if (headers == null) return false;
        String n = name.toLowerCase() + ":";
        for (String h : headers) {
            if (h.toLowerCase().startsWith(n)) return true;
        }
        return false;
    }

    public static String headerValue(List<String> headers, String name) {
        if (headers == null) return null;
        String n = name.toLowerCase() + ":";
        for (String h : headers) {
            if (h.toLowerCase().startsWith(n)) {
                int c = h.indexOf(':');
                return c >= 0 ? h.substring(c + 1).trim() : "";
            }
        }
        return null;
    }

    /** Security headers that are MISSING from the response. */
    public static List<String> missingSecurityHeaders(List<String> headers) {
        List<String> missing = new ArrayList<>();
        String[] required = {
                "Content-Security-Policy", "X-Frame-Options",
                "Strict-Transport-Security", "X-Content-Type-Options"
        };
        for (String r : required) {
            if (!hasHeader(headers, r)) missing.add(r);
        }
        return missing;
    }

    /** Server banner with a version number, if disclosed. */
    public static String serverBanner(List<String> headers) {
        String s = headerValue(headers, "Server");
        if (s != null && s.matches(".*\\d+\\.\\d+.*")) return s;
        return null;
    }

    public static String poweredBy(List<String> headers) {
        return headerValue(headers, "X-Powered-By");
    }

    // ---- Stack-trace / verbose-error / source-path leakage (B02) ----
    private static final Pattern STACK_TRACE = Pattern.compile(
            "(system\\.[a-z][a-z0-9.]*exception|\\bat [\\w.$<>]+\\([^)]*\\)|:line \\d+|"
            + "microsoft\\.aspnetcore|developerexceptionpage|\\bstacktrace\\b|"
            + "traceback \\(most recent call last\\)|org\\.springframework|"
            + "java\\.lang\\.[a-z]+exception|exception in thread|undefined index|"
            + "fatal error:|warning:[^\\n]*on line \\d+|invaliddataexception)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SRC_PATH = Pattern.compile(
            "([a-z]:\\\\[\\w\\\\.@ -]*\\\\(?:repos|source|src|inetpub|wwwroot|projects)[\\w\\\\.@ -]*"
            + "|/(?:home|var|usr|opt|app|srv|www)/[\\w./@ -]+\\.(?:cs|java|py|rb|php|go|ts|js))",
            Pattern.CASE_INSENSITIVE);

    /** Short evidence snippet if the body leaks a stack trace / exception, else null. */
    public static String stackTraceLeak(String body) {
        if (body == null) return null;
        java.util.regex.Matcher m = STACK_TRACE.matcher(body);
        if (m.find()) return snippet(body, m.start());
        return null;
    }

    /** A leaked absolute source path if present, else null. */
    public static String sourcePathLeak(String body) {
        if (body == null) return null;
        java.util.regex.Matcher m = SRC_PATH.matcher(body);
        if (m.find()) {
            String g = m.group(1);
            return g.length() > 160 ? g.substring(0, 160) : g;
        }
        return null;
    }

    private static String snippet(String body, int at) {
        int s = Math.max(0, at - 20);
        int e = Math.min(body.length(), at + 180);
        return body.substring(s, e).replaceAll("\\s+", " ").trim();
    }

    // ---- Installed component (Umbraco /App_Plugins/ etc.) enumeration (B05/B08) ----
    private static final Pattern APP_PLUGIN = Pattern.compile(
            "/App_Plugins/([A-Za-z0-9_.-]+)", Pattern.CASE_INSENSITIVE);

    /** Distinct plugin/component names referenced under /App_Plugins/ in the body. */
    public static java.util.Set<String> appPluginRefs(String body) {
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        if (body == null) return out;
        java.util.regex.Matcher m = APP_PLUGIN.matcher(body);
        while (m.find()) {
            out.add(m.group(1));
            if (out.size() >= 30) break;
        }
        return out;
    }
}
