package burp.report;

import burp.i18n.I18n;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Serialises a finding's {@link ReproStep} reproduction bundle into developer-replayable formats:
 * annotated {@code curl} commands, a HAR 1.2 document, or a plain request/response dump. Pure
 * re-serialisation of already-captured transactions — it never sends anything.
 *
 * @author Zahid Eroglu
 */
public final class ReproExporter {

    private ReproExporter() {}

    /** Localised one-line label for a step role (TR/EN follows the app language). */
    public static String roleLabel(ReproStep.Role role) {
        switch (role) {
            case OWN:     return I18n.t("repro.role.own");
            case ATTACK:  return I18n.t("repro.role.attack");
            case CONTROL: return I18n.t("repro.role.control");
            case PUBLIC:  return I18n.t("repro.role.public");
            case VICTIM:  return I18n.t("repro.role.victim");
            default:      return role.name();
        }
    }

    // ---------------------------------------------------------------- curl

    /** All steps as annotated {@code curl} commands, one block per transaction. */
    public static String toCurl(List<ReproStep> steps) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(I18n.t("repro.curl.header")).append("\n\n");
        int i = 1;
        for (ReproStep s : steps) {
            sb.append("# [").append(i++).append("] ").append(roleLabel(s.getRole()));
            if (!s.getDetail().isEmpty()) sb.append("  (").append(s.getDetail()).append(")");
            sb.append("\n");
            sb.append(curlFor(s)).append("\n\n");
        }
        return sb.toString().trim() + "\n";
    }

    /** Build a single {@code curl} command from one step's raw request bytes. */
    private static String curlFor(ReproStep s) {
        Parsed p = parse(s.requestText());
        if (p == null) return "# (request unavailable)";
        String scheme = s.isHttps() ? "https" : "http";
        boolean defaultPort = (s.isHttps() && s.getPort() == 443) || (!s.isHttps() && s.getPort() == 80) || s.getPort() <= 0;
        String authority = s.getHost() + (defaultPort ? "" : ":" + s.getPort());
        StringBuilder c = new StringBuilder("curl -k -i");
        if (!"GET".equalsIgnoreCase(p.method)) c.append(" -X ").append(p.method);
        for (String[] h : p.headers) {
            String name = h[0];
            String ln = name.toLowerCase();
            if (ln.equals("host") || ln.equals("content-length") || ln.equals("connection")) continue;
            c.append(" \\\n  -H ").append(shellQuote(name + ": " + h[1]));
        }
        if (p.body != null && !p.body.isEmpty()) {
            c.append(" \\\n  --data-binary ").append(shellQuote(p.body));
        }
        c.append(" \\\n  ").append(shellQuote(scheme + "://" + authority + p.path));
        return c.toString();
    }

    // ---------------------------------------------------------------- HAR 1.2

    /** All steps as a HAR 1.2 document (importable into Burp, browsers, Postman, etc.). */
    public static String toHar(List<ReproStep> steps) {
        JSONObject log = new JSONObject();
        log.put("version", "1.2");
        log.put("creator", new JSONObject().put("name", "AppSecHunter").put("version", "repro-bundle"));
        JSONArray entries = new JSONArray();
        for (ReproStep s : steps) {
            Parsed p = parse(s.requestText());
            if (p == null) continue;
            String scheme = s.isHttps() ? "https" : "http";
            boolean defaultPort = (s.isHttps() && s.getPort() == 443) || (!s.isHttps() && s.getPort() == 80) || s.getPort() <= 0;
            String authority = s.getHost() + (defaultPort ? "" : ":" + s.getPort());
            String url = scheme + "://" + authority + p.path;

            JSONObject req = new JSONObject();
            req.put("method", p.method);
            req.put("url", url);
            req.put("httpVersion", p.httpVersion);
            JSONArray reqHeaders = new JSONArray();
            for (String[] h : p.headers) reqHeaders.put(new JSONObject().put("name", h[0]).put("value", h[1]));
            req.put("headers", reqHeaders);
            req.put("queryString", new JSONArray());
            req.put("cookies", new JSONArray());
            req.put("headersSize", -1);
            if (p.body != null && !p.body.isEmpty()) {
                req.put("postData", new JSONObject().put("mimeType", p.contentType()).put("text", p.body));
                req.put("bodySize", p.body.length());
            } else {
                req.put("bodySize", 0);
            }

            JSONObject resp = harResponse(s);

            JSONObject entry = new JSONObject();
            entry.put("comment", roleLabel(s.getRole()) + (s.getDetail().isEmpty() ? "" : " — " + s.getDetail()));
            entry.put("startedDateTime", "1970-01-01T00:00:00.000Z");
            entry.put("time", 0);
            entry.put("request", req);
            entry.put("response", resp);
            entry.put("cache", new JSONObject());
            entry.put("timings", new JSONObject().put("send", 0).put("wait", 0).put("receive", 0));
            entries.put(entry);
        }
        log.put("entries", entries);
        return new JSONObject().put("log", log).toString(2);
    }

    private static JSONObject harResponse(ReproStep s) {
        JSONObject resp = new JSONObject();
        String text = s.responseText();
        Parsed rp = (text.isEmpty()) ? null : parseResponse(text);
        if (rp == null) {
            resp.put("status", 0);
            resp.put("statusText", "");
            resp.put("httpVersion", "HTTP/1.1");
            resp.put("headers", new JSONArray());
            resp.put("content", new JSONObject().put("size", 0).put("mimeType", "").put("text", ""));
        } else {
            resp.put("status", rp.status);
            resp.put("statusText", rp.statusText);
            resp.put("httpVersion", rp.httpVersion);
            JSONArray headers = new JSONArray();
            for (String[] h : rp.headers) headers.put(new JSONObject().put("name", h[0]).put("value", h[1]));
            resp.put("headers", headers);
            String body = rp.body == null ? "" : rp.body;
            resp.put("content", new JSONObject().put("size", body.length())
                    .put("mimeType", rp.contentType()).put("text", body));
        }
        resp.put("redirectURL", "");
        resp.put("cookies", new JSONArray());
        resp.put("headersSize", -1);
        resp.put("bodySize", -1);
        return resp;
    }

    // ---------------------------------------------------------------- plain text

    /** A readable request+response dump of every step, for the clipboard or a bug report. */
    public static String toText(List<ReproStep> steps) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(I18n.t("repro.text.header")).append(" ===\n\n");
        int i = 1;
        for (ReproStep s : steps) {
            sb.append("----- [").append(i++).append("] ").append(roleLabel(s.getRole()));
            if (!s.getDetail().isEmpty()) sb.append("  (").append(s.getDetail()).append(")");
            sb.append(" -----\n");
            sb.append("> ").append(I18n.t("repro.text.request")).append("\n");
            sb.append(trim(s.requestText(), 8192)).append("\n\n");
            String resp = s.responseText();
            if (!resp.isEmpty()) {
                sb.append("< ").append(I18n.t("repro.text.response")).append("\n");
                sb.append(trim(resp, 8192)).append("\n\n");
            }
        }
        return sb.toString();
    }

    private static String trim(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n…(" + (s.length() - max) + " more bytes)";
    }

    // ---------------------------------------------------------------- HTTP parsing

    /** Minimal parsed HTTP message (request or response). */
    private static final class Parsed {
        String method = "GET", path = "/", httpVersion = "HTTP/1.1";
        int status; String statusText = "";
        final java.util.List<String[]> headers = new java.util.ArrayList<>();
        String body;
        String contentType() {
            for (String[] h : headers) if (h[0].equalsIgnoreCase("content-type")) return h[1];
            return "application/octet-stream";
        }
    }

    private static Parsed parse(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            int split = indexOfBlankLine(raw);
            String head = split < 0 ? raw : raw.substring(0, split);
            String body = split < 0 ? null : raw.substring(split).replaceFirst("^(\\r?\\n){2}", "");
            String[] lines = head.split("\r\n|\n");
            if (lines.length == 0) return null;
            Parsed p = new Parsed();
            String[] first = lines[0].split(" ", 3);
            if (first.length >= 2) {
                p.method = first[0];
                p.path = first[1];
                if (first.length >= 3) p.httpVersion = first[2];
            }
            for (int i = 1; i < lines.length; i++) {
                int c = lines[i].indexOf(':');
                if (c > 0) p.headers.add(new String[]{lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim()});
            }
            p.body = (body != null && !body.isEmpty()) ? body : null;
            return p;
        } catch (Exception e) {
            return null;
        }
    }

    private static Parsed parseResponse(String raw) {
        if (raw == null || raw.isEmpty()) return null;
        try {
            int split = indexOfBlankLine(raw);
            String head = split < 0 ? raw : raw.substring(0, split);
            String body = split < 0 ? null : raw.substring(split).replaceFirst("^(\\r?\\n){2}", "");
            String[] lines = head.split("\r\n|\n");
            if (lines.length == 0) return null;
            Parsed p = new Parsed();
            String[] first = lines[0].split(" ", 3);
            if (first.length >= 2) {
                p.httpVersion = first[0];
                try { p.status = Integer.parseInt(first[1]); } catch (Exception ignore) {}
                if (first.length >= 3) p.statusText = first[2];
            }
            for (int i = 1; i < lines.length; i++) {
                int c = lines[i].indexOf(':');
                if (c > 0) p.headers.add(new String[]{lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim()});
            }
            p.body = (body != null && !body.isEmpty()) ? body : null;
            return p;
        } catch (Exception e) {
            return null;
        }
    }

    /** Offset of the CRLFCRLF / LFLF separating headers from body, or -1. */
    private static int indexOfBlankLine(String s) {
        int a = s.indexOf("\r\n\r\n");
        int b = s.indexOf("\n\n");
        if (a < 0) return b;
        if (b < 0) return a;
        return Math.min(a, b);
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }
}
