package burp.authz;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result model for the authorization matrix: one {@link Row} per endpoint, one
 * {@link Cell} per role (incl. anonymous), plus the list of detected access-control
 * {@link Violation}s. Renders to text / CSV / HTML for the panel and report.
 *
 * @author Zahid Eroglu
 */
public class AuthMatrix {

    public enum Verdict { GRANTED, DENIED, ERROR }

    /** One role's result against one endpoint. */
    public static class Cell {
        public Verdict verdict = Verdict.ERROR;
        public int status;
        public int length;
        public String bodySnippet = ""; // first ~2KB of body (for AI BOLA comparison)

        public Cell() {}
        public Cell(Verdict v, int status, int length) {
            this.verdict = v; this.status = status; this.length = length;
        }
    }

    /** One endpoint and its per-role cells. */
    public static class Row {
        public String method;
        public String path;
        public String url;
        public boolean hasResourceId;
        public IHttpRequestResponse base; // the original request (for finding evidence)
        public Map<String, Cell> byRole = new LinkedHashMap<>(); // roleName -> cell

        public Row(String method, String path, String url, boolean hasResourceId) {
            this.method = method; this.path = path; this.url = url; this.hasResourceId = hasResourceId;
        }

        public Cell cell(String role) { return byRole.get(role); }
    }

    /** A detected access-control violation (becomes a Finding). */
    public static class Violation {
        public String type;
        public String severity;
        public double confidence;
        public String endpoint;  // method + path
        public String url;
        public String evidence;
        public String description;
        public String remediation;
        public IHttpRequestResponse base;
        public String baselineBody;     // V3/BOLA: first identity's response body (for AI compare)
        public String manipulatedBody;  // V3/BOLA: second identity's response body
        public String controlBody;      // V3/BOLA: negative control (anonymous body) — endpoint ignores identity?
    }

    public final List<String> roles = new ArrayList<>();   // ordered; "anonymous" first
    public final List<Row> rows = new ArrayList<>();
    public final List<Violation> violations = new ArrayList<>();

    private static String v(Cell c) {
        if (c == null || c.verdict == Verdict.ERROR) return "ERR";
        return (c.verdict == Verdict.GRANTED ? "GRANT " : "deny  ") + c.status;
    }

    /** Compact text grid for the live log. */
    public String renderText() {
        StringBuilder sb = new StringBuilder();
        sb.append("ROLE × ENDPOINT MATRIX  (").append(rows.size()).append(" endpoint × ")
          .append(roles.size()).append(" role)\n");
        for (Row r : rows) {
            sb.append(String.format("%-6s %-40s", r.method, trunc(r.path, 40)));
            for (String role : roles) sb.append(" | ").append(v(r.cell(role)));
            sb.append("\n");
        }
        if (!violations.isEmpty()) {
            sb.append("\nVIOLATIONS (").append(violations.size()).append("):\n");
            for (Violation vi : violations) {
                sb.append("  [").append(vi.severity).append("] ").append(vi.type)
                  .append(" — ").append(vi.endpoint).append("  (").append(vi.evidence).append(")\n");
            }
        }
        return sb.toString();
    }

    public String renderCsv() {
        StringBuilder sb = new StringBuilder("method,path");
        for (String role : roles) sb.append(",").append(csv(role));
        sb.append("\n");
        for (Row r : rows) {
            sb.append(csv(r.method)).append(",").append(csv(r.path));
            for (String role : roles) {
                Cell c = r.cell(role);
                sb.append(",").append(c == null ? "ERR" : c.verdict + ":" + c.status);
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public String renderHtml() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><meta charset='utf-8'><style>")
          .append("body{font-family:Segoe UI,Arial,sans-serif;font-size:13px}")
          .append("table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:center}")
          .append("th{background:#263238;color:#fff}.m{text-align:left;font-family:monospace}")
          .append(".g{background:#c8e6c9}.d{background:#ffcdd2}.e{background:#eeeeee;color:#888}")
          .append("</style></head><body>");
        sb.append("<h3>Authorization Matrix — ").append(rows.size()).append(" endpoint × ")
          .append(roles.size()).append(" role</h3><table><tr><th>Method</th><th>Path</th>");
        for (String role : roles) sb.append("<th>").append(esc(role)).append("</th>");
        sb.append("</tr>");
        for (Row r : rows) {
            sb.append("<tr><td class='m'>").append(esc(r.method)).append("</td><td class='m'>")
              .append(esc(r.path)).append("</td>");
            for (String role : roles) {
                Cell c = r.cell(role);
                String cls = c == null || c.verdict == Verdict.ERROR ? "e"
                        : (c.verdict == Verdict.GRANTED ? "g" : "d");
                sb.append("<td class='").append(cls).append("'>").append(c == null ? "—" : c.status).append("</td>");
            }
            sb.append("</tr>");
        }
        sb.append("</table>");
        if (!violations.isEmpty()) {
            sb.append("<h3>Violations (").append(violations.size()).append(")</h3><ul>");
            for (Violation vi : violations) {
                sb.append("<li><b>[").append(esc(vi.severity)).append("] ").append(esc(vi.type))
                  .append("</b> — ").append(esc(vi.endpoint)).append("<br><i>").append(esc(vi.evidence))
                  .append("</i></li>");
            }
            sb.append("</ul>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }
    private static String csv(String s) {
        if (s == null) return "";
        return s.contains(",") || s.contains("\"") ? "\"" + s.replace("\"", "\"\"") + "\"" : s;
    }
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
