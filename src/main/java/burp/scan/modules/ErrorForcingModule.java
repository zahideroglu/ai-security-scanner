package burp.scan.modules;

import burp.Finding;
import burp.IParameter;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.List;

/**
 * A05 / Information Disclosure (B02): sends malformed input (broken JSON,
 * boundary-violating multipart with an over-long header line, type-confusion,
 * overflow) to coax a verbose error, then flags any response that leaks a stack
 * trace, source path or framework internals (e.g. ASP.NET DeveloperExceptionPage).
 *
 * @author Zahid Eroglu
 */
public class ErrorForcingModule implements ScanModule {

    public String id() { return "errorforcing"; }
    public String displayName() { return "Error / Stack Trace Disclosure"; }
    public boolean isEnabled(Settings s) { return s.isModuleMisconfigEnabled(); }
    public boolean appliesTo(Baseline b) { return b.statusCode > 0; }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> p = new ArrayList<>();
        String ct = b.requestContentType == null ? "" : b.requestContentType.toLowerCase();
        if (b.requestBody != null && !b.requestBody.isEmpty()) {
            if (ct.contains("json")) {
                p.add(probe("Malformed JSON body", "{\"x\":"));
            } else if (ct.contains("multipart")) {
                // Proven trigger: a multipart header line > 100 chars makes ASP.NET's
                // MultipartReader throw "Line length limit 100 exceeded" -> 500 + trace.
                p.add(probe("Malformed multipart (long header line)", multipartLongLine(b.requestContentType)));
            } else {
                p.add(probe("Malformed body", "%%% {[}]"));
            }
        }
        // Type confusion (array where scalar expected) on existing inputs. (The numeric-overflow twin was
        // dropped to halve per-param traffic: it shared the SAME stack-trace/source-path judge oracle as
        // type-confusion, so it added a request per param with negligible extra detection.)
        for (IParameter par : b.injectableParams(4)) {
            p.add(new Probe(id(), "Type confusion " + par.getName(), "param",
                    par.getName(), "%5b%5d", "Information Disclosure", "High"));
        }
        return p;
    }

    private Probe probe(String desc, String body) {
        return new Probe(id(), desc, "body", "", body, "Information Disclosure", "High");
    }

    /** Multipart body whose section-header line exceeds the 100-char limit. */
    private String multipartLongLine(String contentType) {
        String boundary = extractBoundary(contentType);
        if (boundary == null) boundary = "----brokenBoundary";
        StringBuilder name = new StringBuilder();
        for (int i = 0; i < 150; i++) name.append('A');
        return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name
                + "\"\r\n\r\nv\r\n--" + boundary + "--\r\n";
    }

    private String extractBoundary(String contentType) {
        if (contentType == null) return null;
        int i = contentType.toLowerCase().indexOf("boundary=");
        if (i < 0) return null;
        String b = contentType.substring(i + 9).trim();
        int semi = b.indexOf(';');
        if (semi >= 0) b = b.substring(0, semi).trim();
        b = b.replace('"', ' ').trim();
        return b.isEmpty() ? null : b;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> f = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Information Disclosure".equals(r.probe.attackType)) continue;
            String body = r.bodySnippet;
            String trace = Signals.stackTraceLeak(body);
            String srcPath = Signals.sourcePathLeak(body);
            if (trace == null && srcPath == null) continue;
            String ev = (srcPath != null ? I18n.t("f.err.stacktrace.ev.srcpath", srcPath) : "")
                    + (trace != null ? I18n.t("f.err.stacktrace.ev.trace", trace) : "");
            // Stack-trace / source-path leakage is real information disclosure but NOT high-severity on
            // its own (no direct compromise) — report as Medium hygiene, not High.
            Finding finding = new Finding("Information Disclosure (Stack Trace)", "Medium", 0.9,
                    I18n.t("f.err.stacktrace.desc", r.probe.description, r.statusCode),
                    "", ev,
                    I18n.t("f.err.stacktrace.exp"),
                    I18n.t("f.err.stacktrace.rem"));
            finding.setHttpResponse(body != null && body.length() > 1500 ? body.substring(0, 1500) : body);
            finding.setCvssScore(5.3);
            f.add(finding);
            break; // one is enough per endpoint
        }
        return f;
    }
}
