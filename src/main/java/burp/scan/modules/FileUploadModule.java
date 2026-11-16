package burp.scan.modules;

import burp.Finding;
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
 * A04/A05 Unrestricted File Upload. INTRUSIVE (off by default). Re-submits the
 * original multipart body with the uploaded filename swapped to a dangerous
 * extension; flags acceptance (heuristic - marked for manual verification).
 *
 * @author Zahid Eroglu
 */
public class FileUploadModule implements ScanModule {

    public String id() { return "upload"; }
    public String displayName() { return "File Upload (intrusive)"; }
    public boolean isEnabled(Settings s) { return s.isFileUploadTestEnabled(); }

    public boolean appliesTo(Baseline b) {
        String ct = b.requestContentType == null ? "" : b.requestContentType.toLowerCase();
        return ct.contains("multipart/form-data")
                && b.requestBody != null && b.requestBody.contains("filename=");
    }

    // Unique marker stem embedded in both the filename and the file content, so a reflected stored
    // filename/URL in the response confirms a retrieval path (single round-trip, no follow-up fetch).
    private static final String MARK = "mkup7q3z";

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        addUpload(probes, b, MARK + "a.php");
        addUpload(probes, b, MARK + "b.png.php");
        addUpload(probes, b, MARK + "c.svg");
        return probes;
    }

    private void addUpload(List<Probe> probes, Baseline b, String newName) {
        String body = replaceFirstFilename(b.requestBody, newName);
        if (body != null) {
            // location "body" replaces the whole request body (boundary preserved).
            Probe p = new Probe(id(), "Upload " + newName, "body", "", body, "File Upload", "High");
            p.tag = newName;
            probes.add(p);
        }
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"File Upload".equals(r.probe.attackType)) continue;
            String raw = r.bodySnippet == null ? "" : r.bodySnippet;
            String body = raw.toLowerCase();
            // A WAF/deny page means the upload demonstrably did NOT succeed → suppress.
            if (Signals.looksLikeBlockPage(raw)) continue;
            boolean rejected = body.contains("not allowed") || body.contains("invalid file")
                    || body.contains("unsupported") || body.contains("forbidden")
                    || body.contains("file type") || r.statusCode == 415;
            if (r.statusCode == 400) continue;           // generic malformed-multipart, not proof either way
            if ((r.statusCode != 200 && r.statusCode != 201) || rejected) continue;

            // Confirmation tiers: did the response leak our marker (filename / stored URL)? That proves a
            // retrieval path (execution still unproven). A bare 200 that is structurally identical to the
            // safe baseline (which already returned 200) is NOT evidence — downgrade to an unconfirmed Low.
            String markStem = r.probe.tag == null ? MARK : String.valueOf(r.probe.tag);
            boolean reflected = body.contains(MARK) || (markStem != null && body.contains(markStem.toLowerCase()));

            // Accepting a dangerous, server-executable extension (where the safe baseline used a normal name)
            // IS the finding. Reflection of the marker proves a retrieval path → High; otherwise the
            // acceptance is a real Medium that needs manual confirmation of storage/execution — NOT a Low.
            String sev; double conf;
            if (reflected) { sev = "High"; conf = 0.7; }
            else { sev = "Medium"; conf = 0.5; }

            String desc = reflected
                    ? I18n.t("f.upl.unrestricted.desc.reflected", r.statusCode)
                    : I18n.t("f.upl.unrestricted.desc.unconfirmed", r.statusCode);
            Finding f = new Finding("Unrestricted File Upload" + (reflected ? "" : " (unconfirmed)"), sev, conf,
                    desc,
                    "", I18n.t("f.upl.unrestricted.ev", r.statusCode, reflected ? I18n.t("f.upl.unrestricted.ev.marker") : ""),
                    I18n.t("f.upl.unrestricted.exp"),
                    I18n.t("f.upl.unrestricted.rem"));
            f.setHttpResponse(r.bodySnippet);
            if (!reflected) f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            findings.add(f);
        }
        return findings;
    }

    /** Replace the first multipart filename="..." with the given name. */
    private String replaceFirstFilename(String body, String newName) {
        if (body == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("filename=\"[^\"]*\"").matcher(body);
        if (!m.find()) return null;
        return body.substring(0, m.start()) + "filename=\"" + newName + "\"" + body.substring(m.end());
    }
}
