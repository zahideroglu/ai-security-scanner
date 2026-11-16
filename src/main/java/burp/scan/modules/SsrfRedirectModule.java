package burp.scan.modules;

import burp.Finding;
import burp.IParameter;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A10 SSRF + Open Redirect. Open-redirect is non-intrusive (always on with the
 * module); active SSRF (localhost / cloud metadata) is intrusive and gated by
 * {@code ssrfActiveEnabled}.
 *
 * @author Zahid Eroglu
 */
public class SsrfRedirectModule implements ScanModule {

    private static final String EVIL = "https://evil.example/";
    private static final Set<String> URL_NAMES = new HashSet<>(Arrays.asList(
            "url", "next", "redirect", "redirect_uri", "redirecturl", "return", "returnurl",
            "return_url", "callback", "dest", "destination", "target", "to", "out", "view",
            "page", "host", "domain", "site", "feed", "u", "link", "img", "image", "file", "path"));

    public String id() { return "ssrf"; }
    public String displayName() { return "SSRF / Open Redirect"; }
    public boolean isEnabled(Settings s) { return s.isModuleSsrfRedirectEnabled(); }

    public boolean appliesTo(Baseline b) {
        for (IParameter p : b.parameters) {
            if (isUrlParam(p)) return true;
        }
        return false;
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        for (IParameter p : b.parameters) {
            if (!isUrlParam(p)) continue;
            String name = p.getName();
            // Open redirect (non-intrusive)
            probes.add(new Probe(id(), "Open redirect (" + name + ")", "param", name,
                    EVIL, "Open Redirect", "Medium"));
            probes.add(new Probe(id(), "Open redirect // (" + name + ")", "param", name,
                    "//evil.example", "Open Redirect", "Medium"));
            // Active SSRF (intrusive) — cloud-metadata only. (The http://127.0.0.1/ localhost probe was
            // dropped: judge() can only CONFIRM SSRF via EC2/GCP metadata response fields, which a loopback
            // fetch can never return — there is no OOB/timing/diff oracle — so it could never produce a
            // finding the metadata probe doesn't. Pure wasted request per URL-param.)
            if (s.isSsrfActiveEnabled()) {
                probes.add(new Probe(id(), "SSRF cloud metadata (" + name + ")", "param", name,
                        "http://169.254.169.254/latest/meta-data/", "SSRF", "High"));
            }
        }
        return probes;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok()) continue;
            String type = r.probe.attackType;

            if ("Open Redirect".equals(type)) {
                String hdrs = r.responseHeaders == null ? "" : r.responseHeaders.toLowerCase();
                if (r.statusCode >= 300 && r.statusCode < 400 && hdrs.contains("location:")
                        && hdrs.contains("evil.example")) {
                    Finding f = new Finding("Open Redirect", "Medium", 0.85,
                            I18n.t("f.ssrf.openredirect.desc", r.probe.targetParameter),
                            "", I18n.t("f.ssrf.openredirect.ev", r.probe.payload, r.statusCode),
                            I18n.t("f.ssrf.openredirect.exp"),
                            I18n.t("f.ssrf.openredirect.rem"));
                    f.setHttpResponse(r.bodySnippet);
                    findings.add(f);
                }
            } else if ("SSRF".equals(type)) {
                String body = r.bodySnippet == null ? "" : r.bodySnippet.toLowerCase();
                String payloadLower = r.probe.payload == null ? "" : r.probe.payload.toLowerCase();
                // FP guard: if the page merely REFLECTS our payload URL (e.g. a login page echoing
                // ?redirect=http://169.254.169.254/latest/meta-data/), its body contains "meta-data"
                // but no real metadata was fetched. Drop tokens that occur in the payload itself, and
                // require ACTUAL EC2/GCP metadata RESPONSE fields that never appear in the payload URL.
                boolean reflectedPayload = !payloadLower.isEmpty() && body.contains(payloadLower);
                boolean metadata = !reflectedPayload && (
                        body.contains("ami-id") || body.contains("instance-id") || body.contains("instance-action")
                        || body.contains("reservation-id") || body.contains("security-credentials")
                        || body.contains("\"accesskeyid\"") || body.contains("local-ipv4") || body.contains("public-ipv4")
                        || body.contains("iam/security-credentials") || body.contains("\"iam\":")
                        || body.contains("computemetadata") || body.contains("\"availabilityzone\""));
                if (metadata) {
                    Finding f = new Finding("SSRF", "High", 0.8,
                            I18n.t("f.ssrf.ssrf.desc", r.probe.targetParameter),
                            "", I18n.t("f.ssrf.ssrf.ev", r.probe.payload),
                            I18n.t("f.ssrf.ssrf.exp"),
                            I18n.t("f.ssrf.ssrf.rem"));
                    f.setHttpResponse(r.bodySnippet);
                    findings.add(f);
                }
            }
        }
        return findings;
    }

    private boolean isUrlParam(IParameter p) {
        byte t = p.getType();
        if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) return false;
        String n = p.getName().toLowerCase();
        if (URL_NAMES.contains(n)) return true;
        String v = p.getValue();
        return v != null && (v.startsWith("http://") || v.startsWith("https://") || v.startsWith("//"));
    }
}
