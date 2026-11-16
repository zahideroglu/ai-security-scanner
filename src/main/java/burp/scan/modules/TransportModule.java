package burp.scan.modules;

import burp.Finding;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.RequestKit;
import burp.scan.ScanModule;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.List;

/**
 * A02 Cryptographic Failures (B04): missing HTTP -> HTTPS redirect. Re-requests
 * the site root over plain HTTP on port 80 and flags a 2xx response (full content
 * served without redirecting to HTTPS). Host-level: runs only on an HTTPS root.
 *
 * @author Zahid Eroglu
 */
public class TransportModule implements ScanModule {

    public String id() { return "transport"; }
    public String displayName() { return "Transport Security (HTTP->HTTPS)"; }
    public boolean isEnabled(Settings s) { return s.isModuleMisconfigEnabled(); }

    public boolean appliesTo(Baseline b) {
        return b.statusCode > 0 && b.helpers != null && (b.singleRequestScan || isRoot(b.path)) && isHttps(b);
    }

    private boolean isRoot(String p) { return p == null || p.isEmpty() || p.equals("/"); }

    private boolean isHttps(Baseline b) {
        try {
            return b.base != null && b.base.getHttpService() != null
                    && "https".equalsIgnoreCase(b.base.getHttpService().getProtocol());
        } catch (Exception e) {
            return false;
        }
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> p = new ArrayList<>();
        byte[] raw = RequestKit.minimalGet(b.helpers, b.host, "/");
        if (raw == null) return p;
        Probe pr = new Probe(id(), "HTTP port-80 downgrade check", "raw", "http80", "", "Transport Security", "Low");
        pr.rawRequest = raw;
        pr.overrideService = b.helpers.buildHttpService(b.host, 80, false); // false = plain HTTP
        p.add(pr);
        return p;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> f = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Transport Security".equals(r.probe.attackType)) continue;
            int sc = r.statusCode;
            // 2xx on port 80 = content served without forcing HTTPS. 3xx-to-https or a
            // connection error (port closed) are both fine and produce no finding.
            if (sc < 200 || sc >= 300) continue;
            // FP guards: a tiny fixed stub (e.g. a constant 746b landing/redirect page) or a WAF/deny
            // interstitial on port 80 is NOT "the full site served over HTTP". Require a real, content-
            // bearing body roughly comparable to the HTTPS baseline before flagging.
            if (r.responseLength < 1024) continue;
            if (b.responseLength > 0 && r.responseLength < b.responseLength * 0.5) continue;
            if (Signals.looksLikeBlockPage(r.bodySnippet)) continue;

            // Missing HTTP->HTTPS redirect is an industry-standard Low. If the HTTPS root already sets
            // HSTS (esp. preload), browsers refuse plain HTTP anyway → de-prioritise further.
            String hsts = Signals.headerValue(b.responseHeaders, "Strict-Transport-Security");
            double conf = hsts != null ? 0.35 : 0.55;
            String hstsNote = hsts != null ? " " + I18n.t("f.trans.downgrade.desc.hsts", hsts) : "";
            f.add(new Finding("Transport Security Misconfiguration", "Low", conf,
                    I18n.t("f.trans.downgrade.desc", sc) + hstsNote,
                    "", "http://" + b.host + "/ -> HTTP " + sc + " · " + r.responseLength
                            + I18n.t("f.trans.downgrade.ev.noredir") + (hsts != null ? " · " + I18n.t("f.trans.downgrade.ev.hsts") : ""),
                    I18n.t("f.trans.downgrade.exp", b.host),
                    I18n.t("f.trans.downgrade.rem")));
        }
        return f;
    }
}
