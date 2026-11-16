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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A05 Security Misconfiguration (B05 + B08): probes a small curated set of
 * sensitive admin/management/config paths anonymously and flags those publicly
 * reachable, and enumerates installed components from /App_Plugins/ references in
 * page source (Umbraco-style plugin disclosure). Host-level: runs on the root.
 *
 * @author Zahid Eroglu
 */
public class ContentDiscoveryModule implements ScanModule {

    // High-signal secret/config/management paths only. The low-signal CMS/swagger login probes
    // (/umbraco*, /administrator, /admin/login, /swagger*, /api/swagger.json, /wp-login.php,
    // /.well-known/security.txt) were dropped: they are redundant with ForcedBrowser's wordlist and
    // Burp's native content discovery, and yielded mostly Low/Info noise. Umbraco plugin disclosure is
    // still detected from the page source (Signals.appPluginRefs), independent of probing /umbraco.
    private static final String[] PATHS = {
            "/admin", "/.git/config", "/.env", "/server-status",
            "/actuator", "/actuator/health", "/phpmyadmin"
    };

    public String id() { return "contentdisco"; }
    public String displayName() { return "Content & Component Discovery"; }
    public boolean isEnabled(Settings s) { return s.isModuleMisconfigEnabled(); }

    public boolean appliesTo(Baseline b) {
        return b.statusCode > 0 && b.helpers != null && (b.singleRequestScan || isRoot(b.path));
    }
    private boolean isRoot(String p) { return p == null || p.isEmpty() || p.equals("/"); }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> p = new ArrayList<>();
        for (String path : PATHS) {
            byte[] raw = RequestKit.minimalGet(b.helpers, b.host, path);
            if (raw == null) continue;
            Probe pr = new Probe(id(), "Discover " + path, "raw", path, "", "Content Discovery", "Low");
            pr.rawRequest = raw;
            p.add(pr);
        }
        return p;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> f = new ArrayList<>();
        Set<String> plugins = new LinkedHashSet<>(Signals.appPluginRefs(b.bodySnippet));

        // Cluster 200-hits by body length: a length shared by >= 3 different sensitive paths is a
        // template (WAF block / generic error / login wall), NOT three exposed admin panels.
        // This kills the "all sensitive paths return the same 1029-byte block page" false positives.
        java.util.Map<Integer, Integer> lenFreq = new java.util.HashMap<>();
        for (ProbeResult r : results) {
            if (r.probe != null && r.ok() && "Content Discovery".equals(r.probe.attackType) && r.statusCode == 200) {
                lenFreq.merge(r.responseLength / 64, 1, Integer::sum);
            }
        }

        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Content Discovery".equals(r.probe.attackType)) continue;
            String path = r.probe.targetParameter;
            plugins.addAll(Signals.appPluginRefs(r.bodySnippet));
            if (r.statusCode != 200) continue;
            // Skip SPA fallback: a 200 that is the same size as the root page is just the catch-all route.
            if (b.responseLength > 0 && Signals.lengthDeltaRatio(b.responseLength, r.responseLength) < 0.02) continue;
            // Skip WAF block / generic-error template pages (clustered length OR explicit block wording).
            if (lenFreq.getOrDefault(r.responseLength / 64, 0) >= 3 || Signals.looksLikeBlockPage(r.bodySnippet)) continue;
            String sev = isSensitive(path) ? "Medium" : "Low";
            f.add(new Finding("Sensitive Path Disclosure", sev, 0.7,
                    I18n.t("f.disc.path.desc", path),
                    "", path + " -> HTTP 200",
                    I18n.t("f.disc.path.exp", path),
                    I18n.t("f.disc.path.rem")));
        }

        if (!plugins.isEmpty()) {
            f.add(new Finding("Technology / Component Disclosure", "Info", 0.8,
                    I18n.t("f.disc.tech.desc", String.join(", ", plugins)),
                    "", "App_Plugins: " + String.join(", ", plugins),
                    I18n.t("f.disc.tech.exp"),
                    I18n.t("f.disc.tech.rem")));
        }
        return f;
    }

    private boolean isSensitive(String path) {
        String p = path.toLowerCase();
        return p.contains(".git") || p.contains(".env") || p.contains("admin") || p.contains("phpmyadmin")
                || p.contains("actuator") || p.contains("server-status");
    }
}
