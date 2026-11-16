package burp.recon;

import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.i18n.I18n;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.scan.RequestKit;
import burp.scan.Signals;
import burp.spec.SyntheticHttpRequestResponse;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Wordlist-driven forced browsing: probes a curated, high-signal list of hidden
 * files/directories (secrets, backups, VCS metadata, admin/debug consoles, config)
 * at the host root. Exposed (HTTP 200) sensitive resources are reported with a
 * severity by sensitivity; all non-404 hits are returned to feed the scanners.
 * Complements the AI/JS surface discovery with deterministic coverage.
 *
 * @author Zahid Eroglu
 */
public class ForcedBrowser {

    private static final String[] WORDLIST = {
            "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/.htaccess", "/web.config", "/appsettings.json", "/appsettings.Development.json",
            "/config.json", "/config.php", "/configuration.php", "/wp-config.php", "/.aws/credentials",
            "/.npmrc", "/package.json", "/composer.json", "/composer.lock", "/yarn.lock",
            "/Dockerfile", "/docker-compose.yml", "/.DS_Store", "/phpinfo.php", "/info.php",
            "/server-status", "/server-info", "/actuator", "/actuator/env", "/actuator/health",
            "/metrics", "/debug", "/console", "/admin", "/administrator", "/admin/login",
            "/manager", "/management", "/dashboard", "/backup", "/backups", "/backup.zip",
            "/backup.sql", "/backup.tar.gz", "/db.sql", "/dump.sql", "/database.sql",
            // (Dropped 9 generic-dir entries — /test /tests /dev /staging /tmp /temp /uploads /files /old —
            //  they exist legitimately on most apps, yield only Low "directory exists" noise, and overlap
            //  AiEndpointDiscoverer/Burp surface discovery. Secrets/VCS/backup/admin core is kept.)
            "/private", "/internal", "/api", "/api/docs", "/api-docs", "/swagger", "/swagger-ui.html",
            "/.well-known/security.txt", "/crossdomain.xml", "/.well-known/openid-configuration",
            "/error_log", "/logs", "/error.log"
    };

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final List<Finding> findings = new ArrayList<>();

    public ForcedBrowser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    /** Findings (exposed sensitive resources) from the last {@link #discover}. */
    public List<Finding> findings() { return findings; }

    /** Returns all non-404 hits (synthetic request+response) for the seed's host. */
    public List<IHttpRequestResponse> discover(IHttpRequestResponse seed, SharedRateLimiter limiter, StageListener l) {
        List<IHttpRequestResponse> out = new ArrayList<>();
        try {
            IRequestInfo ri = helpers.analyzeRequest(seed);
            String host = ri.getUrl().getHost();
            IHttpService svc = seed.getHttpService();

            // Soft-404 / catch-all + WAF-block-page calibration. Two failure modes corrupt forced
            // browsing: (a) a SPA/catch-all serves its index (HTTP 200) for EVERY path; (b) a WAF
            // answers SUSPICIOUS paths (/.git, /admin, /wp-login) with a short generic block page
            // (often HTTP 200) while still 404-ing plain gibberish. We probe BOTH kinds of decoy
            // path and remember every (status,length) "deny signature" so a hit matching one is not
            // reported as a real exposure. (This was the #1 false-positive source: 13 "exposed files"
            // that were all the same 1029-byte WAF block page — /wp-login.php returned it too.)
            int catchAllStatus = -1, catchAllLen = -1;
            java.util.Set<Long> denyLens = new java.util.HashSet<>();      // body-lengths that mean "blocked/missing"
            String[] decoys = {
                    "/zzx9q7-not-a-real-path-001", "/definitely-missing-7f3a2b.zzz", // plain gibberish (catch-all)
                    "/.git/zzx9q7-fake-config", "/admin-zzx9q7-fake/login",          // suspicious-looking (WAF block)
                    "/.env.zzx9q7-fake", "/wp-zzx9q7-fake-login.php"
            };
            for (int i = 0; i < decoys.length; i++) {
                String rnd = decoys[i];
                if (limiter != null) limiter.acquire();
                byte[] rq = RequestKit.minimalGet(helpers, host, rnd);
                if (rq == null) continue;
                try {
                    IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, rq);
                    byte[] rp = rr.getResponse();
                    if (rp == null) continue;
                    int sc = helpers.analyzeResponse(rp).getStatusCode();
                    int blen = bodyLen(rp);
                    if (sc != 404 && sc != 0) {
                        // A non-existent path that did NOT 404 → its body length is a deny/template signature.
                        denyLens.add(roundLen(blen));
                    }
                    if (i < 2) { // plain-gibberish probes drive the catch-all (SPA index) decision
                        if (sc == 404 || sc == 0) { catchAllStatus = -1; }
                        else if (catchAllStatus == -1) { catchAllStatus = sc; catchAllLen = rp.length; }
                        else if (sc != catchAllStatus) { catchAllStatus = -1; }
                    }
                } catch (Exception ignore) {
                }
            }
            final boolean catchAll = catchAllStatus > 0;
            if ((catchAll || !denyLens.isEmpty()) && l != null) {
                l.onStageProgress(DetectionStage.RECON, "ℹ️ Catch-all/WAF block kalibre edildi"
                        + (catchAll ? " (HTTP " + catchAllStatus + ")" : "") + " — block sayfaları elenecek");
            }

            // Collect candidates first; decide what is a real exposure AFTER seeing the full picture
            // (so a block-page length shared by many paths can be recognised and dropped as a template).
            List<Cand> cands = new ArrayList<>();
            int found = 0;
            for (String path : WORDLIST) {
                if (limiter != null) limiter.acquire();
                byte[] req = RequestKit.minimalGet(helpers, host, path);
                if (req == null) continue;
                try {
                    IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
                    byte[] resp = rr.getResponse();
                    if (resp == null) continue;
                    int sc = helpers.analyzeResponse(resp).getStatusCode();
                    if (sc == 0 || sc == 404) continue;
                    // Suppress catch-all echoes: same status AND similar length as the random-path
                    // baseline (the SPA index served for everything). Real files differ markedly in length.
                    if (catchAll && sc == catchAllStatus && catchAllLen > 0
                            && Math.abs(resp.length - catchAllLen) <= Math.max(256, catchAllLen / 5)) {
                        continue;
                    }
                    SyntheticHttpRequestResponse s = new SyntheticHttpRequestResponse(req, svc);
                    s.setResponse(resp);
                    out.add(s);
                    found++;
                    if (sc == 200) {
                        cands.add(new Cand(path, bodyLen(resp), bodyStr(resp)));
                    } else if ((sc == 401 || sc == 403) && l != null) {
                        l.onStageProgress(DetectionStage.RECON, "• " + path + " var ama korumalı (HTTP " + sc + ")");
                    }
                } catch (Exception ignore) {
                }
            }

            // A body length shared by >= 3 different sensitive paths is almost certainly a template
            // (WAF block / generic error / login wall), not three separate exposed files → suppress it.
            java.util.Map<Long, Integer> lenFreq = new java.util.HashMap<>();
            for (Cand c : cands) lenFreq.merge(roundLen(c.len), 1, Integer::sum);

            int suppressed = 0;
            for (Cand c : cands) {
                long rl = roundLen(c.len);
                if (denyLens.contains(rl) || lenFreq.getOrDefault(rl, 0) >= 3 || Signals.looksLikeBlockPage(c.body)) {
                    suppressed++;
                    continue; // block page / generic template, not a real exposure
                }
                String sev = severity(c.path);
                Finding f = new Finding("Sensitive File/Path Exposure", sev, sevConf(sev),
                        I18n.t("f.fb.exposure.desc", c.path, describe(c.path)),
                        "", I18n.t("f.fb.exposure.ev", c.path, c.len),
                        I18n.t("f.fb.exposure.exp", c.path),
                        I18n.t("f.fb.exposure.rem"));
                f.setAffectedUrl(svc.getProtocol() + "://" + host + c.path);
                findings.add(f);
                if (l != null) l.onStageProgress(DetectionStage.RECON, "✓ açık: " + c.path + " (HTTP 200, " + sev + ")");
            }
            if (stdout != null) stdout.println("[ForcedBrowser] " + found + " yol var, " + findings.size()
                    + " açık, " + suppressed + " block/template elendi (" + host + ")");
        } catch (Exception e) {
        }
        return out;
    }

    /** A 200 candidate awaiting block-page/template adjudication. */
    private static final class Cand {
        final String path; final int len; final String body;
        Cand(String path, int len, String body) { this.path = path; this.len = len; this.body = body; }
    }

    /** Round body length into ~64-byte buckets so near-identical templates cluster together. */
    private static long roundLen(int len) { return len / 64L; }

    private int bodyLen(byte[] resp) {
        try {
            if (resp == null) return 0;
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return Math.max(0, resp.length - off);
        } catch (Exception e) { return resp == null ? 0 : resp.length; }
    }

    private String bodyStr(byte[] resp) {
        try {
            if (resp == null) return "";
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.min(8192, Math.max(0, resp.length - off)),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) { return ""; }
    }

    private String severity(String p) {
        String s = p.toLowerCase();
        if (s.contains(".env") || s.contains(".git") || s.contains(".svn") || s.contains("web.config")
                || s.contains("appsettings") || s.contains("wp-config") || s.contains(".aws") || s.contains("backup")
                || s.contains(".sql") || s.contains("dump") || s.contains("database") || s.contains("credential")
                || s.contains(".npmrc") || s.contains("error_log") || s.contains("error.log") || s.endsWith("/logs")) {
            return "High";
        }
        if (s.contains("admin") || s.contains("manager") || s.contains("management") || s.contains("dashboard")
                || s.contains("actuator") || s.contains("console") || s.contains("debug") || s.contains("phpinfo")
                || s.contains("info.php") || s.contains("server-status") || s.contains("server-info")
                || s.contains("swagger") || s.contains("private") || s.contains("internal") || s.equals("/old")
                || s.contains("composer") || s.contains("package.json") || s.contains("metrics")
                || s.contains("docker")) {
            return "Medium";
        }
        return "Low";
    }

    private double sevConf(String sev) {
        return "High".equals(sev) ? 0.8 : "Medium".equals(sev) ? 0.65 : 0.5;
    }

    private String describe(String p) {
        String s = p.toLowerCase();
        if (s.contains(".env") || s.contains("appsettings") || s.contains("wp-config") || s.contains(".aws")
                || s.contains("credential") || s.contains(".npmrc")) return I18n.t("f.fb.describe.secrets");
        if (s.contains(".git") || s.contains(".svn")) return I18n.t("f.fb.describe.vcs");
        if (s.contains("backup") || s.contains(".sql") || s.contains("dump") || s.contains("database"))
            return I18n.t("f.fb.describe.dbdump");
        if (s.contains("admin") || s.contains("console") || s.contains("manager") || s.contains("dashboard"))
            return I18n.t("f.fb.describe.mgmt");
        if (s.contains("phpinfo") || s.contains("server-status") || s.contains("actuator") || s.contains("metrics")
                || s.contains("info.php")) return I18n.t("f.fb.describe.internals");
        return I18n.t("f.fb.describe.review");
    }
}
