package burp.recon;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.AiApiClient;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.scan.RequestKit;
import burp.spec.SyntheticHttpRequestResponse;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AI-assisted attack-surface discovery: widens coverage by combining endpoints
 * extracted from observed JS with paths the AI proposes (sibling resources,
 * admin/debug/internal variants, REST actions, hidden parameters), then verifies
 * which ones actually exist. The confirmed-new endpoints feed the normal scanners,
 * so more surface => more findings. Uses AI in the RECON stage (not just judging).
 *
 * @author Zahid Eroglu
 */
public class AiEndpointDiscoverer {

    private static final int VERIFY_CAP = 40;
    private static final Pattern JS_PATH = Pattern.compile("[\"'`](/[A-Za-z0-9_\\-./{}]{2,80})[\"'`]");
    private static final Pattern STATIC_EXT =
            Pattern.compile("\\.(css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map|webp|avif)$", Pattern.CASE_INSENSITIVE);

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final AiApiClient aiClient;
    private final PrintWriter stdout, stderr;
    private final List<String> minedParams = new ArrayList<>(); // AI-proposed hidden parameters (for the test engine)

    public AiEndpointDiscoverer(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                AiApiClient aiClient, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /** Returns confirmed-new endpoints (synthetic request+response) for the seed's host. */
    public List<IHttpRequestResponse> discover(IHttpRequestResponse seed, SharedRateLimiter limiter, StageListener l) {
        return discover(seed, limiter, l, true);
    }

    /**
     * @param verifyEndpoints when {@code false}, mine hidden params only (one AI call) and SKIP the target
     *        directory-scanning verification GETs — for AI mode focused on IDOR/BOLA/BAC, not content discovery.
     *        {@link #minedParams()} is still populated (the IDOR fuel); the returned endpoint list is empty.
     */
    public List<IHttpRequestResponse> discover(IHttpRequestResponse seed, SharedRateLimiter limiter,
                                               StageListener l, boolean verifyEndpoints) {
        List<IHttpRequestResponse> out = new ArrayList<>();
        try {
            IRequestInfo ri = helpers.analyzeRequest(seed);
            String host = ri.getUrl().getHost();
            IHttpService svc = seed.getHttpService();

            Set<String> observed = new LinkedHashSet<>();
            Set<String> jsPaths = new LinkedHashSet<>();
            IHttpRequestResponse[] hist = callbacks.getProxyHistory();
            if (hist != null) {
                for (IHttpRequestResponse h : hist) {
                    try {
                        IRequestInfo r = helpers.analyzeRequest(h);
                        if (!host.equalsIgnoreCase(r.getUrl().getHost())) continue;
                        observed.add(r.getUrl().getPath());
                        if (h.getResponse() != null && r.getUrl().getPath().toLowerCase().endsWith(".js")) {
                            extractJsPaths(bodyOf(h), jsPaths);
                        }
                    } catch (Exception ignore) {
                    }
                }
            }

            Set<String> candidates = new LinkedHashSet<>(jsPaths);
            candidates.addAll(aiProposePaths(host, observed));
            candidates.removeAll(observed);
            if (l != null) l.onStageProgress(DetectionStage.RECON, observed.size() + " gözlenen yol · "
                    + jsPaths.size() + " JS-yolu · " + candidates.size() + " aday (AI+JS)");

            if (!verifyEndpoints) {   // params-only mode: minedParams already filled; skip target dir-scanning
                if (stdout != null) stdout.println("[AiDiscover] endpoint doğrulama atlandı (dizin taraması kapalı) — "
                        + minedParams.size() + " gizli param madenlendi");
                return out; // empty; minedParams() carries the IDOR fuel
            }

            // Soft-404 / catch-all calibration: learn how the host answers a KNOWN-nonexistent path ONCE,
            // so a "200-for-everything" SPA/WAF host does not mint phantom endpoints that then re-multiply
            // every downstream module's traffic. (ForcedBrowser already does this; this loop previously had
            // no such guard — only a sc==0||404 check.)
            int softStatus = -1, softLen = -1;
            try {
                if (limiter != null) limiter.acquire();
                byte[] cal = RequestKit.minimalGet(helpers, host, "/zZ9q__nonexistent_" + Math.abs(host.hashCode()) + "__");
                if (cal != null) {
                    byte[] cresp = callbacks.makeHttpRequest(svc, cal).getResponse();
                    if (cresp != null) {
                        softStatus = helpers.analyzeResponse(cresp).getStatusCode();
                        softLen = bodyLen(cresp);
                    }
                }
            } catch (Exception ignore) {
            }

            // Bound the loop by REQUESTS, not just by confirmations: misses were previously unbounded
            // (found++ only on a hit), so a 404-heavy host could fire one GET per candidate (up to ~225).
            // ATTEMPT_CAP caps total verification GETs; VERIFY_CAP still caps confirmed endpoints.
            final int ATTEMPT_CAP = 60;
            int found = 0, attempts = 0;
            for (String path : candidates) {
                if (found >= VERIFY_CAP || attempts >= ATTEMPT_CAP) break;
                if (STATIC_EXT.matcher(path).find()) continue;
                if (limiter != null) limiter.acquire();
                byte[] req = RequestKit.minimalGet(helpers, host, path);
                if (req == null) continue;
                try {
                    attempts++;
                    IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
                    byte[] resp = rr.getResponse();
                    if (resp == null) continue;
                    int sc = helpers.analyzeResponse(resp).getStatusCode();
                    if (sc == 0 || sc == 404) continue; // does not exist
                    // Phantom guard: same status AND near-same body length as the known-nonexistent baseline
                    // => host answers everything the same way => not a real endpoint. Also drop WAF/block pages.
                    if (softStatus > 0 && sc == softStatus && similarLen(bodyLen(resp), softLen)) continue;
                    if (burp.scan.Signals.looksLikeBlockPage(bodyStr(resp))) continue;
                    SyntheticHttpRequestResponse s = new SyntheticHttpRequestResponse(req, svc);
                    s.setResponse(resp);
                    out.add(s);
                    found++;
                    if (l != null) l.onStageProgress(DetectionStage.RECON, "✓ keşfedildi: " + path + " (HTTP " + sc + ")");
                } catch (Exception ignore) {
                }
            }
            if (stdout != null) stdout.println("[AiDiscover] " + out.size() + " yeni endpoint doğrulandı (" + host + ")");
        } catch (Exception e) {
            if (stderr != null) stderr.println("[AiDiscover] " + e.getMessage());
        }
        return out;
    }

    /** AI-proposed hidden parameters from the last {@link #discover} call. */
    public List<String> minedParams() { return minedParams; }

    private void extractJsPaths(String body, Set<String> into) {
        if (body == null) return;
        if (body.length() > 200000) body = body.substring(0, 200000);
        Matcher m = JS_PATH.matcher(body);
        while (m.find()) {
            String p = m.group(1);
            if (p.contains("//") || p.contains("{{") || p.contains(" ")) continue;
            if (STATIC_EXT.matcher(p).find()) continue;
            into.add(p);
            if (into.size() >= 200) break;
        }
    }

    private List<String> aiProposePaths(String host, Set<String> observed) {
        List<String> out = new ArrayList<>();
        if (aiClient == null) return out;
        try {
            StringBuilder sample = new StringBuilder();
            int n = 0;
            for (String p : observed) { sample.append(p).append("\n"); if (++n >= 60) break; }
            String prompt = "You are mapping the attack surface of a web application/API on host " + host + ".\n"
                    + "Observed paths:\n" + sample + "\n"
                    + "Propose up to 25 ADDITIONAL likely paths that probably EXIST but were not observed: sibling "
                    + "resources, list/detail variants, admin/debug/internal/management endpoints, common REST actions "
                    + "(create/update/delete/export), versioned /api paths, and likely sensitive operations. Use concrete "
                    + "paths starting with '/'. Also list likely hidden request parameters for the main resource.\n"
                    + "Respond ONLY JSON: {\"endpoints\":[\"/...\"],\"parameters\":[\"...\"]}";
            List<AiApiClient.Message> msgs = new ArrayList<>();
            msgs.add(new AiApiClient.Message("system",
                    "You are a web application reconnaissance expert. Respond only with valid JSON."));
            msgs.add(new AiApiClient.Message("user", prompt));
            JSONObject resp = aiClient.chatCompletion(msgs);
            String content = resp.getJSONArray("choices").getJSONObject(0).getJSONObject("message").getString("content");
            int s = content.indexOf("{"), e = content.lastIndexOf("}") + 1;
            if (s >= 0 && e > s) {
                JSONObject j = new JSONObject(content.substring(s, e));
                JSONArray eps = j.optJSONArray("endpoints");
                if (eps != null) {
                    for (int i = 0; i < eps.length(); i++) {
                        String p = eps.optString(i, "").trim();
                        if (p.startsWith("/") && p.length() <= 120) out.add(p);
                    }
                }
                JSONArray params = j.optJSONArray("parameters");
                if (params != null) {
                    for (int i = 0; i < params.length(); i++) {
                        String p = params.optString(i, "").trim();
                        if (!p.isEmpty()) minedParams.add(p);
                    }
                    if (!minedParams.isEmpty() && stdout != null) {
                        stdout.println("[AiDiscover] AI gizli parametreler: " + minedParams);
                    }
                }
            }
        } catch (Exception ex) {
            if (stderr != null) stderr.println("[AiDiscover] AI: " + ex.getMessage());
        }
        return out;
    }

    private String bodyOf(IHttpRequestResponse h) {
        try {
            byte[] resp = h.getResponse();
            if (resp == null) return "";
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.max(0, resp.length - off), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private int bodyLen(byte[] resp) {
        try { int off = helpers.analyzeResponse(resp).getBodyOffset(); return Math.max(0, resp.length - off); }
        catch (Exception e) { return resp == null ? 0 : resp.length; }
    }

    private String bodyStr(byte[] resp) {
        try {
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.min(8192, Math.max(0, resp.length - off)), StandardCharsets.UTF_8);
        } catch (Exception e) { return ""; }
    }

    /** True when two body lengths are within 5% — used to spot catch-all (soft-404) responses. */
    private static boolean similarLen(int a, int b) {
        if (a < 0 || b < 0) return false;
        int max = Math.max(a, b);
        return max == 0 || Math.abs(a - b) / (double) max < 0.05;
    }
}
