package burp.recon;

import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.i18n.I18n;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.authz.OwnershipOracle;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Tests AI-mined hidden parameters against an endpoint: adds each parameter (not
 * already present) with a probe value and flags those the server honours (status
 * change / response-size change / value reflected) — candidate hidden features,
 * access-control vectors (id/privilege names) or information disclosure. The
 * findings are AI-adjudicated downstream (id/privilege types route to BOLA judging).
 *
 * @author Zahid Eroglu
 */
public class ParamMiningTester {

    private static final int CAP = 30;

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    // Honored hidden id-like params (customerId/userId/accountId/...) — the caller feeds these into a
    // real IDOR/BOLA test instead of a weak "honored" finding.
    private final List<String> honoredIdParams = new ArrayList<>();

    /** Id-like params the server honored, for upstream IDOR/BOLA testing. Valid after {@link #mine}. */
    public List<String> honoredIdParams() { return honoredIdParams; }

    public ParamMiningTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    public List<Finding> mine(IHttpRequestResponse base, List<String> params,
                              SharedRateLimiter limiter, StageListener l) {
        List<Finding> out = new ArrayList<>();
        if (base == null || params == null || params.isEmpty()) return out;
        try {
            IRequestInfo ri = helpers.analyzeRequest(base);
            Set<String> existing = new HashSet<>();
            for (IParameter p : ri.getParameters()) existing.add(p.getName().toLowerCase());

            byte[] baseResp = base.getResponse();
            if (baseResp == null) {
                try { baseResp = callbacks.makeHttpRequest(base.getHttpService(), base.getRequest()).getResponse(); }
                catch (Exception ignore) { }
            }
            int baseLen = bodyLen(baseResp);
            int baseStatus = statusOf(baseResp);
            String baseBody = bodyStr(baseResp);

            int n = 0;
            Set<String> done = new HashSet<>();
            for (String raw : params) {
                if (n >= CAP) break;
                String name = raw == null ? "" : raw.trim().replaceAll("[^A-Za-z0-9_\\-]", "");
                if (name.isEmpty() || existing.contains(name.toLowerCase()) || !done.add(name.toLowerCase())) continue;
                String val = valueFor(name);
                if (limiter != null) limiter.acquire();
                byte[] req = helpers.addParameter(base.getRequest(),
                        helpers.buildParameter(name, val, IParameter.PARAM_URL));
                byte[] resp;
                try {
                    resp = callbacks.makeHttpRequest(base.getHttpService(), req).getResponse();
                } catch (Exception e) {
                    continue;
                }
                if (resp == null) continue;
                n++;
                int len = bodyLen(resp);
                int st = statusOf(resp);
                String body = bodyStr(resp);
                // FP guard: a param that trips a WAF/error page (response collapses to a small generic
                // block page) is NOT "exposed internal data". Drop block pages and dramatic collapses to
                // a tiny body. ('debug=true'/'limit=1' -> 23828b -> 1029b block page were false positives.)
                if (burp.scan.Signals.looksLikeBlockPage(body)) continue;
                if (len < 2048 && baseLen > 0 && len < baseLen / 2) continue;
                boolean changed = (st != baseStatus) || deltaRatio(baseLen, len) > 0.05;
                boolean reflects = body != null && !val.isEmpty() && body.contains(val)
                        && (baseBody == null || !baseBody.contains(val));
                if (!changed && !reflects) continue;

                String low = name.toLowerCase(Locale.ROOT);
                // True id parameter (same criteria as the IDOR engine) → hand it off to a REAL
                // ownership-aware IDOR/BOLA test upstream (value-swap + public/own-data discrimination)
                // instead of a weak "honored" finding that the AI judge just refutes.
                boolean idParam = low.endsWith("id") || low.endsWith("_id")
                        || OwnershipOracle.isAccountOwnershipParam(name);
                if (idParam) {
                    honoredIdParams.add(name);
                    if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                            "Param mining: '" + name + "' honored (id → IDOR/BOLA testine alındı)");
                    continue;
                }

                boolean privLike = low.matches(".*(admin|role|debug|internal|verbose|preview|draft|unpublish|test).*")
                        || low.startsWith("is") || low.startsWith("can") || low.startsWith("has") || low.startsWith("show");
                String type = privLike ? "Broken Access Control (Hidden Parameter)" : "Hidden Parameter (AI-mined)";
                String sev = privLike ? "Medium" : "Low";

                String descBaseline = (st != baseStatus) ? I18n.t("f.pmt.honored.desc.baseline", baseStatus) : "";
                String descReflected = reflects ? I18n.t("f.pmt.honored.desc.reflected") : "";
                String evReflected = reflects ? I18n.t("f.pmt.honored.ev.reflected") : "";
                Finding f = new Finding(type, sev, 0.45,
                        I18n.t("f.pmt.honored.desc", name, val, st, descBaseline, baseLen, len, descReflected),
                        "", I18n.t("f.pmt.honored.ev", name, val, baseStatus, st, baseLen, len, evReflected),
                        I18n.t("f.pmt.honored.exp"),
                        I18n.t("f.pmt.honored.rem"));
                f.setHttpResponse(body);
                out.add(f);
                if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                        "Param mining: '" + name + "' honored (" + baseStatus + "→" + st + ")");
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    private String valueFor(String name) {
        String n = name.toLowerCase();
        if (n.contains("admin") || n.contains("role")) return "admin";
        if (n.startsWith("is") || n.startsWith("can") || n.startsWith("has") || n.contains("debug")
                || n.contains("internal") || n.contains("verbose") || n.contains("test") || n.contains("preview")
                || n.contains("draft") || n.contains("enable") || n.contains("unpublish") || n.contains("show")
                || n.contains("all")) {
            return "true";
        }
        if (n.contains("format") || n.contains("output") || n.contains("type")) return "json";
        return "1";
    }

    private int statusOf(byte[] resp) {
        try { return resp == null ? 0 : helpers.analyzeResponse(resp).getStatusCode(); }
        catch (Exception e) { return 0; }
    }

    private int bodyLen(byte[] resp) {
        try {
            if (resp == null) return 0;
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return Math.max(0, resp.length - off);
        } catch (Exception e) { return 0; }
    }

    private String bodyStr(byte[] resp) {
        try {
            if (resp == null) return "";
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.min(8192, Math.max(0, resp.length - off)), StandardCharsets.UTF_8);
        } catch (Exception e) { return ""; }
    }

    private double deltaRatio(int a, int b) {
        int max = Math.max(a, b);
        return max == 0 ? 0 : Math.abs(a - b) / (double) max;
    }
}
