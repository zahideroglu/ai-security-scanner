package burp.scan;

import burp.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Snapshot of the unmodified request/response, captured once per endpoint and
 * reused by every module as the diff anchor.
 *
 * @author Zahid Eroglu
 */
public class Baseline {

    public IHttpRequestResponse base;
    public IExtensionHelpers helpers;       // for modules that build raw probe requests
    public IBurpExtenderCallbacks callbacks; // available to modules if needed
    public boolean singleRequestScan = false; // true = one chosen request: run host-level checks on any path
    public int statusCode;
    public long responseTimeMs;
    public int responseLength;
    public String bodySnippet = "";
    public String fullBody = "";   // full decoded baseline body (uncapped) for judges that scan past 8KB
    public List<String> responseHeaders = new ArrayList<>();
    public List<String> requestHeaders = new ArrayList<>();
    public String requestBody = "";
    public List<IParameter> parameters = new ArrayList<>();
    public String method = "";
    public String path = "";
    public String host = "";
    public String url = "";
    public String requestContentType = "";
    public boolean responseIsHtml;
    public String responseContentType = ""; // inferred mime / Content-Type of the baseline response

    public static Baseline capture(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                   IHttpRequestResponse base) {
        return capture(callbacks, helpers, base, null);
    }

    /** @param limiter site-wide throttle; when non-null the baseline re-fetch (when needed) acquires a slot
     *  so it shares the global per-minute budget like every other target request. */
    public static Baseline capture(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                   IHttpRequestResponse base, burp.engine.SharedRateLimiter limiter) {
        Baseline b = new Baseline();
        b.base = base;
        b.helpers = helpers;
        b.callbacks = callbacks;
        try {
            IRequestInfo ri = helpers.analyzeRequest(base);
            b.method = ri.getMethod();
            b.url = ri.getUrl().toString();
            b.path = ri.getUrl().getPath();
            b.host = ri.getUrl().getHost();
            b.parameters = ri.getParameters();
            b.requestHeaders = ri.getHeaders();
            for (String h : ri.getHeaders()) {
                if (h.toLowerCase().startsWith("content-type:")) {
                    b.requestContentType = h.substring(h.indexOf(':') + 1).trim();
                }
            }
            byte[] req = base.getRequest();
            if (req != null) {
                int roff = ri.getBodyOffset();
                if (roff < req.length) {
                    b.requestBody = new String(req, roff, req.length - roff);
                }
            }

            // Reuse the already-captured response as the diff anchor when we have a usable one — this avoids
            // one extra request on EVERY scanned endpoint (the single biggest traffic saving, since it
            // multiplies by endpoint count). Only re-send when there is no captured response, or it is a
            // redirect/cached status (3xx incl. 304) whose body is not a reliable anchor. The module probes
            // carry the same request headers as this captured response, so reusing it stays consistent —
            // only its timestamp differs, which the modules already absorb via length-ratio tolerances.
            byte[] resp = base.getResponse();
            if (resp == null || isRedirectAnchor(helpers, resp)) {
                try {
                    if (limiter != null) limiter.acquire(); // share the global per-minute budget
                    IHttpRequestResponse fresh = callbacks.makeHttpRequest(base.getHttpService(), base.getRequest());
                    if (fresh.getResponse() != null) resp = fresh.getResponse();
                } catch (Exception e) {
                    // send failed → keep the captured response (may be null) as the fallback
                }
            }
            if (resp != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(resp);
                b.statusCode = respInfo.getStatusCode();
                b.responseHeaders = respInfo.getHeaders();
                int off = respInfo.getBodyOffset();
                b.responseLength = Math.max(0, resp.length - off);
                b.bodySnippet = new String(resp, off, Math.min(8192, resp.length - off));
                b.fullBody = new String(resp, off, Math.max(0, resp.length - off)); // uncapped, same source as bodySnippet
                String mime = respInfo.getInferredMimeType();
                String ctHeader = "";
                for (String h : respInfo.getHeaders()) {
                    if (h.toLowerCase().startsWith("content-type:")) { ctHeader = h.substring(h.indexOf(':') + 1).trim(); break; }
                }
                b.responseContentType = (ctHeader.isEmpty() ? (mime == null ? "" : mime) : ctHeader);
                b.responseIsHtml = (mime != null && mime.toLowerCase().contains("html"))
                        || b.bodySnippet.toLowerCase().contains("<html");
            }
        } catch (Exception ignore) {
        }
        return b;
    }

    /** A 3xx (incl. 304-cached) captured response is a poor diff anchor (its body is a redirect/cached
     *  stub), so we re-fetch a fresh one in that case. Any parse failure also forces a clean re-fetch. */
    private static boolean isRedirectAnchor(IExtensionHelpers helpers, byte[] resp) {
        try {
            int sc = helpers.analyzeResponse(resp).getStatusCode();
            return sc >= 300 && sc < 400;
        } catch (Exception e) {
            return true;
        }
    }

    /** True when the baseline response is an image/media asset (chart/avatar/font/av) — public by nature.
     *  NOT pdf/zip/octet-stream: those can be a user's private file and ARE valid IDOR/BOLA targets. */
    public boolean responseIsImageMedia() {
        return Signals.isImageOrMediaType(responseContentType);
    }

    /** Value of a request header by name (case-insensitive), or null. */
    public String requestHeader(String name) {
        String n = name.toLowerCase() + ":";
        for (String h : requestHeaders) {
            if (h.toLowerCase().startsWith(n)) {
                int c = h.indexOf(':');
                return c >= 0 ? h.substring(c + 1).trim() : "";
            }
        }
        return null;
    }

    /** Injectable params only (URL/body/JSON), capped for performance. */
    public List<IParameter> injectableParams(int max) {
        List<IParameter> out = new ArrayList<>();
        for (IParameter p : parameters) {
            byte t = p.getType();
            if (t == IParameter.PARAM_URL || t == IParameter.PARAM_BODY || t == IParameter.PARAM_JSON) {
                out.add(p);
                if (out.size() >= max) break;
            }
        }
        return out;
    }
}
