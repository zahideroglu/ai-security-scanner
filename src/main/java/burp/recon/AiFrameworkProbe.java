package burp.recon;

import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.i18n.I18n;
import burp.scan.RequestKit;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Host-level fingerprint for exposed AI-application frameworks (Langflow, Flowise, LangServe,
 * an open Ollama server). These are an emerging, high-value attack surface — the "ARTEX" LLM
 * pentest framework reported by Previdian (Nov 2026) specifically hunted Langflow/Flowise for
 * code execution and file read. Burp's signature scanner does not fingerprint them.
 *
 * <p>Strictly SAFE: only benign identification GETs are sent (no exploit payloads). A known-
 * dangerous endpoint is probed with a plain GET only to learn whether it is REACHABLE and
 * whether it is auth-gated — never with the actual CVE payload. One pass per host, a handful
 * of requests, funnelled through the shared rate limiter like every other request.
 *
 * @author Zahid Eroglu
 */
public class AiFrameworkProbe {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public AiFrameworkProbe(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    /** One framework signature + its known-dangerous (safely-probed) endpoints. */
    private static final class Fw {
        final String name;
        final String[] sigPaths;   // benign GETs that identify the framework
        final String[] markers;    // lowercase tokens expected in a signature response
        final String[] dangerPaths;// known-sensitive endpoints, probed with a plain GET only
        final String cveNote;      // technical note (CVE ids / technique) — not translated
        Fw(String name, String[] sigPaths, String[] markers, String[] dangerPaths, String cveNote) {
            this.name = name; this.sigPaths = sigPaths; this.markers = markers;
            this.dangerPaths = dangerPaths; this.cveNote = cveNote;
        }
    }

    private static final Fw[] FRAMEWORKS = {
            new Fw("Langflow",
                    new String[]{"/api/v1/version", "/api/v1/config"},
                    new String[]{"langflow"},
                    new String[]{"/api/v1/validate/code"},
                    "/api/v1/validate/code — CVE-2025-3248 / CVE-2026-0768 (code execution); profile-picture path traversal CVE-2026-33497"),
            new Fw("Flowise",
                    new String[]{"/", "/api/v1/version"},
                    new String[]{"flowise"},
                    new String[]{"/api/v1/openai-assistants-file", "/api/v1/get-upload-file"},
                    "arbitrary file read — CVE-2024-36420"),
            new Fw("LangServe",
                    new String[]{"/", "/docs"},
                    new String[]{"langserve"},
                    new String[]{"/invoke", "/playground"},
                    "exposed chain invoke/playground endpoints (prompt-injection / SSRF surface)"),
            new Fw("Ollama",
                    new String[]{"/api/tags", "/api/version"},
                    new String[]{"\"models\"", "ollama"},
                    new String[]{"/api/generate", "/api/pull"},
                    "unauthenticated model management — resource abuse, SSRF via /api/pull"),
    };

    /**
     * Fingerprint the seed's host. Returns one Finding per detected framework (empty if none).
     * Never throws into the caller.
     */
    public List<Finding> probe(IHttpRequestResponse seed, SharedRateLimiter limiter, StageListener l) {
        List<Finding> out = new ArrayList<>();
        try {
            IRequestInfo ri = helpers.analyzeRequest(seed);
            String host = ri.getUrl().getHost();
            IHttpService svc = seed.getHttpService();
            if (host == null || svc == null) return out;
            String root = ri.getUrl().getProtocol() + "://" + host
                    + (ri.getUrl().getPort() > 0 && ri.getUrl().getPort() != ri.getUrl().getDefaultPort()
                        ? ":" + ri.getUrl().getPort() : "");

            for (Fw fw : FRAMEWORKS) {
                String hitPath = null, hitMarker = null;
                int hitStatus = 0;
                for (String sp : fw.sigPaths) {
                    Resp r = get(svc, host, sp, limiter);
                    if (r == null || r.status == 0 || r.status == 404) continue;
                    String marker = firstMarker(r.bodyLower, fw.markers);
                    if (marker != null) { hitPath = sp; hitMarker = marker; hitStatus = r.status; break; }
                }
                if (hitPath == null) continue; // not this framework

                if (l != null) l.onStageProgress(DetectionStage.RECON,
                        "⚠ AI uygulama çatısı tespit edildi: " + fw.name + " (" + host + ")");

                // Safely check whether a known-dangerous endpoint is reachable (plain GET, no payload).
                String dangerNote = "";
                String severity = "Medium";
                double confidence = 0.80;
                for (String dp : fw.dangerPaths) {
                    Resp r = get(svc, host, dp, limiter);
                    if (r == null) continue;
                    if (r.status == 200 || r.status == 400 || r.status == 405 || r.status == 422 || r.status == 500) {
                        dangerNote = dp + " → HTTP " + r.status + " (reachable, not auth-gated)";
                        severity = "High"; confidence = 0.88;
                        break;
                    } else if (r.status == 401 || r.status == 403) {
                        dangerNote = dp + " → HTTP " + r.status + " (reachable but auth-gated)";
                    }
                }

                String url = root;
                Finding f = new Finding(
                        "AI Application Framework Exposure",
                        severity,
                        confidence,
                        I18n.t("f.aiapp.desc", fw.name, url),
                        url,
                        I18n.t("f.aiapp.ev", hitPath, hitStatus, hitMarker,
                                dangerNote.isEmpty() ? "—" : dangerNote),
                        I18n.t("f.aiapp.exp", fw.cveNote),
                        I18n.t("f.aiapp.rem", fw.name));
                out.add(f);
                if (stdout != null) stdout.println("[AiFrameworkProbe] " + fw.name + " @ " + host
                        + " sev=" + severity + (dangerNote.isEmpty() ? "" : " | " + dangerNote));
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    private static final class Resp {
        final int status; final String bodyLower;
        Resp(int status, String bodyLower) { this.status = status; this.bodyLower = bodyLower; }
    }

    private Resp get(IHttpService svc, String host, String path, SharedRateLimiter limiter) {
        try {
            if (limiter != null) limiter.acquire();
            byte[] req = RequestKit.minimalGet(helpers, host, path);
            if (req == null) return null;
            IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
            byte[] resp = rr == null ? null : rr.getResponse();
            if (resp == null) return new Resp(0, "");
            int sc = helpers.analyzeResponse(resp).getStatusCode();
            int bodyOff = helpers.analyzeResponse(resp).getBodyOffset();
            String body = "";
            if (bodyOff > 0 && bodyOff <= resp.length) {
                int end = Math.min(resp.length, bodyOff + 8192); // cap: markers appear early
                body = new String(resp, bodyOff, end - bodyOff, java.nio.charset.StandardCharsets.UTF_8);
            }
            return new Resp(sc, body.toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            return null;
        }
    }

    private static String firstMarker(String bodyLower, String[] markers) {
        if (bodyLower == null) return null;
        for (String m : markers) {
            if (m != null && bodyLower.contains(m.toLowerCase(Locale.ROOT))) return m;
        }
        return null;
    }
}
