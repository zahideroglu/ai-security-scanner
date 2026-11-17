package burp.scan;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.Settings;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Tags every request the extension sends to a TARGET with an identifying header, so the target's
 * defenders can tell authorized AppSecHunter scan traffic apart from a real attack in their SIEM /
 * WAF logs — and can whitelist, correlate or clean up afterwards.
 *
 * <p>This is responsible-testing hygiene: offensive automation frameworks seen in the wild
 * (e.g. the "ARTEX" LLM pentest framework reported by Previdian, Nov 2026) self-label their traffic
 * for their own coordination; an authorized tool should do the same so blue teams are not left
 * guessing. Only traffic sent through Burp's extender tool is tagged — AI-provider calls go over a
 * separate java.net client and are never touched.
 *
 * <p>Injection happens once, centrally, from {@code BurpExtender.processHttpMessage} for
 * {@code TOOL_EXTENDER} requests, so no individual send site needs to know about it.
 *
 * @author Zahid Eroglu
 */
public final class ScanMarker {

    private ScanMarker() {}

    /** Stable per-Burp-session id, so all requests from one run share one correlatable value. */
    private static final String SESSION_ID = UUID.randomUUID().toString().substring(0, 8);

    private static final String PRODUCT = "AppSecHunter";

    /** The header value sent on every tagged request. */
    public static String markerValue() {
        return PRODUCT + " authorized-scan; id=" + SESSION_ID;
    }

    /** The session id other components can surface to the user (e.g. "tell your SOC to expect id=…"). */
    public static String sessionId() {
        return SESSION_ID;
    }

    /**
     * Add the scan-marker header to a request in place, if enabled and not already present.
     * Never throws into the caller — a marker must never break a request.
     */
    public static void tag(IHttpRequestResponse messageInfo, Settings settings, IExtensionHelpers helpers) {
        if (messageInfo == null || settings == null || helpers == null) return;
        if (!settings.isScanMarkerEnabled()) return;
        try {
            byte[] req = messageInfo.getRequest();
            if (req == null) return;
            IRequestInfo info = helpers.analyzeRequest(req);
            List<String> headers = info.getHeaders();
            if (headers == null || headers.isEmpty()) return;

            String headerName = settings.getScanMarkerHeader();
            String prefix = headerName.toLowerCase() + ":";
            for (String h : headers) {
                if (h != null && h.toLowerCase().startsWith(prefix)) return; // idempotent
            }

            headers.add(headerName + ": " + markerValue());
            byte[] body = Arrays.copyOfRange(req, info.getBodyOffset(), req.length);
            messageInfo.setRequest(helpers.buildHttpMessage(headers, body));
        } catch (Exception ignore) {
            // swallow: tagging is best-effort and must not interfere with the test
        }
    }
}
