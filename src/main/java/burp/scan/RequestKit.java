package burp.scan;

import burp.IExtensionHelpers;

import java.util.ArrayList;
import java.util.List;

/**
 * Builders for raw probe requests that the standard param/path/header mutation
 * cannot express: changing the HTTP method, hitting a different path/service, or
 * sending an anonymous clone. Used by the host-level modules (HTTP method,
 * transport, content discovery). Pure CPU - performs NO network I/O.
 *
 * @author Zahid Eroglu
 */
public final class RequestKit {

    private RequestKit() {}

    private static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

    /**
     * Clone the baseline headers with a new method + path and an empty body.
     * Drops Content-Type/Content-Length (no body); optionally strips Cookie /
     * Authorization to test anonymous access. Keeps (or adds) a browser UA so the
     * upstream WAF does not 403 a Java user-agent.
     */
    public static byte[] reshape(IExtensionHelpers helpers, List<String> baseHeaders,
                                 String method, String path, boolean dropAuth) {
        if (helpers == null || baseHeaders == null || baseHeaders.isEmpty()) return null;
        List<String> out = new ArrayList<>();
        String first = baseHeaders.get(0);
        String httpVer = "HTTP/1.1";
        String[] parts = first.split(" ");
        if (parts.length >= 3) httpVer = parts[parts.length - 1];
        out.add(method + " " + path + " " + httpVer);
        boolean hasUa = false;
        for (int i = 1; i < baseHeaders.size(); i++) {
            String h = baseHeaders.get(i);
            String low = h.toLowerCase();
            if (dropAuth && (low.startsWith("cookie:") || low.startsWith("authorization:"))) continue;
            if (low.startsWith("content-length:") || low.startsWith("content-type:")) continue;
            if (low.startsWith("user-agent:")) hasUa = true;
            out.add(h);
        }
        if (!hasUa) out.add("User-Agent: " + UA);
        return helpers.buildHttpMessage(out, new byte[0]);
    }

    /**
     * A minimal anonymous {@code GET host+path} request (no cookies). Carries a realistic browser
     * navigation header set (UA, Accept, Accept-Language, Sec-Fetch-*, Upgrade-Insecure-Requests) so a
     * WAF does not flag the sparse "scanner" fingerprint. NOTE: Accept-Encoding is intentionally omitted
     * so the response body stays uncompressed and parseable (block-page / soft-404 detection reads it).
     */
    public static byte[] minimalGet(IExtensionHelpers helpers, String host, String path) {
        if (helpers == null || host == null) return null;
        List<String> h = new ArrayList<>();
        h.add("GET " + path + " HTTP/1.1");
        h.add("Host: " + host);
        h.add("User-Agent: " + UA);
        h.add("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
        h.add("Accept-Language: en-US,en;q=0.9");
        h.add("Upgrade-Insecure-Requests: 1");
        h.add("Sec-Fetch-Dest: document");
        h.add("Sec-Fetch-Mode: navigate");
        h.add("Sec-Fetch-Site: none");
        h.add("Sec-Fetch-User: ?1");
        return helpers.buildHttpMessage(h, new byte[0]);
    }
}
