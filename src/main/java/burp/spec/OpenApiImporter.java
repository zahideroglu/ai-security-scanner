package burp.spec;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Imports endpoints from an OpenAPI v3 / Swagger v2 (JSON) spec so coverage is not
 * bound to observed traffic. Auto-discovers the spec at common paths on the host, or
 * fetches a given URL, then synthesises one request per path × method (path templates
 * filled with a sample value). Feeds the authorization matrix (and can feed scanning).
 *
 * @author Zahid Eroglu
 */
public class OpenApiImporter {

    private static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            + "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
    private static final String[] COMMON_SPEC_PATHS = {
            "/swagger/v1/swagger.json", "/swagger.json", "/openapi.json", "/v3/api-docs",
            "/api-docs", "/v2/api-docs", "/api/swagger.json", "/api/openapi.json",
            "/swagger/docs/v1", "/api-docs/v1"
    };
    private static final String[] METHODS = {"get", "post", "put", "delete", "patch"};
    private static final Pattern PATH_PARAM = Pattern.compile("\\{[^}]+\\}");
    private static final int MAX_ENDPOINTS = 200;

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;

    public OpenApiImporter(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
    }

    /** Try the common spec paths on the seed's host; parse the first that looks like a spec. */
    public List<IHttpRequestResponse> discover(IHttpRequestResponse seed) {
        IHttpService svc = seed.getHttpService();
        for (String path : COMMON_SPEC_PATHS) {
            String json = fetch(svc, path);
            if (looksLikeSpec(json)) {
                if (stdout != null) stdout.println("[OpenAPI] spec bulundu: " + path);
                return parse(json, svc);
            }
        }
        return new ArrayList<>();
    }

    /** Fetch + parse a spec from an explicit URL; generated endpoints target that URL's host. */
    public List<IHttpRequestResponse> fromUrl(String specUrl, IHttpService fallback) {
        try {
            URL u = new URL(specUrl);
            boolean https = "https".equalsIgnoreCase(u.getProtocol());
            int port = u.getPort() == -1 ? (https ? 443 : 80) : u.getPort();
            IHttpService svc = helpers.buildHttpService(u.getHost(), port, https);
            String path = u.getFile() == null || u.getFile().isEmpty() ? "/" : u.getFile();
            String json = fetch(svc, path);
            return looksLikeSpec(json) ? parse(json, svc) : new ArrayList<>();
        } catch (Exception e) {
            if (stdout != null) stdout.println("[OpenAPI] URL hatası: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    /** Parse a spec JSON string into synthetic request endpoints against {@code svc}. */
    public List<IHttpRequestResponse> parse(String json, IHttpService svc) {
        List<IHttpRequestResponse> out = new ArrayList<>();
        try {
            JSONObject root = new JSONObject(json);
            String basePath = "";
            if (root.has("basePath")) {                       // Swagger v2
                basePath = root.optString("basePath", "");
            } else if (root.has("servers")) {                 // OpenAPI v3
                JSONArray servers = root.optJSONArray("servers");
                if (servers != null && servers.length() > 0) {
                    JSONObject s0 = servers.optJSONObject(0);
                    if (s0 != null) basePath = pathOf(s0.optString("url", ""));
                }
            }
            JSONObject paths = root.optJSONObject("paths");
            if (paths == null) return out;
            for (String rawPath : paths.keySet()) {
                JSONObject item = paths.optJSONObject(rawPath);
                if (item == null) continue;
                String full = join(basePath, PATH_PARAM.matcher(rawPath).replaceAll("1"));
                for (String m : METHODS) {
                    if (!item.has(m)) continue;
                    boolean body = !"get".equals(m) && !"delete".equals(m);
                    out.add(new SyntheticHttpRequestResponse(
                            buildRequest(m.toUpperCase(), full, svc.getHost(), body), svc));
                    if (out.size() >= MAX_ENDPOINTS) {
                        if (stdout != null) stdout.println("[OpenAPI] " + MAX_ENDPOINTS + " endpoint sınırına ulaşıldı, kırpıldı.");
                        return out;
                    }
                }
            }
        } catch (Exception e) {
            if (stdout != null) stdout.println("[OpenAPI] parse hatası: " + e.getMessage());
        }
        return out;
    }

    private byte[] buildRequest(String method, String path, String host, boolean withBody) {
        List<String> h = new ArrayList<>();
        h.add(method + " " + (path.startsWith("/") ? path : "/" + path) + " HTTP/1.1");
        h.add("Host: " + host);
        h.add("User-Agent: " + UA);
        h.add("Accept: */*");
        h.add("Connection: close");
        byte[] bodyBytes;
        if (withBody) {
            h.add("Content-Type: application/json");
            bodyBytes = "{}".getBytes(StandardCharsets.UTF_8);
        } else {
            bodyBytes = new byte[0];
        }
        return helpers.buildHttpMessage(h, bodyBytes);
    }

    private String fetch(IHttpService svc, String path) {
        try {
            byte[] req = buildRequest("GET", path, svc.getHost(), false);
            IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, req);
            byte[] resp = rr.getResponse();
            if (resp == null) return null;
            IResponseInfo ri = helpers.analyzeResponse(resp);
            if (ri.getStatusCode() != 200) return null;
            int off = ri.getBodyOffset();
            return new String(resp, off, Math.max(0, resp.length - off), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean looksLikeSpec(String json) {
        if (json == null) return false;
        String s = json.trim();
        return s.startsWith("{") && (s.contains("\"swagger\"") || s.contains("\"openapi\"")) && s.contains("\"paths\"");
    }

    private String pathOf(String serverUrl) {
        if (serverUrl == null || serverUrl.isEmpty()) return "";
        try {
            if (serverUrl.startsWith("http://") || serverUrl.startsWith("https://")) {
                String p = new URL(serverUrl).getPath();
                return p == null ? "" : p;
            }
            return serverUrl; // relative server url is already a base path
        } catch (Exception e) {
            return "";
        }
    }

    private String join(String basePath, String path) {
        if (basePath == null || basePath.isEmpty() || "/".equals(basePath)) return path;
        String b = basePath.endsWith("/") ? basePath.substring(0, basePath.length() - 1) : basePath;
        return path.startsWith("/") ? b + path : b + "/" + path;
    }
}
