package burp;

import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Single source of truth for API credentials, kept OUT of version control.
 *
 * <p>Secrets are never hardcoded in source any more. Each value is resolved at
 * runtime with this precedence:
 * <ol>
 *   <li>Environment variable (for CI / headless runs), e.g. {@code APPSEC_API_KEY}.</li>
 *   <li>JSON file at {@code ~/.appsechunter/secrets.json} (gitignored by location —
 *       it lives in the user home, outside any repo, so it can never be committed).</li>
 *   <li>Empty string — the user then enters the value in Settings → API, which Burp
 *       persists in its own extension-settings store.</li>
 * </ol>
 *
 * <p>Expected {@code ~/.appsechunter/secrets.json} shape (all keys optional):
 * <pre>
 * {
 *   "apiKey": "sk-lm-...",
 *   "gatewayUsername": "...",
 *   "gatewayPassword": "...",
 *   "gatewayClientId": "...",
 *   "gatewayClientSecret": "...",
 *   "gatewayRequestedSubject": "..."
 * }
 * </pre>
 *
 * <p>The file is read once and cached. Any failure (missing file, bad JSON) is
 * swallowed and treated as "no secret configured" — it never breaks extension load.
 *
 * @author Zahid Eroglu
 */
public final class SecretsProvider {

    private static final String FILE_PATH =
            System.getProperty("user.home") + File.separator + ".appsechunter" + File.separator + "secrets.json";

    private static volatile JSONObject cache;     // loaded once, lazily (per-user home file)
    private static volatile boolean loaded;
    private static volatile JSONObject bundledCache;   // loaded once, lazily (jar-bundled /secrets.json)
    private static volatile boolean bundledLoaded;

    private SecretsProvider() {}

    // ---- Public accessors (env var override → file → "") ----------------

    public static String apiKey() {
        return resolve("APPSEC_API_KEY", "apiKey");
    }

    public static String gatewayUsername() {
        return resolve("APPSEC_GW_USERNAME", "gatewayUsername");
    }

    public static String gatewayPassword() {
        return resolve("APPSEC_GW_PASSWORD", "gatewayPassword");
    }

    public static String gatewayClientId() {
        return resolve("APPSEC_GW_CLIENT_ID", "gatewayClientId");
    }

    public static String gatewayClientSecret() {
        return resolve("APPSEC_GW_CLIENT_SECRET", "gatewayClientSecret");
    }

    public static String gatewayRequestedSubject() {
        return resolve("APPSEC_GW_SUBJECT", "gatewayRequestedSubject");
    }

    /** True if secrets are available from any source (per-user file or the jar-bundled defaults). */
    public static boolean hasFile() {
        return new File(FILE_PATH).isFile() || loadBundled() != null;
    }

    public static String filePath() {
        return FILE_PATH;
    }

    // ---- Internals ------------------------------------------------------

    private static String resolve(String envVar, String jsonKey) {
        String env = System.getenv(envVar);
        if (env != null && !env.trim().isEmpty()) {
            return env.trim();                       // 1) environment variable (highest priority)
        }
        String fromFile = valueFrom(load(), jsonKey);       // 2) per-user ~/.appsechunter/secrets.json
        if (!fromFile.isEmpty()) {
            return fromFile;
        }
        return valueFrom(loadBundled(), jsonKey);            // 3) /secrets.json bundled in the distributed jar
    }

    /** Non-blank trimmed value for {@code key}, or "". */
    private static String valueFrom(JSONObject json, String key) {
        if (json == null) return "";
        String v = json.optString(key, "");
        return (v != null && !v.trim().isEmpty()) ? v.trim() : "";
    }

    private static JSONObject load() {
        if (loaded) {
            return cache;
        }
        synchronized (SecretsProvider.class) {
            if (loaded) {
                return cache;
            }
            try {
                File f = new File(FILE_PATH);
                if (f.isFile()) {
                    String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                    cache = new JSONObject(content);
                }
            } catch (Exception ignore) {
                // Missing / malformed secrets file → treat as "no secret configured".
                cache = null;
            } finally {
                loaded = true;
            }
            return cache;
        }
    }

    /** Optional secrets bundled INSIDE the jar at {@code /secrets.json} (from src/main/resources/secrets.json,
     *  which is gitignored — never committed, only present in the locally-built jar). This lets the team run
     *  ZERO-CONFIG: the builder drops their keys in resources, builds, and ships the jar; every teammate that
     *  loads it gets the keys. A per-user env var or {@code ~/.appsechunter/secrets.json} still overrides it. */
    private static JSONObject loadBundled() {
        if (bundledLoaded) {
            return bundledCache;
        }
        synchronized (SecretsProvider.class) {
            if (bundledLoaded) {
                return bundledCache;
            }
            try (java.io.InputStream is = SecretsProvider.class.getResourceAsStream("/secrets.json")) {
                if (is != null) {
                    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = is.read(buf)) >= 0) {
                        bos.write(buf, 0, n);
                    }
                    bundledCache = new JSONObject(new String(bos.toByteArray(), StandardCharsets.UTF_8));
                }
            } catch (Exception ignore) {
                bundledCache = null;
            } finally {
                bundledLoaded = true;
            }
            return bundledCache;
        }
    }
}
