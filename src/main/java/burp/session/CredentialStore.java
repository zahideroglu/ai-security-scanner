package burp.session;

import burp.IBurpExtenderCallbacks;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Encrypted-at-rest store for {@link LoginProfile}s (so re-login works on a later re-test of the
 * same app). Credentials are NEVER written as plaintext: profiles are AES/GCM encrypted, with the
 * key kept in the OS keychain (macOS {@code security}) when available, or derived from a one-time
 * master password as a fallback. The encrypted blob is persisted via Burp's extension settings.
 *
 * @author Zahid Eroglu
 */
public class CredentialStore {

    private static final String SETTING_PREFIX = "appsechunter.cred.";
    private static final String KEYCHAIN_SERVICE = "AppSecHunter";
    private static final String KEYCHAIN_ACCOUNT = "credstore-key";

    private final IBurpExtenderCallbacks callbacks;
    private final PrintWriter stderr;
    private SecretKey key;             // resolved lazily and cached
    private String masterPassword;     // fallback when the OS keychain is unavailable

    public CredentialStore(IBurpExtenderCallbacks callbacks, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.stderr = stderr;
    }

    /** Set a master password (used only if the OS keychain is unavailable). Resets the cached key. */
    public void setMasterPassword(String p) {
        this.masterPassword = (p == null || p.isEmpty()) ? null : p;
        this.key = null;
    }

    public boolean isReady() {
        try { key(); return true; } catch (Exception e) { return false; }
    }

    public void save(LoginProfile p) throws Exception {
        if (p == null || p.host == null || p.host.isEmpty()) throw new IllegalArgumentException("profile/host required");
        callbacks.saveExtensionSetting(SETTING_PREFIX + p.host, encrypt(p.toJson().toString()));
    }

    public LoginProfile load(String host) {
        if (host == null || host.isEmpty()) return null;
        String enc = callbacks.loadExtensionSetting(SETTING_PREFIX + host);
        if (enc == null || enc.isEmpty()) return null;
        try {
            return LoginProfile.fromJson(new JSONObject(decrypt(enc)));
        } catch (Exception e) {
            if (stderr != null) stderr.println("[CredentialStore] load/decrypt failed for " + host + ": " + e.getMessage());
            return null;
        }
    }

    public void delete(String host) {
        if (host != null && !host.isEmpty()) callbacks.saveExtensionSetting(SETTING_PREFIX + host, null);
    }

    // ---- crypto -----------------------------------------------------------

    public String encrypt(String plain) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public String decrypt(String b64) throws Exception {
        byte[] in = Base64.getDecoder().decode(b64);
        byte[] iv = new byte[12];
        System.arraycopy(in, 0, iv, 0, 12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, iv));
        byte[] pt = c.doFinal(in, 12, in.length - 12);
        return new String(pt, StandardCharsets.UTF_8);
    }

    private SecretKey key() throws Exception {
        if (key != null) return key;
        // 1) OS keychain (macOS). Transparent: no prompt on the same machine.
        try {
            String b64 = keychainGet();
            if (b64 == null) b64 = keychainCreate();
            if (b64 != null) {
                key = new SecretKeySpec(Base64.getDecoder().decode(b64.trim()), "AES");
                return key;
            }
        } catch (Exception ignore) {
            // keychain unavailable (non-mac, locked, sandboxed) -> fall through to master password
        }
        // 2) Master-password fallback (PBKDF2). Requires the user to set one this session.
        if (masterPassword != null) {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = "appsechunter::credstore::v1".getBytes(StandardCharsets.UTF_8);
            PBEKeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, 120_000, 256);
            key = new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");
            return key;
        }
        throw new IllegalStateException("No encryption key: OS keychain unavailable and no master password set.");
    }

    private String keychainGet() throws Exception {
        Process p = new ProcessBuilder("security", "find-generic-password",
                "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w").redirectErrorStream(false).start();
        String out = readFirstLine(p);
        return p.waitFor() == 0 && out != null && !out.isEmpty() ? out : null;
    }

    private String keychainCreate() throws Exception {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String b64 = Base64.getEncoder().encodeToString(raw);
        Process p = new ProcessBuilder("security", "add-generic-password",
                "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", b64, "-U").start();
        return p.waitFor() == 0 ? b64 : null;
    }

    private String readFirstLine(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line = r.readLine();
            return line == null ? null : line.trim();
        } catch (Exception e) {
            return null;
        }
    }
}
