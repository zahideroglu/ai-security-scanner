package burp.report;

import java.nio.charset.StandardCharsets;

/**
 * One ordered HTTP transaction in a finding's REPRODUCTION BUNDLE — the self-contained proof trail a
 * defender can replay (in Burp Repeater, as {@code curl}, or as HAR) WITHOUT re-running AppSecHunter.
 *
 * <p>A confirmed IDOR/BOLA finding ships up to four roles, in order:
 * <ol>
 *   <li>{@link Role#OWN} — the attacker requests their OWN object id (normal, authorised behaviour);</li>
 *   <li>{@link Role#ATTACK} — the attacker swaps in the victim's id;</li>
 *   <li>{@link Role#CONTROL} — a definitely-invalid id (negative control, proves the id is honoured);</li>
 *   <li>{@link Role#PUBLIC} — the same request stripped of auth (proves the object is not simply public).</li>
 * </ol>
 * The {@link Role#VICTIM} role (the victim's own session fetching the same id) is attached by the
 * ground-truth two-session BOLA pass when it is available.
 *
 * <p>This is purely a RECORD of transactions the verifier already performed against the authorised
 * target — not an exploit generator. The raw bytes are what Burp captured; nothing is re-sent here.
 *
 * @author Zahid Eroglu
 */
public final class ReproStep {

    public enum Role { OWN, ATTACK, CONTROL, PUBLIC, VICTIM }

    private final Role role;
    private final String detail;      // short human note (e.g. the swapped id "41 → 42")
    private final byte[] request;     // full request bytes as Burp sent them (may be null)
    private final byte[] response;    // full response bytes as Burp received them (may be null)
    private final String host;
    private final int port;
    private final boolean https;

    public ReproStep(Role role, String detail, byte[] request, byte[] response,
                     String host, int port, boolean https) {
        this.role = role;
        this.detail = detail == null ? "" : detail;
        this.request = request;
        this.response = response;
        this.host = host == null ? "" : host;
        this.port = port;
        this.https = https;
    }

    // ----- convenience factories (keep the judge call sites readable) -----
    public static ReproStep own(byte[] req, byte[] resp, String host, int port, boolean https, String detail) {
        return new ReproStep(Role.OWN, detail, req, resp, host, port, https);
    }
    public static ReproStep attack(byte[] req, byte[] resp, String host, int port, boolean https, String detail) {
        return new ReproStep(Role.ATTACK, detail, req, resp, host, port, https);
    }
    public static ReproStep control(byte[] req, byte[] resp, String host, int port, boolean https, String detail) {
        return new ReproStep(Role.CONTROL, detail, req, resp, host, port, https);
    }
    public static ReproStep publicProbe(byte[] req, byte[] resp, String host, int port, boolean https, String detail) {
        return new ReproStep(Role.PUBLIC, detail, req, resp, host, port, https);
    }
    public static ReproStep victim(byte[] req, byte[] resp, String host, int port, boolean https, String detail) {
        return new ReproStep(Role.VICTIM, detail, req, resp, host, port, https);
    }

    public Role getRole() { return role; }
    public String getDetail() { return detail; }
    public byte[] getRequest() { return request; }
    public byte[] getResponse() { return response; }
    public boolean hasRequest() { return request != null && request.length > 0; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public boolean isHttps() { return https; }

    /** Full request as text (ISO-8859-1 preserves raw bytes 1:1), "" when absent. */
    public String requestText() {
        return request == null ? "" : new String(request, StandardCharsets.ISO_8859_1);
    }

    /** Response as text, capped so a huge body does not bloat the bundle; "" when absent. */
    public String responseText() {
        if (response == null) return "";
        int cap = Math.min(response.length, 32768);
        return new String(response, 0, cap, StandardCharsets.ISO_8859_1);
    }
}
