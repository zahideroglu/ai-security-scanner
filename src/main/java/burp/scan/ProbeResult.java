package burp.scan;

/**
 * Result of sending one {@link Probe}.
 *
 * @author Zahid Eroglu
 */
public class ProbeResult {
    public Probe probe;
    public int statusCode;
    public long responseTimeMs;
    public int responseLength;          // body length
    public String responseHeaders = ""; // joined
    public String bodySnippet = "";     // first ~8KB of body
    public byte[] rawRequest;
    public byte[] rawResponse;
    public String error;

    public boolean ok() {
        return error == null;
    }
}
