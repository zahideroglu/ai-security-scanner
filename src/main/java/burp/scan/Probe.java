package burp.scan;

/**
 * A single deterministic test request: inject {@code payload} at {@code location}
 * (param/path/header/jwt/cookie/body) of the base request.
 *
 * @author Zahid Eroglu
 */
public class Probe {
    public String moduleId;
    public String description;
    public String location = "param";   // param|path|header|jwt|cookie|body
    public String targetParameter = "";
    public String payload = "";
    public String attackType;           // -> Finding type
    public String severity = "Medium";
    public Object tag;                  // module-private state
    public byte[] rawRequest;           // if set, sent as-is (bypasses buildModifiedRequest)
    public burp.IHttpService overrideService; // if set, sent here instead of the base service (e.g. port 80)

    public Probe(String moduleId, String description, String location,
                 String targetParameter, String payload, String attackType, String severity) {
        this.moduleId = moduleId;
        this.description = description;
        this.location = location;
        this.targetParameter = targetParameter != null ? targetParameter : "";
        this.payload = payload != null ? payload : "";
        this.attackType = attackType;
        this.severity = severity;
    }
}
