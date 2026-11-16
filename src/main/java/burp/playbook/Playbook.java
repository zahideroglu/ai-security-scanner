package burp.playbook;

/**
 * One specialized vulnerability-hunting "skill" for the agentic pentester.
 * Loaded from a Markdown file (bundled or external): an optional front-matter
 * block (key: value lines between two `---` lines) plus a free-form body that
 * is injected into the agent's system prompt as its STRATEGY.
 *
 * @author Zahid Eroglu
 */
public class Playbook {

    public final String id;              // stable key (filename stem)
    public final String title;           // human label, e.g. "Authentication & JWT Bypass"
    public final String vulnClass;       // canonical Finding type for dedup/reporting
    public final String focusKey;        // accessControl|businessLogic|authJwt|multiStep|"" (maps to Settings toggles)
    public final String severityHint;    // default severity the agent should lean toward
    public final boolean requiresSessions; // router skips this unless >=1 identity is saved
    public final String markdown;        // body (after front-matter) = the agent's strategy doc

    public Playbook(String id, String title, String vulnClass, String focusKey,
                    String severityHint, boolean requiresSessions, String markdown) {
        this.id = id;
        this.title = title;
        this.vulnClass = vulnClass;
        this.focusKey = focusKey;
        this.severityHint = severityHint;
        this.requiresSessions = requiresSessions;
        this.markdown = markdown;
    }

    /**
     * Parse a playbook from raw markdown. The front-matter is the block between the
     * first two lines that are exactly "---". Missing keys fall back to sensible
     * defaults derived from {@code fallbackId}. Never throws — returns a best-effort
     * Playbook so a malformed file still yields a usable (if generic) agent.
     */
    public static Playbook parse(String fallbackId, String raw) {
        String id = fallbackId;
        String title = humanize(fallbackId);
        String vulnClass = title;
        String focusKey = "";
        String severityHint = "Medium";
        boolean requiresSessions = false;
        String body = raw == null ? "" : raw;

        try {
            String[] lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n", -1);
            int i = 0;
            // skip leading blank lines
            while (i < lines.length && lines[i].trim().isEmpty()) i++;
            if (i < lines.length && lines[i].trim().equals("---")) {
                int start = i + 1;
                int end = -1;
                for (int j = start; j < lines.length; j++) {
                    if (lines[j].trim().equals("---")) { end = j; break; }
                }
                if (end > 0) {
                    for (int j = start; j < end; j++) {
                        String line = lines[j];
                        int c = line.indexOf(':');
                        if (c <= 0) continue;
                        String key = line.substring(0, c).trim().toLowerCase();
                        String val = line.substring(c + 1).trim();
                        switch (key) {
                            case "id": if (!val.isEmpty()) id = val; break;
                            case "title": if (!val.isEmpty()) title = val; break;
                            case "vulnclass": if (!val.isEmpty()) vulnClass = val; break;
                            case "focuskey": focusKey = val; break;
                            case "severityhint": if (!val.isEmpty()) severityHint = val; break;
                            case "requiressessions": requiresSessions = val.equalsIgnoreCase("true"); break;
                            default: break;
                        }
                    }
                    // body = everything after the closing '---'
                    StringBuilder sb = new StringBuilder();
                    for (int j = end + 1; j < lines.length; j++) {
                        sb.append(lines[j]);
                        if (j < lines.length - 1) sb.append('\n');
                    }
                    body = sb.toString().trim();
                }
            }
        } catch (Exception ignore) {
            // keep defaults + raw body
        }
        return new Playbook(id, title, vulnClass, focusKey, severityHint, requiresSessions, body);
    }

    private static String humanize(String stem) {
        if (stem == null || stem.isEmpty()) return "Playbook";
        return stem.replace('-', ' ').replace('_', ' ');
    }
}
