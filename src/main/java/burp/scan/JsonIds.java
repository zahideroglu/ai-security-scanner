package burp.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts id-candidate fields from a JSON body at ANY depth — nested objects ({@code {"account":{"id":1}}})
 * and array elements ({@code [{"orderId":1},{"orderId":2}]}) — which Burp's flat {@code IParameter} model
 * does NOT surface, so IDOR/BOLA can swap a nested/array id, not just top-level ones.
 *
 * <p>Each {@link Hit} carries the value's CHARACTER offset inside the body (inside the quotes for strings),
 * so the caller can splice it surgically and keep the rest of the body byte-for-byte identical. Pure CPU,
 * regex-based (no full JSON parse → no key reordering / reformatting that a strict server might reject).
 *
 * @author Zahid Eroglu
 */
public final class JsonIds {

    private JsonIds() {}

    public static final class Hit {
        public final String name;     // JSON field name
        public final String value;    // current value (string content or integer text)
        public final int valueStart;  // char offset in the body of the value (inside quotes for strings)
        public final int valueEnd;
        Hit(String name, String value, int valueStart, int valueEnd) {
            this.name = name; this.value = value; this.valueStart = valueStart; this.valueEnd = valueEnd;
        }
    }

    // "key" : "string"   |   "key" : 123    (quoted strings and integers; bool/null/float deliberately skipped)
    private static final Pattern KV = Pattern.compile(
            "\"([A-Za-z0-9_]{1,64})\"\\s*:\\s*(?:\"((?:\\\\.|[^\"\\\\]){0,200})\"|(-?\\d{1,18}))");

    /** All id-CANDIDATE fields (string or integer value) at any depth, capped for safety. */
    public static List<Hit> extract(String body) {
        List<Hit> hits = new ArrayList<>();
        if (body == null || body.length() < 2) return hits;
        try {
            Matcher m = KV.matcher(body);
            int n = 0;
            while (m.find() && n++ < 80) {
                if (m.group(2) != null) {            // quoted string value → splice inside the quotes
                    hits.add(new Hit(m.group(1), m.group(2), m.start(2), m.end(2)));
                } else if (m.group(3) != null) {     // integer value
                    hits.add(new Hit(m.group(1), m.group(3), m.start(3), m.end(3)));
                }
            }
        } catch (Exception ignore) {
            // best-effort: malformed JSON → no hits
        }
        return hits;
    }
}
