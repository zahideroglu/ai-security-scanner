package burp.authz;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ground-truth object-ownership model: which concrete objects each identity is
 * known to own/access (observed returning HTTP 200 for that identity). This is the
 * basis for PROVABLE BOLA: "object O belongs to identity B, yet identity A can
 * access it." Built by {@link AccessModelBuilder}; consumed by {@link ScenarioAccessTester}.
 *
 * @author Zahid Eroglu
 */
public class AccessModel {

    /** One object an identity is known to own/access. */
    public static class OwnedObject {
        public final String role;     // owning identity
        public final String type;     // object type (path segment / id-param name)
        public final String id;       // the object identifier value
        public final String location; // "path" | "param"
        public final String param;    // path segment value or parameter name
        public final IHttpRequestResponse request; // the request that accessed it (carries the endpoint)

        public OwnedObject(String role, String type, String id, String location, String param,
                           IHttpRequestResponse request) {
            this.role = role; this.type = type; this.id = id;
            this.location = location; this.param = param; this.request = request;
        }

        public String key() { return type.toLowerCase() + "|" + id; }
    }

    public final Map<String, List<OwnedObject>> ownedByRole = new LinkedHashMap<>();
    public final List<String> roles = new ArrayList<>();
    private final Set<String> seen = new HashSet<>();

    /** Record an owned object (deduped per role+type+id). */
    public void add(OwnedObject o) {
        if (o == null || o.id == null || o.id.isEmpty()) return;
        String k = o.role + "|" + o.key();
        if (!seen.add(k)) return;
        List<OwnedObject> list = ownedByRole.get(o.role);
        if (list == null) { list = new ArrayList<>(); ownedByRole.put(o.role, list); }
        list.add(o);
        if (!roles.contains(o.role)) roles.add(o.role);
    }

    public List<OwnedObject> ownedBy(String role) {
        List<OwnedObject> l = ownedByRole.get(role);
        return l != null ? l : Collections.<OwnedObject>emptyList();
    }

    /** Objects owned by OTHER identities (the cross-owner BOLA targets for {@code role}). */
    public List<OwnedObject> objectsNotOwnedBy(String role) {
        Set<String> mine = new HashSet<>();
        for (OwnedObject o : ownedBy(role)) mine.add(o.key());
        List<OwnedObject> out = new ArrayList<>();
        for (Map.Entry<String, List<OwnedObject>> e : ownedByRole.entrySet()) {
            if (e.getKey().equals(role)) continue;
            for (OwnedObject o : e.getValue()) if (!mine.contains(o.key())) out.add(o);
        }
        return out;
    }

    /** Attacker's own object of the same type (a baseline reference), or null. */
    public OwnedObject ownObjectOfType(String role, String type) {
        for (OwnedObject o : ownedBy(role)) {
            if (o.type.equalsIgnoreCase(type)) return o;
        }
        return null;
    }

    public int totalObjects() {
        int n = 0;
        for (List<OwnedObject> l : ownedByRole.values()) n += l.size();
        return n;
    }

    public String summary() {
        StringBuilder sb = new StringBuilder("ACCESS MODEL (ground-truth ownership):\n");
        for (String role : roles) {
            sb.append("  ").append(role).append(": ");
            List<OwnedObject> l = ownedBy(role);
            int show = Math.min(8, l.size());
            for (int i = 0; i < show; i++) sb.append(l.get(i).type).append(":").append(l.get(i).id).append(" ");
            if (l.size() > show) sb.append("… (+").append(l.size() - show).append(")");
            sb.append("\n");
        }
        return sb.toString();
    }
}
