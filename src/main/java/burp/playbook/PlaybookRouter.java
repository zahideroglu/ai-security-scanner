package burp.playbook;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Settings;
import burp.authz.OwnershipOracle;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Decides which specialized playbooks are worth running against a given endpoint.
 *
 * {@link #eligible} applies the mode-independent gates (focus toggle, requires-sessions,
 * multi-step seed cap). {@link #heuristicFilter} narrows that set using cheap request
 * signals (no LLM). The orchestrator picks: "all" → eligible; "heuristic" →
 * heuristicFilter(eligible); "ai" → an LLM triage over eligible.
 *
 * @author Zahid Eroglu
 */
public class PlaybookRouter {

    private static final Set<String> ID_NAMES = new HashSet<>(Arrays.asList(
            "id", "user", "userid", "user_id", "uid", "account", "accountid", "account_id",
            "customer", "customerid", "customer_id", "order", "orderid", "order_id",
            "invoice", "doc", "docid", "file", "fileid", "pid", "objectid", "object_id"));

    private static final Set<String> ECON_NAMES = new HashSet<>(Arrays.asList(
            "price", "amount", "qty", "quantity", "total", "cost", "discount", "coupon",
            "voucher", "balance", "credit", "role", "isadmin", "admin", "status", "state",
            "approved", "verified", "isverified", "permission", "scope"));

    /** A JWT anywhere in the raw request (Authorization, Cookie, custom header, or body):
     *  header.payload both base64url-encoded JSON ("eyJ..."), with an optional signature
     *  (empty for alg:none). Strong, low-FP signal. */
    private static final java.util.regex.Pattern JWT_RE = java.util.regex.Pattern.compile(
            "eyJ[A-Za-z0-9_-]{6,}\\.eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]*");

    private final IExtensionHelpers helpers;
    private final Settings settings;
    private final boolean haveSessions;

    public PlaybookRouter(IExtensionHelpers helpers, Settings settings, boolean haveSessions) {
        this.helpers = helpers;
        this.settings = settings;
        this.haveSessions = haveSessions;
    }

    /** True if the request carries a JWT in ANY header (Authorization/Cookie/custom) or the body.
     *  The auth-jwt playbook is skipped on endpoints with no token to forge/tamper — so the JWT
     *  agent only runs against history requests that actually use a JWT. */
    public static boolean requestHasJwt(IHttpRequestResponse msg) {
        if (msg == null || msg.getRequest() == null) return false;
        try {
            return JWT_RE.matcher(new String(msg.getRequest(), "UTF-8")).find();
        } catch (Exception e) {
            return false;
        }
    }

    /** Mode-independent eligibility: focus toggle + requires-sessions + multi-step seed cap. */
    public List<Playbook> eligible(PlaybookLibrary lib, int seedIndex) {
        List<Playbook> out = new ArrayList<>();
        for (Playbook p : lib.all()) {
            if (!focusEnabled(p)) continue;
            if (p.requiresSessions && !haveSessions) continue;
            if ("multistep-chain".equals(p.id) && seedIndex >= 3) continue; // K=3 seed cap
            out.add(p);
        }
        // Faz 3: run in the agreed depth priority — access-control/BOLA first, then multi-step chains,
        // then business logic, then auth/JWT. Earlier playbooks claim the step/token budget first.
        out.sort((a, b) -> Integer.compare(priority(a.id), priority(b.id)));
        return out;
    }

    /** Lower = runs first. Mirrors the agreed depth priority: BOLA > multi-step > business-logic > auth. */
    private static int priority(String id) {
        if (id == null) return 50;
        switch (id) {
            case "access-control-idor": return 0;
            case "bola-multisession":   return 1;
            case "multistep-chain":     return 2;
            case "business-logic":      return 3;
            case "mass-assignment":     return 4;
            case "auth-jwt":            return 5;
            default:                    return 50; // custom playbooks last
        }
    }

    /** Narrow an eligible set to playbooks whose signals appear on this endpoint. */
    public List<Playbook> heuristicFilter(List<Playbook> eligible, IRequestInfo ri, IHttpRequestResponse msg) {
        Signals s = signals(ri, msg);
        List<Playbook> out = new ArrayList<>();
        for (Playbook p : eligible) {
            if (matches(p, s)) out.add(p);
        }
        // Never return empty for an input-bearing endpoint: fall back to business-logic if present.
        if (out.isEmpty() && s.bodyParams) {
            for (Playbook p : eligible) {
                if ("business-logic".equals(p.id)) { out.add(p); break; }
            }
        }
        return out;
    }

    /** Hard, mode-independent precondition filter: keep only playbooks whose required signal is present
     *  on this request (same match as {@link #heuristicFilter}, applied in EVERY router mode so a playbook
     *  never runs with nothing to test — no JWT / no id / no body|econ → skip). */
    public List<Playbook> applyPreconditions(List<Playbook> chosen, IRequestInfo ri, IHttpRequestResponse msg) {
        if (chosen == null || chosen.isEmpty()) return chosen;
        Signals s = signals(ri, msg);
        List<Playbook> out = new ArrayList<>(chosen.size());
        for (Playbook p : chosen) {
            if (matches(p, s)) out.add(p);
        }
        return out;
    }

    private boolean matches(Playbook p, Signals s) {
        switch (p.id) {
            case "auth-jwt":            return s.hasJwt;          // real JWT in the request, not just any auth header
            case "access-control-idor": return s.idLike;
            case "bola-multisession":   return s.idLike;          // requires-sessions gated in eligible()
            case "business-logic":      return s.bodyParams || s.econ;
            case "mass-assignment":     return s.bodyParams;
            case "multistep-chain":     return true;              // seed-capped in eligible()
            default:                    return true;              // custom playbooks: always relevant
        }
    }

    private boolean focusEnabled(Playbook p) {
        String fk = p.focusKey == null ? "" : p.focusKey;
        switch (fk) {
            case "accessControl": return settings.isAgentFocusAccessControl();
            case "businessLogic": return settings.isAgentFocusBusinessLogic();
            case "authJwt":       return settings.isAgentFocusAuthJwt();
            case "multiStep":     return settings.isAgentFocusMultiStep();
            default:              return true; // blank/unknown focus → always eligible
        }
    }

    // ----- signal extraction ----------------------------------------------

    private static class Signals {
        boolean hasAuth, hasJwt, idLike, bodyParams, econ;
    }

    private Signals signals(IRequestInfo ri, IHttpRequestResponse msg) {
        Signals s = new Signals();
        try {
            String method = ri.getMethod();
            String path = ri.getUrl().getPath() == null ? "" : ri.getUrl().getPath().toLowerCase();

            s.hasAuth = header(ri, "authorization") != null || header(ri, "cookie") != null
                    || header(ri, "x-auth-token") != null || header(ri, "x-api-key") != null;
            s.hasJwt = requestHasJwt(msg); // real JWT anywhere in the request → gates the auth-jwt playbook

            // numeric or uuid-looking path segment
            for (String seg : path.split("/")) {
                if (seg.matches("\\d{1,}") || seg.matches("[0-9a-f]{8}-[0-9a-f-]{12,}")) { s.idLike = true; break; }
            }

            boolean nonReadMethod = !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method);
            for (IParameter pr : ri.getParameters()) {
                byte t = pr.getType();
                String name = pr.getName() == null ? "" : pr.getName().toLowerCase(Locale.ROOT);
                if (t == IParameter.PARAM_BODY || t == IParameter.PARAM_JSON) {
                    if (nonReadMethod) s.bodyParams = true;
                }
                if (ID_NAMES.contains(name) || OwnershipOracle.isAccountOwnershipParam(name)) s.idLike = true;
                if (ECON_NAMES.contains(name)) s.econ = true;
            }
        } catch (Exception ignore) {
        }
        return s;
    }

    private String header(IRequestInfo ri, String name) {
        String n = name.toLowerCase() + ":";
        for (String h : ri.getHeaders()) {
            if (h.toLowerCase().startsWith(n)) {
                int c = h.indexOf(':');
                return c >= 0 ? h.substring(c + 1).trim() : "";
            }
        }
        return null;
    }
}
