package burp.engine;

import burp.Settings;

/**
 * Compact, per-vuln-class technique modules injected into the agent's system prompt.
 *
 * <p>Rather than a single one-line focus hint, each in-scope focus area contributes a tight
 * "technique library" of concrete detection patterns, bypass tricks and chain templates — the
 * kind of knowledge a human access-control tester carries. Modules are loaded ONLY for the focus
 * areas the user enabled, so the extra prompt cost is paid only where it earns its keep.
 *
 * <p>Content is deliberately terse (high signal, few tokens): the agent already has the
 * ground-truth ownership map and the ReAct action schema; this just sharpens WHAT it tries.
 *
 * @author Zahid Eroglu
 */
public final class AttackTechniques {

    private AttackTechniques() {}

    /** Assemble the technique library for whichever focus areas are enabled. Empty if none. */
    public static String forFocus(Settings s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        if (s.isAgentFocusAccessControl()) sb.append(ACCESS_CONTROL);
        if (s.isAgentFocusBusinessLogic())  sb.append(BUSINESS_LOGIC);
        if (s.isAgentFocusAuthJwt())        sb.append(AUTH_JWT);
        if (s.isAgentFocusMultiStep())      sb.append(MULTI_STEP);
        if (sb.length() == 0) return "";
        return "\n## TECHNIQUE LIBRARY (apply only the patterns relevant to the target in front of you)\n"
                + sb;
    }

    private static final String ACCESS_CONTROL =
        "### IDOR / BOLA / BFLA\n"
      + "- Object ids hide in EVERY location — path segments, query params, the request body (including nested `{\"user\":{\"id\":N}}` and arrays `[{\"orderId\":N}]`), custom headers (X-User-Id, X-Account), cookies, and JWT claims (sub, uid, tenant). Burp will not correlate ownership for you; that is your job.\n"
      + "- A confirmed BOLA is a FOREIGN owner's id requested under YOUR identity that returns THEIR data (200 + fields that belong to the other owner). A bare 200, a 403, an empty body, or your own data echoed back is NOT a finding.\n"
      + "- Reuse ids the app already revealed to you (list/search/export/sibling responses, the ground-truth ownership map) instead of brute-forcing unguessable UUIDs/hashes. For sequential ids, try ±1 and nearby values.\n"
      + "- BFLA (function level): keep the id, change the METHOD (GET→PUT/PATCH/DELETE), or hit admin/internal/bulk/export routes under a low-privilege identity.\n"
      + "- Indirect IDOR surfaces: report/export/search filters (?userId=, ?account=), GraphQL node(id:), file/attachment/invoice/ticket download paths, numeric references in redirects.\n"
      + "- Access-check bypass tricks: add/strip a trailing slash; change id case or URL-encoding; parameter pollution (duplicate the id param); wrap the id (`[N]`, `{\"id\":N}`); switch content-type (json↔form); add a method-override header (X-HTTP-Method-Override).\n";

    private static final String BUSINESS_LOGIC =
        "### Business logic & mass assignment\n"
      + "- Mass assignment: on create/update (POST/PUT/PATCH) add client-controlled fields the UI never sends — role, isAdmin, is_verified, status, approved, price, balance, userId, tenantId. Confirm the server HONORED them with a follow-up GET; a silently-ignored field is not a bug.\n"
      + "- Value tampering: negative / zero / fractional / overflow amounts, currency swap, unit-vs-total mismatch, re-applying or stacking a discount/coupon (replay).\n"
      + "- Workflow abuse: jump straight to the confirm/pay/ship endpoint (step skip), reorder steps, repeat a one-time step, or resume another user's half-finished flow by its token/id.\n"
      + "- Quantity/limit abuse: negative quantity (credit), exceed advertised max, or race the check with parallel requests to double-spend / over-redeem.\n"
      + "- Trust rule: any value the client sends that the server SHOULD derive itself (userId, orgId, role, price, final status) is a tamper candidate.\n";

    private static final String AUTH_JWT =
        "### Authentication & JWT\n"
      + "- Strip the auth header / cookie entirely — does the endpoint still return data? (silent unauth access).\n"
      + "- JWT attacks: alg:none (drop the signature); algorithm confusion RS256→HS256 (sign with the public key as the HMAC secret); unverified kid (point it at a known/injected key); remove or back-date exp; tamper sub / role / scope / tenant claims and check if accepted.\n"
      + "- Session hygiene: does logout actually invalidate the token? session fixation? token leaked in the URL? a session id that never rotates or is predictable?\n"
      + "- Vertical escalation: replay the SAME privileged request under a lower-privilege saved identity — if it still succeeds, that is a confirmed privilege escalation.\n";

    private static final String MULTI_STEP =
        "### Multi-step chains\n"
      + "- Canonical BOLA chain: (1) read your OWN object to learn the id shape/pattern → (2) obtain a FOREIGN id from a list/search/sibling response → (3) request it under your identity → (4) compare: the other owner's fields in the response = confirmed.\n"
      + "- Cross-identity chain: create a resource as identity A, then access or modify it as identity B.\n"
      + "- Escalation chain: a low-privilege user discovers an admin/internal endpoint (from JS, recon, or an error) and invokes it — a privileged action succeeding is the proof.\n"
      + "- Every chain MUST end in a compare against baseline with evidence_refs cited; a chain only counts when the FINAL observation concretely demonstrates impact.\n";
}
