---
id: bola-multisession
title: BOLA via Multi-Session Replay
vulnClass: Broken Object Level Authorization
focusKey: accessControl
severityHint: High
requiresSessions: true
---
# OBJECTIVE
Prove Broken Object Level Authorization with TWO real identities: a resource that
belongs to identity A is returned (or mutated) when the SAME request is replayed as
identity B. This is the highest-confidence access-control proof and is exactly what
Burp cannot do — it has no notion of "another user".

# WHAT TO INSPECT
- The BASE REQUEST targets a specific object (an id in path/param) owned by the
  current (baseline) identity.
- Available saved session roles are listed in the initial context (e.g. "User", "Admin").
- Baseline response = the legitimate owner's view (your control).

# HUNTING HEURISTICS
1. Identify the object the baseline request reads/acts on.
2. Replay the EXACT same request as a DIFFERENT saved identity (replay_as_session).
3. Compare to baseline: if the other identity gets the owner's object data (HTTP 200,
   same sensitive body), object-level authorization is missing.
4. Also try the reverse direction (low-priv reading a high-priv object) for privilege
   escalation.

# EXAMPLE ACTION SEQUENCE
{"action":"note","thought":"Baseline GET /api/orders/8842 is owned by the baseline identity. Replay as role 'User' to see if a different user can read it."}
{"action":"replay_as_session","thought":"Send the same request under the 'User' identity.","session_role":"User","description":"replay /orders/8842 as User","save_as":"asUser"}
{"action":"compare","thought":"Did 'User' get the owner's order?","left":"asUser","right":"baseline"}
{"action":"report_finding","type":"Broken Object Level Authorization","severity":"High","confidence":0.95,"description":"BOLA: order 8842 is readable by an unrelated identity; no object-level ownership check.","evidence":"asUser returned HTTP 200 with the same order details as baseline, under a different authenticated user.","exploitation":"Any authenticated user can read any order by id.","remediation":"Check that the authenticated principal owns the object before returning it.","evidence_refs":["asUser","baseline"]}

# PROOF CRITERIA
Report ONLY when replay under a DIFFERENT identity returns the owner's object (HTTP 200,
same sensitive content as baseline) or performs the owner's action. A 401/403/404 under
the other identity means authorization is enforced — not a finding.

# COMMON FALSE POSITIVES
- The other identity legitimately has access (e.g. Admin reading any order by design).
  Prefer the low-priv -> high-priv direction for a clean finding.
- 200 with empty/generic data rather than the owner's specific object.

# STAY IN LANE
This agent is ONLY for cross-identity replay. If no sessions are usable, finish quickly.
Do NOT fire SQLi/XSS or JWT-forging here.
