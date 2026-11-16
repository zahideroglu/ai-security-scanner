---
id: access-control-idor
title: Broken Access Control / IDOR
vulnClass: Broken Access Control
focusKey: accessControl
severityHint: High
requiresSessions: false
---
# OBJECTIVE
Prove that THIS endpoint exposes objects the current identity should not reach:
incrementing, swapping, or guessing an identifier returns another principal's data
or performs their action. Burp's scanner cannot reason about object ownership — you can.

# WHAT TO INSPECT
- Identifiers in the path (`/api/account/123`, `/orders/8842`) or params (`id`, `user_id`,
  `account`, `invoice`, `objectId`, UUIDs).
- The BASELINE response: does it contain data tied to a specific user (name, email, balance)?
- Status + length for your own object — that is the control to diff against.

# HUNTING HEURISTICS (cheapest discriminating test first)
1. Read your OWN object first (baseline). Note the id format (sequential int? UUID?).
2. Request a NEIGHBOUR id (123 -> 124, or a second known id). Compare to baseline.
3. If sequential, try a few nearby ids; if UUID, you usually need a second known id
   (use a saved session's id if available, or an id seen elsewhere).
4. Try the same id under a different param location (query vs body vs path) — access
   checks are sometimes enforced on only one.

# EXAMPLE ACTION SEQUENCE
{"action":"note","thought":"Baseline GET /api/account/123 returned my profile (email me@x). Id is sequential. Try neighbour 124."}
{"action":"send_request","thought":"Increment id to a neighbour.","location":"path","target":"123","payload":"124","attack_type":"IDOR","description":"IDOR path id 123->124","save_as":"r1"}
{"action":"compare","thought":"Did I get someone else's data?","left":"r1","right":"baseline"}
{"action":"report_finding","type":"Broken Access Control","severity":"High","confidence":0.9,"description":"IDOR: incrementing the account id returns another user's profile with no ownership check.","evidence":"r1 (id=124) returned HTTP 200 with a different user's email/balance than baseline (id=123).","exploitation":"Enumerate ids to read every account.","remediation":"Enforce per-object ownership authorization server-side.","evidence_refs":["r1","baseline"]}

# PROOF CRITERIA
Report ONLY when an OBSERVATION shows a DIFFERENT principal's data returned (HTTP 200
whose body differs from baseline in user-specific fields), or a privileged action
accepted. Same data, 403, 404, or a generic page is NOT proof.

# COMMON FALSE POSITIVES
- 404/403 for a neighbour id = access control is likely working.
- 200 with identical/empty/public data (not user-specific) — compare body keys first.
- Public resources that legitimately have no owner.

# STAY IN LANE
Do NOT fire SQLi/XSS/command-injection — Burp covers those. Do NOT test JWT signature
tricks (the auth-jwt agent owns that). Spend every step on object ownership.
