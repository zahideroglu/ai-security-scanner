---
id: multistep-chain
title: Multi-Step Attack Chain
vulnClass: Business Logic
focusKey: multiStep
severityHint: High
requiresSessions: false
---
# OBJECTIVE
Prove impact that a single request cannot show, by CHAINING requests and carrying state
between them: read a value here, reuse it there; complete a flow out of order; use a
token/id learned in step 1 to act in step 2. Scanners test endpoints in isolation —
your edge is composition.

# WHAT TO INSPECT
- Values in the baseline response that look reusable downstream: ids, tokens, references,
  reset codes, redirect targets, signed blobs.
- Whether a later step trusts a value the client supplies from an earlier step.
- Sequence assumptions: does step N verify that steps 1..N-1 actually happened?

# HUNTING HEURISTICS
1. Read the baseline; extract a candidate value (note it).
2. Send a follow-up request that consumes that value in a way the app did not intend
   (replay it, increment it, or supply it where a fresh/authorized value is expected).
3. Use save_as handles to keep each step's response; compare to confirm the chain worked.
4. Look for "skip the gate" flows: call the final/confirm step directly.

# EXAMPLE ACTION SEQUENCE
{"action":"note","thought":"Baseline returned resetToken=abc tied to my account. Test if step-2 (set password) trusts a supplied account id with this token."}
{"action":"send_request","thought":"Reuse the reset token but target a different account id.","location":"body","target":"","payload":"{\"account\":\"124\",\"token\":\"abc\",\"newpass\":\"P@ss1\"}","attack_type":"Workflow bypass","description":"reset-token reuse cross-account","save_as":"r1"}
{"action":"compare","thought":"Did step-2 accept my token for another account?","left":"r1","right":"baseline"}
{"action":"report_finding","type":"Business Logic","severity":"High","confidence":0.85,"description":"Password-reset step trusts a client-supplied account id, allowing a token issued for my account to reset another account.","evidence":"r1 returned HTTP 200 confirming reset for account 124 using my token.","exploitation":"Take over arbitrary accounts by binding my reset token to their id.","remediation":"Bind the reset token to the account server-side; ignore client-supplied account ids.","evidence_refs":["r1","baseline"]}

# PROOF CRITERIA
Report ONLY when the OBSERVATION shows the chained step SUCCEEDED in a way that crosses
a trust boundary (a foreign account changed, a gate skipped with effect). A rejection at
any step means the chain is broken — not a finding.

# COMMON FALSE POSITIVES
- The follow-up step independently re-validates and rejects the reused value.
- Apparent success that is actually scoped to your own account (no boundary crossed).

# STAY IN LANE
Compose requests; do NOT brute-force payloads. No SQLi/XSS. Keep each step's handle and
reason explicitly about what state moved between requests.
