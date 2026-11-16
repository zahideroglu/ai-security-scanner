---
id: mass-assignment
title: Mass Assignment / Auto-Binding
vulnClass: Broken Access Control
focusKey: businessLogic
severityHint: High
requiresSessions: false
---
# OBJECTIVE
Prove the endpoint binds request fields straight onto a server object, so adding a
field the client should never control (`role`, `isAdmin`, `isVerified`, `price`,
`balance`, `accountId`, `verified`) silently elevates privilege or alters protected
state. Scanners send known payloads; they don't reason about which fields are off-limits.

# WHAT TO INSPECT
- Write endpoints (POST/PUT/PATCH) that accept a JSON/body object (register, profile
  update, create resource).
- The fields the legitimate request sends — then guess sensitive sibling fields the
  model likely has (role, isAdmin, status, owner, price, verified, credits).
- The baseline response: what does the created/updated object look like?

# HUNTING HEURISTICS
1. Resend the baseline body PLUS one extra sensitive field (e.g. add `"role":"admin"`
   or `"isAdmin":true`).
2. Read the response: is the extra field reflected/accepted? If not visible, follow up
   with a read of the object (or a privileged action) to confirm it stuck.
3. Try `isVerified`/`verified`, `balance`/`credits`, `accountId`/`owner` similarly.
4. One extra field per request to keep the OBSERVATION unambiguous.

# EXAMPLE ACTION SEQUENCE
{"action":"note","thought":"POST /api/users body is {name,email,password}. Try injecting role=admin."}
{"action":"send_request","thought":"Add a privileged field the client should not set.","location":"body","target":"","payload":"{\"name\":\"x\",\"email\":\"x@x.io\",\"password\":\"P@ss1\",\"role\":\"admin\"}","attack_type":"Mass assignment","description":"inject role=admin on create","save_as":"r1"}
{"action":"compare","thought":"Was role=admin accepted/reflected?","left":"r1","right":"baseline"}
{"action":"report_finding","type":"Broken Access Control","severity":"High","confidence":0.85,"description":"Mass assignment: the create-user endpoint binds a client-supplied role, allowing self-promotion to admin.","evidence":"r1 returned the created user with role=admin (baseline had role=user).","exploitation":"Register or update yourself as admin by adding role=admin to the body.","remediation":"Whitelist bindable fields server-side; never auto-bind role/privilege fields.","evidence_refs":["r1","baseline"]}

# PROOF CRITERIA
Report ONLY when the OBSERVATION shows the injected privileged field was ACCEPTED
(reflected in the object, or a subsequent privileged action succeeds). If the field is
ignored/stripped or rejected (400), the binding is safe — not a finding.

# COMMON FALSE POSITIVES
- The field is echoed in the response but NOT actually persisted/authoritative.
- The server strips unknown fields (no change vs baseline).

# STAY IN LANE
Only add/alter fields the client should not own. No SQLi/XSS. No JWT forging. One
sensitive field at a time.
