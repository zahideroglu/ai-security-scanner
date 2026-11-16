---
id: auth-jwt
title: Authentication & JWT Bypass
vulnClass: Authentication
focusKey: authJwt
severityHint: High
requiresSessions: false
---
# OBJECTIVE
Prove that authentication or session handling on THIS endpoint can be bypassed or
forged: a request that should require a valid identity is honoured without one, or
with a token you control. Burp does not reason about token semantics — you do.

# WHAT TO INSPECT
- Does the BASE REQUEST carry `Authorization: Bearer <jwt>` or a session `Cookie`?
- If a JWT is present, decode its dot-separated base64url parts. Note `alg` and claims
  like `role`, `isAdmin`, `sub`, `exp`.
- Baseline status with the real identity (usually 200) — your control.

# HUNTING HEURISTICS (cheapest discriminating test first)
1. DROP the credential: resend with `Authorization` empty (location=header,
   target=Authorization, payload=""). Still 200 with protected data => missing auth.
2. alg=none forge: rebuild the JWT header as {"alg":"none","typ":"JWT"}, keep the
   payload, drop the signature (trailing dot). Send as location=jwt.
3. Claim tampering: flip `role`->"admin" / `isAdmin`->true WITHOUT re-signing.
4. Expired/foreign token: try an obviously-expired exp or a structurally valid but
   foreign token. 200 indicates broken validation.

# EXAMPLE ACTION SEQUENCE
{"action":"send_request","thought":"Baseline 200 with real token. Drop it to test enforcement.","location":"header","target":"Authorization","payload":"","attack_type":"Auth bypass","description":"drop Authorization","save_as":"noauth"}
{"action":"compare","thought":"Did dropping creds change anything?","left":"noauth","right":"baseline"}
{"action":"send_request","thought":"Still protected. Try alg=none forge keeping the payload.","location":"jwt","target":"Authorization","payload":"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<original-payload>.","attack_type":"JWT alg=none","description":"alg=none forge","save_as":"algnone"}
{"action":"report_finding","type":"Authentication","severity":"High","confidence":0.9,"description":"alg=none JWT accepted; signature not verified.","evidence":"algnone returned HTTP 200 with the same authenticated profile as baseline.","exploitation":"Forge any identity by setting alg=none and arbitrary claims.","remediation":"Reject alg=none; verify the signature against a server-side secret/JWKS.","evidence_refs":["algnone","baseline"]}

# PROOF CRITERIA
Report ONLY when an OBSERVATION shows a protected resource returned (HTTP 200 with the
same authenticated content as baseline) under a credential you removed, forged, or
tampered. A redirect to /login, 401, or 403 is NOT a finding.

# COMMON FALSE POSITIVES
- 200 with a generic public/login page after dropping the token (the unauthenticated
  view, not a bypass) — compare body length and key tokens vs baseline.
- An endpoint that was never authenticated to begin with (baseline had no token).

# STAY IN LANE
Do NOT test IDOR/object ownership (the access-control agent owns that). Do NOT fire
SQLi/XSS. Spend every step on token/session validation.
