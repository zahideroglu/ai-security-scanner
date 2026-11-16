---
id: business-logic
title: Business Logic & Workflow Abuse
vulnClass: Business Logic
focusKey: businessLogic
severityHint: High
requiresSessions: false
---
# OBJECTIVE
Make the application do something economically or logically wrong by sending values
the UI would never allow: negative/zero price, huge or fractional quantity, tampered
totals/discounts, status/role fields the client should not set, or by skipping a
required workflow step. Scanners don't understand intent — you do.

# WHAT TO INSPECT
- Body/JSON fields with business meaning: `price, amount, qty, quantity, total, cost,
  discount, coupon, balance, status, role, currency`.
- Whether the server RECOMPUTES money/authority or TRUSTS the client value.
- Multi-step flows (cart -> checkout -> pay): can a step be skipped or reordered?

# HUNTING HEURISTICS
1. Tamper one economic field at a time and read the response: set `price`/`amount` to
   0, 0.01, or negative; set `quantity` to negative or fractional.
2. Tamper authority fields: `status` -> "paid"/"approved", `role` -> "admin".
3. Coupon/voucher abuse: reuse, stack, or apply an expired/zero-target code.
4. Workflow: call a later step directly (e.g. confirm without pay) and see if it sticks.
5. Confirm IMPACT in the response (new total, accepted state) — not just a 200.

# EXAMPLE ACTION SEQUENCE
{"action":"note","thought":"POST /api/cart body has price:100, qty:1. Test if server trusts client price."}
{"action":"send_request","thought":"Set price to 0.01.","location":"body","target":"","payload":"{\"item\":\"x\",\"price\":0.01,\"qty\":1}","attack_type":"Price manipulation","description":"price->0.01","save_as":"r1"}
{"action":"compare","thought":"Did the server accept the tampered price?","left":"r1","right":"baseline"}
{"action":"report_finding","type":"Business Logic","severity":"High","confidence":0.85,"description":"Server trusts client-supplied price; cart accepted price=0.01.","evidence":"r1 returned HTTP 200 with order total reflecting 0.01 instead of catalog price.","exploitation":"Purchase any item for 1 cent.","remediation":"Recompute price server-side from the catalog; never trust client price.","evidence_refs":["r1","baseline"]}

# PROOF CRITERIA
Report ONLY when the OBSERVATION shows the server HONOURED the tampered value (total
reflects 0.01, status became 'paid', negative quantity credited balance). A validation
error (400/422) or unchanged total means the control held — not a finding.

# COMMON FALSE POSITIVES
- 400/422 rejecting the value = server-side validation works.
- Response echoes your input but the authoritative total is recomputed correctly.
- Client-side-only price shown that the backend ignores at charge time.

# STAY IN LANE
Do NOT fire SQLi/XSS — Burp covers those. Reason about money, authority, and workflow
order. One tampered field per request so the OBSERVATION is unambiguous.
