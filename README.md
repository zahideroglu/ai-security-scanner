# 🛡️ AppSecHunter

<div align="center">

![Version](https://img.shields.io/badge/version-2.1-blue.svg)
![Java](https://img.shields.io/badge/Java-8-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Compatible-red.svg)

**Agentic, AI-adjudicated security testing for Burp Suite**

[Features](#-features) • [Detection](#-how-detection-works) • [Auth Matrix](#-authorization-matrix) • [Scenario BOLA](#-scenario-based-bolaidor) • [Login Profiles](#-login-profiles-fresh-sessions-moved-here-2026-06-25) • [WAF/FW](#-waffw-evasion-min-istek-maks-bulgu) • [Install](#-installation) • [Usage](#-usage) • [Config](#-configuration)

</div>

---

## 📋 Overview

**AppSecHunter** is a Burp Suite extension that combines a **fast, deterministic OWASP scanning engine** with a full **agentic AI layer** for triage, adjudication, access-control matrix testing, and a built-in security assistant. Works with **cloud** (OpenAI-compatible) or **local** AI models (Ollama / LM Studio / llama.cpp), so your traffic can stay on your machine.

> ### 🆕 Latest (2026-06 → 2026-07) — access-control–first, WAF-aware, banking-grade
> The tool now leans into what Burp's own scanner **cannot** do well: **IDOR / BOLA / BAC (broken access control)**. Highlights of the current line:
> - **Ownership-aware IDOR/BOLA** (`OwnershipOracle`) — public-resource + own-data discriminators kill the two biggest IDOR false positives; only a *proven cross-owner leak* is flagged. Now also covers **nested / array JSON ids** (`{"account":{"id":…}}`, `[{"orderId":…}]`) that Burp's flat parameter model misses, plus **write-IDOR** (idempotent PUT/PATCH replay with a status oracle).
> - **AI-only by default** — the deterministic module barrage and `/logs`,`/api` directory brute-forcing are **off by default**; a scan focuses its requests on IDOR/BOLA/BAC. (SQLi & XSS checks were **removed** — Burp covers those.)
> - **WAF / firewall aware ("min istek, maks bulgu")** — one global `SharedRateLimiter` funnels *every* request under a per-minute ceiling with jitter, plus a reactive per-host WAF circuit-breaker. Fewer, smarter requests instead of a blocking-triggering barrage.
> - **Banking-grade login profiles** — a capture-from-history wizard mints **fresh sessions per scan**; pick which body field is `{user}`/`{pass}` (for complex JSON logins), auto-configures body-carried sessions (e.g. Gateway `sessionToken`), copy/search, and actionable login diagnostics.
> - **Zero-config team distribution** — AI keys can be bundled in the jar (gitignored source) so teammates just load-and-go. See [Credentials](#credentials--secrets).

**v2.0** adds three major capability pillars; **v2.1** builds scenario-based ground-truth BOLA/IDOR on top and consolidates the UI to a single-click "scan everything" workflow:

| Pillar | What it does |
|--------|-------------|
| **Authorization Matrix** | Automatically discovers roles from history, builds a role × endpoint matrix, and hunts BOLA/IDOR/privilege-escalation with three AccessOracle verdict rules |
| **AI Adjudication** | Every deterministic finding and every matrix violation is reviewed by the AI before it reaches you — false positives are flagged and learning is fed back |
| **Report-Reproduction Probes (B01–B08)** | Eight auto-detection modules that fire additional confirmation probes (error forcing, HTTP method manipulation, transport downgrade, content discovery, parameter guessing, brute-force success-detection) so every finding ships with reproduction evidence |
| **Scenario-Based BOLA/IDOR** *(v2.1)* | Builds an `AccessModel` (ground-truth ownership map from history + active discovery), then drives cross-owner scenarios deterministically (`ScenarioAccessTester`) **and** agentically (`AgentPentestEngine + AccessModel`). Near-zero false positives because every finding is proven against owned vs. foreign objects |
| **One-click "Hepsini Tara"** *(v2.1)* | Single right-click item fires the entire campaign — fast scan + playbook + site scan + auth matrix + scenario BOLA — all in background threads; no manual orchestration needed |

> ⚠️ Active and autonomous scanning send real attack requests. Use **only on systems you are authorized to test.**

---

## ✨ Features

### 2026-06 → 2026-07 — Access-control focus, WAF-aware, banking login profiles
- 🔓 **Ownership-aware IDOR/BOLA** — `burp.authz.OwnershipOracle` classifies each candidate as `CONFIRMED_IDOR / FP_PUBLIC / FP_OWN_DATA / AMBIGUOUS`: it always sends an **anonymous public probe**, tolerates volatile/own-data noise, and reports **only** when a *foreign owner's* data actually leaks. Suppress-unless-confirmed.
- 🧬 **Nested / array JSON id IDOR** — `burp.scan.JsonIds` extracts id-like fields at any depth (`{"account":{"id":1}}`, `[{"orderId":1},{"orderId":2}]`) and swaps them surgically (byte-offset splice, no re-serialize), feeding both single-session IDOR and the cross-owner ownership model.
- ✍️ **Write-IDOR / mutating BOLA** — `ScenarioAccessTester` replays a victim's **PUT/PATCH** as the attacker (idempotent — victim's own body) with a status oracle (valid id → GRANTED, invalid id → DENIED) ⇒ **Critical, CONFIRMED**. Gated by the per-scan test-environment consent (DELETE/POST excluded).
- 🎯 **Single-session endpoint-param IDOR always runs** — parameter → IDOR (value-swap + ownership) fires on every id-bearing host endpoint **in addition to** cross-owner BOLA (they are complementary), so id-param coverage is never skipped when ≥2 accounts are configured. AI-independent (deterministic).
- 🚦 **WAF/FW evasion — "min istek, maks bulgu"** — a single global `burp.engine.SharedRateLimiter` funnels every target request under a configurable **per-minute ceiling** (default 100/min) + per-second smoothing + jitter (FW protection), plus a reactive **per-host WAF circuit-breaker** (`noteResult` / `isHostBlocked`, 25 s bounded send, slow-on-first-signal, 5–15 min host cool-down). See [WAF/FW evasion](#-waffw-evasion-min-istek-maks-bulgu).
- 🔑 **Banking-grade login profiles** — capture from proxy history; **field-mapping pickers** choose which body field is `{user}`/`{pass}` (for complex JSON logins where auto-detect can't); **body-carried session** auto-config (token injected into a JSON field like Gateway `sessionToken`, not an `Authorization` header); **Copy** a profile; **search** the history picker; **OTP/STS login warning**; and rich `LoginManager` diagnostics (HTTP status, empty-vs-missing token, response preview) instead of a dead-end "token not found".
- 🧭 **AI-only by default** — `heuristicScanEnabled = false` and `contentDiscoveryEnabled = false`: the deterministic OWASP-module barrage and `/logs`,`/api` directory brute-forcing are off; the access-control layer (matrix + scenario BOLA + agentic) still runs. Flip either flag in settings to re-enable.
- 🌍 **Bilingual UI (TR/EN)** — `burp.i18n.I18n` catalog (~460 keys) + language switch; findings render in the selected language.
- 📦 **Zero-config secrets** — `burp.SecretsProvider` resolves keys env → `~/.appsechunter/secrets.json` → **jar-bundled `/secrets.json`** (gitignored source) for turnkey internal team distribution.

### Core engine
- ⚡ **Fast deterministic OWASP engine** — an **opt-in** heuristic layer (`heuristicScanEnabled`, off by default) of access-control–oriented active modules, parallel request sending, global rate limiting, dedup. ~5–8 s per endpoint.
- 🤖 **Cloud or local AI** — OpenAI-compatible cloud endpoint or a local model (Ollama / LM Studio / llama.cpp) with presets, model auto-discovery, and a connection test.
- 🧭 **Staged AI detection pipeline** — 7 visible stages (Recon → Hypothesis → Test Plan → Execute → Analyze → Verify → Report) in **Automatic** or **Guided** mode.
- 🌐 **Two scan scopes** — single request, or **Whole Site + History** (site map + proxy history, merged + deduped; POST/parameterized prioritized).
- 📊 **Visual Detection tab** — per-run sub-tabs, live Active Tests table, counters, progress bar, request/response preview per row.

### v2.1 — Scenario-based BOLA/IDOR (ground truth)
- 🎯 **AppAccessModel** — `AccessModelBuilder` builds an object-ownership map from proxy history: each identity *owns* the ids it accessed with HTTP 200; silent active discovery replays owned GETs to validate the map.
- 🔐 **Ground-Truth ScenarioAccessTester** — for each attacker A × object owned by B≠A, replays B's request *as A* (`MultiSessionTester.replayAs`); if HTTP 200 → AI `judgeAccessControl` with baseline (A's own object) + manipulated (B's foreign object) + negative control (invalid id). Finding label: **BOLA (Ground-Truth)**.
- 🤖 **Agentic BOLA driver** — `AgentPentestEngine.setAccessModel(model)` injects the full ownership map into the agent's context ("A owns {…}; B owns {…}; intended policy …") so the ReAct agent drives provable cross-owner / multi-step scenarios using existing `send_request` / `replay_as_session` / `compare` actions.
- 🖱️ **One-click "Hepsini Tara"** — new `startEverything` fires the full campaign in one confirmation: fast scan + playbook hunt (if AI) + site scan + auto auth-matrix + scenario BOLA (ground-truth) + agentic BOLA (if AI). No manual orchestration needed.
- 📋 **Scanner toolbar slimmed** — removed Quick Tests / Dynamic Tests / AI Autonomous buttons; toolbar now: **🚀 Hepsini Tara** + New Scan + Scan Domain + Close Tab.

### v2.0 — AI adjudication
- 🧠 **AI Adjudication** — every candidate finding from the deterministic engine and every authorization-matrix violation is evaluated by the AI before reporting. Refuted findings are FP-flagged (kept but grayed) rather than silently dropped. Activates automatically when AI is configured; fails open so scanning continues if the AI is unavailable.
- 🔎 **AI-driven BOLA/IDOR** — `IdorModule` captures baseline and manipulated response bodies; the AI compares them to confirm real cross-owner data leakage rather than cosmetic differences.

### v2.0 — Authorization Matrix
- 🔐 **Authorization Matrix (Yetki Matrisi)** — role × endpoint access-control matrix built on `MultiSessionTester.replayAs`. Automatically harvests roles from proxy history (`SessionHarvester`) and tests every combination.
- 🎯 **AccessOracle verdicts** — three layered verdict rules (V1: status-code diff, V2: body-length diff, V3: AI body-diff) to classify each cell as `ALLOWED / BLOCKED / SUSPICIOUS`.
- 📋 **Visual matrix tab** — colour-coded grid (green/red/yellow), CSV and HTML export.
- 📂 **OpenAPI importer** — feed an OpenAPI 3.x spec to seed the matrix with endpoints even before you browse them (`burp/spec/OpenApiImporter`).
- ⚠️ **Mutating-method consent** — POST/PUT/DELETE matrix replays ask for confirmation before sending.

### v2.0 — Report-reproduction probes
- 🔬 **B01 Error Forcing** — triggers verbose server error pages to surface stack traces and framework banners.
- 🔬 **B02 HTTP Method** — tests non-standard verbs (TRACE, PUT, DELETE, PATCH, OPTIONS) on every endpoint.
- 🔬 **B03 Transport** — checks HTTP→HTTPS downgrade and HSTS absence.
- 🔬 **B04 Content Discovery** — probes common hidden paths (`.git`, `/.env`, `/api/swagger.json`, `/actuator`, backup files).
- 🔬 **B05 Param Guess** — appends common hidden parameters (`debug`, `test`, `admin`, `id`, `token`, `key`) to reveal additional surfaces.
- 🔬 **B06 Brute-Force Success Detection** — characterises success vs. failure responses to detect missing rate-limiting without sending thousands of requests.
- 🔬 **B07–B08 Raw-Request Escape Hatch** — `Probe.rawRequest` / `overrideService` + `RequestKit` let modules send fully custom HTTP requests outside the normal parameter-mutation loop.

### Ambient Copilot
- 🛰️ **Ambient Security Copilot** — passively watches proxy traffic, scores endpoints **LLM-free**, surfaces a live **Opportunities** feed with one-click *Test / Quick scan / Ignore*.
- 🎯 **Autonomous background hunter** — **auto-starts on extension load** *(2026-06-25)* and tests queued in-scope endpoints within a global **token / time / concurrency / rate** budget; scope-only, read/idempotent. Stop it any time from the **kill switch in the Copilot panel**.
- 📖 **Playbook-driven agentic pentester** — ReAct (observe→reason→act) loop specialized per endpoint by editable Markdown playbooks (IDOR/BOLA, business logic, auth/JWT, mass-assignment, multi-step).
- 🧠 **Learning loop** — confirmed findings and false-positive marks feed back per host so the copilot stops suggesting fruitless classes.

### General
- 💬 **Security Assistant** — built-in chatbot for vulnerability questions, exploitation guidance, and remediation advice.
- 🛡️ **Per-scan safety gate** — intrusive tests (brute force, file upload, active SSRF, command-timing) now run **by default** *(2026-06-25)*, but every scan that would fire them first shows a **per-scan confirmation dialog** you must accept.
- 🔎 **Single Findings view** — all findings in one place with run-level de-duplication, Burp Issues integration, PoC generation, and export.

---

## 🔬 How detection works

| Approach | Speed | When to use |
|----------|-------|-------------|
| **Fast Active Scan** (deterministic) | ~5–8 s / endpoint | **Recommended.** Modules send probes and judge by deterministic signals. AI adjudicates each candidate before reporting. |
| **Authorization Matrix** | seconds–minutes | Discovers roles automatically, then tests every role × endpoint combination for BOLA/IDOR/priv-esc. |
| **Scenario-Based BOLA/IDOR** *(v2.1)* | minutes (budgeted) | Builds an ownership map from history; proves cross-owner access with ground-truth objects. Near-zero FP. |
| **Agentic BOLA** *(v2.1)* | adaptive, budgeted | AI drives cross-owner + multi-step scenarios using the ownership map; owns stages + reports internally. |
| **Ambient Copilot** (passive) | instant, LLM-free | Watches proxy traffic, scores endpoints, surfaces Opportunities while you work. |
| **Agentic / Playbook** (AI pentester) | adaptive, budgeted | ReAct loop specialized by playbooks; hunts access-control / logic / auth flaws. Manual or autonomous. |
| **AI Staged** (Automatic / Guided) | slower (per-request AI) | Deep recon→plan→execute→verify with optionally-approved stages. |

### OWASP module coverage (deterministic)

> **SQLi & XSS are intentionally NOT covered** — Burp's own scanner does those well; the `InjectionModule` (and the GraphQL tester) were **removed** so AppSecHunter concentrates on the access-control gap. (`Signals.hasSqlError` is retained purely as an IDOR false-positive guard.)

| Module | Class | Detects |
|--------|-------|---------|
| **IDOR** | A01 | Numeric/UUID id swap in URL path, params **and nested/array JSON bodies**; **ownership-aware** (public + own-data discriminators) → only proven cross-owner leakage; AI body-diff confirms |
| **Access Control** | A01 | Auth/cookie removal + JWT `alg=none` forgery → resource still served; **write-IDOR** (PUT/PATCH status oracle) |
| **Misconfiguration** | A05 | Missing security headers, CORS reflection, version banners, insecure cookie flags |
| **Mass Assignment** | A08 | Extra privileged fields accepted on write endpoints |
| **SSRF / Open Redirect** | A10 | Open redirect (always); localhost/cloud-metadata SSRF (intrusive) |
| **CAPTCHA bypass** | — | Weak/omittable CAPTCHA on protected flows |
| **Brute Force** | A07 | Missing rate-limit / account-lockout on login (intrusive) |
| **File Upload** | A04/A05 | Dangerous-extension upload acceptance (intrusive) |

> These deterministic modules form the **opt-in** heuristic layer (`heuristicScanEnabled`, **off by default**). The default AI scan runs the **access-control layer** (auth matrix + ground-truth/agentic BOLA + ownership-aware IDOR) instead.

### Report-reproduction probes (B-series)

Every deterministic finding is supplemented by one or more B-series confirmation probes before it reaches the Findings view. This ensures each reported issue ships with concrete reproduction evidence rather than a single anomalous response.

```
B01 Error Forcing       — verbose error pages, stack traces, framework banners
B02 HTTP Method         — TRACE / PUT / DELETE / PATCH / OPTIONS on every endpoint
B03 Transport           — HTTP→HTTPS downgrade, HSTS check
B04 Content Discovery   — .git, /.env, /actuator, /api/swagger.json, backup files
B05 Param Guess         — hidden parameter injection (debug, admin, id, token, key…)
B06 Brute Success       — rate-limit/lockout characterisation (reads success/fail shape)
B07-B08 Raw Request     — fully custom HTTP via Probe.rawRequest + RequestKit
```

---

## 🔐 Authorization Matrix

The **Yetki Matrisi** tab provides automated BOLA/IDOR/privilege-escalation testing across multiple roles.

### How it works

1. **Role harvesting** — `SessionHarvester` scans proxy history to detect distinct authenticated sessions and map them to role names (admin, user, guest, etc.).  Alternatively, add sessions manually in the **Sessions** context menu.
2. **Endpoint seeding** — endpoints come from proxy history, the Burp site map, or an imported **OpenAPI 3.x spec** (`OpenApiImporter`).
3. **Matrix replay** — for each role × endpoint combination, `MultiSessionTester.replayAs` replays the request under that session's credentials.
4. **AccessOracle verdict** — three verdict rules classify each cell:
   - **V1** — status code differs from the owner's response → `BLOCKED`
   - **V2** — body length diverges by more than a threshold → `SUSPICIOUS`
   - **V3** — AI body diff comparing owner vs. target response → `ALLOWED / BLOCKED / SUSPICIOUS`
5. **Colour-coded grid** — green (allowed), red (blocked), yellow (suspicious). Export as CSV or HTML.

### Running the matrix

```
Right-click a request → AppSecHunter → Sessions ▸ → Run Auth Matrix
```

Or trigger autonomously: **Settings → Authorization Matrix → Auto-run on scan**.

### 🔐 Login Profiles (fresh sessions) *(moved here 2026-06-25)*

The **Yetki Matrisi** tab has a **🔐 Login Profilleri** button that opens a self-contained dialog (`burp.authz.LoginProfilesDialog`) for managing login profiles — the credentials the engine replays to mint **fresh sessions per scan** for the matrix, BOLA, and scenario tests. *(Previously these lived under Settings → AI Pentester.)*

- Table-based **➕ Add / ✏️ Edit / 📋 Copy / 🗑️ Delete / 🔑 Test**, with an **⚙️ Advanced (JSON)** escape hatch behind a toggle. Each profile is one role; **Copy** duplicates it under a unique name for the next account.
- **➕ Add** opens a capture wizard: pick a login request from the **searchable** proxy-history picker (login-looking requests first, live filter, full history) → the form auto-fills (URL, method, credentials, token JSON-path auto-detected by `LoginProfileBuilder`).
- **Identity mapping for complex JSON logins** — banking/mobile logins often bury the identity in the body among several id/secret-looking fields (`UserName`, `CustomerId`, `ExtUPassword`, `Password`…). Two pickers let you choose exactly **which body field is `{user}`** and **which is `{pass}`**; the template is always re-derived from the immutable captured body, so switching a mapping never corrupts another field. The request-body box is large and editable for manual `{user}`/`{pass}` marking.
- **Body-carried sessions** — when the minted token isn't an `Authorization` header but a JSON body field (e.g. Gateway `sessionToken`), capture auto-detects the empty session-carrier field and injects the token there on every replay.
- **Actionable diagnostics** — **🔑 Test** reports HTTP status, the `Success` flag, whether the token field resolved-but-was-**empty** vs. **missing**, and a response preview; `[LoginManager]` lines go to Burp's Output (and the scan log). A single-use **OTP/STS login** capture is flagged so you grab the plain `IsStsLogin:false` login instead.
- **Minted once per campaign** — the auth-matrix, ground-truth BOLA and agentic hunts share one 5-minute session mint (guarded on the shared `MultiSessionTester`), so 3 accounts = 3 logins, not 9.
- Persists **directly** via `SettingsManager` — no Settings "Save" needed.

---

## 🎯 Scenario-Based BOLA/IDOR

The ground-truth engine *(v2.1)* goes beyond blind id+1 fuzzing by building a **provable ownership map** before testing.

### How it works

1. **AccessModelBuilder — history pass** — scans proxy history for every authenticated identity (from `SessionHarvester`). An identity *owns* an object if it accessed that path/param with HTTP 200. Object type = the path segment or parameter name preceding the id.
2. **AccessModelBuilder — active discovery** — silently re-sends owned GET requests with each session to validate the ownership map; responses now returning 401/403/404 are dropped to keep the model honest.
3. **ScenarioAccessTester** — for every attacker A × object owned by B≠A:
   - Replays B's request *as A* via `MultiSessionTester.replayAs`
   - If HTTP 200 → AI `judgeAccessControl` with three inputs: *baseline* (A's own object), *manipulated* (B's foreign object as A), *negative control* (same endpoint, invalid id → expected 404/403)
   - Only confirmed leakage is reported as **BOLA (Ground-Truth)**
4. **Agentic mode** — `AgentPentestEngine.setAccessModel(model)` injects the full ownership map into the agent context; the ReAct agent drives multi-step cross-owner scenarios using existing `send_request / replay_as_session / compare` actions.

### Running scenario tests

Both modes fire automatically as part of **Hepsini Tara — Tam Otomatik** (when AI is configured).  Manual triggers:

```
Right-click a request → AppSecHunter → (via Hepsini Tara — or previously via Sessions menu)
```

> GET-only by default. Mutating-method (POST/PUT/DELETE) replays prompt for confirmation.

---

## 🧠 AI Adjudication

When an AI model is configured, **every candidate finding** produced by the deterministic engine and every `SUSPICIOUS` or `ALLOWED` cell in the authorization matrix is reviewed by the AI before it is reported.

| Verdict | Action |
|---------|--------|
| **Confirmed** | Finding reported normally |
| **Refuted** | Finding kept in the list, marked `[FP?]`, grayed out — not counted in totals |
| **Uncertain** | Finding reported with a lower confidence note |

- **Fail-open**: if the AI call fails (rate limit, offline model, timeout), the finding is reported as-is so scanning continues.
- **Auto-on**: activates whenever `Settings → API Configuration` has a working model; no separate toggle needed.
- **BOLA/IDOR deep compare**: `IdorModule` captures the baseline response body alongside the manipulated response; the AI receives both and decides whether the difference constitutes real cross-owner data leakage.

---

## 🚦 WAF/FW evasion ("min istek, maks bulgu")

Two asymmetric threats are handled differently: a **firewall** that bans your IP for a day if you exceed a session/minute rate (must be avoided *proactively*), and a **WAF** that silently drops requests for 5–15 minutes when it sees an attack pattern (can be handled *reactively*).

- **One global funnel** — every target request (scan modules, agents, ambient hunter, matrix, login, baseline) goes through a single `burp.engine.SharedRateLimiter`. No more three uncoordinated limiters summing up.
- **Per-minute ceiling + jitter** — a configurable hard cap (default **100 req/min**) with per-second smoothing and randomized spacing keeps you structurally under the firewall's limit; work is never dropped, only spread over time.
- **Reactive WAF circuit-breaker** — responses are scored (`Signals.looksLikeBlockPage` + 403/429/503); on a per-host block signal the limiter slows down, and a persistently-blocked host is cooled down (`noteResult` / `isHostBlocked`) so the rest of the campaign continues on other hosts. The silent-drop "blackhole" (HTTP 0 / ~600 s hang) is caught by a 25 s bounded send instead of stalling the whole scan.
- **Volume trimming** — SQLi/XSS/GraphQL removed, directory brute-forcing off by default, AI router set to `ai` (1–3 relevant playbooks per endpoint instead of all), and preconditions gate low-yield probes. Net effect: far fewer requests, negligible detection loss.

Tune from **Settings → Detection Engine**: `maxRequestsPerMinute`, `maxRequestsPerSecond`, parallelism, and agent concurrency (defaults: 100/min, 3/s, 2 parallel probes, 2 agents).

---

## 🚀 Installation

### Prerequisites
- **Burp Suite** (Community or Professional)
- **JDK 8** to build (`tools.jar` is required — a JRE alone is not enough)
- For AI: a cloud API key **or** a local model server (e.g. `ollama serve`)

### Build from source
```bash
# IMPORTANT: point JAVA_HOME at a real JDK 8 (not the system JRE)
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home
./gradlew clean jar
# Output: build/libs/appsechunter-2.0.jar
```

### Load in Burp
**Extensions → Installed → Add → Extension type: Java →** select the jar. The Output tab prints a banner and `loaded successfully`. Burp does **not** hot-reload — to update, **Remove** the old entry and **Add** the new jar.

### Credentials / secrets
API credentials are **never hardcoded in source**. They are resolved at runtime, in order:
1. **Environment variables** (for CI / headless): `APPSEC_API_KEY`, `APPSEC_GW_USERNAME`, `APPSEC_GW_PASSWORD`, `APPSEC_GW_CLIENT_ID`, `APPSEC_GW_CLIENT_SECRET`, `APPSEC_GW_SUBJECT`.
2. **`~/.appsechunter/secrets.json`** (recommended for desktop Burp) — lives in your home dir, outside any repo, so it can never be committed. Example:
   ```json
   {
     "apiKey": "sk-...",
     "gatewayUsername": "...",
     "gatewayPassword": "...",
     "gatewayClientId": "...",
     "gatewayClientSecret": "...",
     "gatewayRequestedSubject": "..."
   }
   ```
   `chmod 600 ~/.appsechunter/secrets.json` is recommended.
3. **Jar-bundled `/secrets.json`** (classpath) — for **turnkey internal team distribution**: drop a `src/main/resources/secrets.json` (same schema) before building and teammates get a load-and-go jar with no per-machine setup. The file is **gitignored** (`**/secrets.json`) so it never lands in the repo — only inside the jar you hand out internally.
4. **Settings → API** in the UI — whatever you type is persisted by Burp's own extension-settings store.

If none is set, the relevant field is simply blank until you fill it in. See `burp.SecretsProvider`.

> Only bundle keys for **internal, authorized** distribution — the jar is not encrypted; anyone with it can read the embedded keys.

---

## 🎮 Usage

1. **Settings → API Configuration** — choose provider:
   - **Hosted API (API key)**: any OpenAI-compatible endpoint. Pick a **preset** (OpenAI, OpenRouter, Groq, Together, DeepSeek) to fill the base URL, paste your API key, set the model, click **Test Connection**.
   - **Local LLM**: pick a preset (Ollama `:11434/v1`, LM Studio `:1234/v1`, llama.cpp `:8080/v1`), refresh models, no key needed.
   - **Enterprise Gateway** *(advanced)*: Keycloak token-exchange → your internal LLM gateway.
2. *(optional)* **Settings → Detection Engine → Ambient card** — passive triage and the autonomous hunter are **on by default** *(2026-06-25)*; here you only tune their **budgets** (token / time / concurrency), min score, and router mode. The hunter auto-starts on load — stop it from the **Copilot panel kill switch**.
3. **Browse the target** through Burp's proxy so requests land in the site map / history (feeds ambient triage and role harvesting).
4. **Right-click a request → AppSecHunter →**:
   - **Hepsini Tara — Tam Otomatik** *(recommended)* — one confirmation dialog, then the campaign fires in background threads. By default (AI-only): playbook hunt, AI site hunt, **auto auth-matrix**, AI surface discovery, **ground-truth BOLA**, **agentic BOLA**. The deterministic fast/site scans are added only if the **heuristic layer** is enabled. Auth-matrix roles + fresh login sessions are auto-minted from your login profiles; no manual session setup needed.
   - **Tara — Sadece bu istek (hızlı)** — fast deterministic scan + AI playbook for the selected request only.
   - **Add Session (rol ekle — opsiyonel)** — manually add a role cookie/header to improve matrix accuracy.
5. **Scanner toolbar** (in the Scanner tab): **🚀 Hepsini Tara** (pick a request, then fires the full campaign) · **+ New Scan** · **Scan Domain** (bulk via BulkScanPanel) · **Close Tab**.
6. Watch progress in **Detection** (per-run sub-tabs, live Active Tests table, counters, request/response preview). Findings collect in **Findings** and Burp **Issues**.
7. **Yetki Matrisi** tab: review the colour-coded role × endpoint grid; export as CSV or HTML.
8. **Copilot** tab: act on Opportunities, watch the hunter's budget meter / kill switch, ask endpoint-specific questions.

### Context menu *(v2.1 — menu-v5)*
```
AppSecHunter ▸
├─ Hepsini Tara — Tam Otomatik     ← recommended; fires everything in background (one confirm)
│                                     fast scan + playbook + site + auth-matrix
│                                     + scenario BOLA + agentic BOLA (AI items need AI config)
├─ Tara — Sadece bu istek (hızlı)  ← fast det + AI playbook for this request only
└─ Add Session (rol ekle — opsiyonel) ← add a role for matrix accuracy
```

---

## 🖥️ Tabs

| Tab | Description |
|-----|-------------|
| **Scanner** | Interactive per-request scan tabs + AI chat |
| **Detection** | Live, persistent per-run view: stages, Active Tests table, B-series probe results, request/response preview |
| **Findings** | Global de-duplicated findings list; AI-adjudicated items flagged; PoC, export, false-positive marking |
| **Yetki Matrisi** | Authorization Matrix — role × endpoint colour-coded grid; CSV/HTML export; **🔐 Login Profilleri** button (fresh-session login profiles, moved here 2026-06-25) |
| **Copilot** | Ambient Opportunities feed, context-aware chat, hunter kill switch + budget meter |
| **Settings** | AI provider, Detection Engine, Ambient Copilot, Authorization Matrix configuration |

---

## 🔧 Configuration

**API**
- Provider: **Hosted API** (`hosted` — OpenAI-compatible endpoint + API key; one-click presets for OpenAI / OpenRouter / Groq / Together / DeepSeek) · **Local LLM** (`local` — Ollama / LM Studio / llama.cpp, no key; plain `http://localhost` allowed) · **Enterprise Gateway** (`gateway` — Keycloak token-exchange, advanced).

**Detection Engine** (Settings → Detection Engine)
- **Fast model** (optional separate small/fast model) + engine max tokens (default 512).
- **Rate limiting** — `maxRequestsPerMinute` (default **100**), `maxRequestsPerSecond` (default **3**), **parallel probes** (default **2**), **agent concurrency** (default **2**). These are the WAF/FW knobs (see [WAF/FW evasion](#-waffw-evasion-min-istek-maks-bulgu)).
- **Max endpoints** per Whole Site + History scan (default 40).
- **AI-only by default** — `heuristicScanEnabled = false` (no deterministic OWASP-module barrage) and `contentDiscoveryEnabled = false` (no `/logs`,`/api` directory brute-forcing). Flip either to add that layer. The access-control layer (matrix + BOLA + ownership-aware IDOR) runs regardless.
- **When the heuristic layer *is* on, all modules are always-on** *(2026-06-25)* — the per-module checkboxes, the **intrusive** tests (Brute Force / File Upload / Active SSRF / Command-timing), the **deep-AI pass**, and the old **Safe / Balanced / Aggressive** mode buttons were removed; intrusive tests are gated only by the per-scan confirmation dialog.

**Authorization Matrix** (Settings → Authorization Matrix)
- **Auto-harvest roles** from proxy history on/off.
- **AccessOracle rules**: enable/disable V1 (status), V2 (body length), V3 (AI diff) independently.
- **Mutating-method consent**: prompt before replaying POST/PUT/DELETE.
- **OpenAPI spec path**: point to a local `.json` or `.yaml` to pre-seed endpoints.

**🛰️ Ambient Security Copilot** (Settings → Detection Engine → Ambient card)
- Passive triage, the autonomous hunter, **scope-only** and the **shared rate limiter** are **always-on** *(2026-06-25)* — their on/off checkboxes were removed. Stop the hunter at runtime from the **Copilot panel kill switch**.
- **Opportunity min score** (default 35), **concurrency**, **token budget**, **time budget** (minutes), and **playbook router mode** (`all` / `heuristic` / `ai`) remain tunable here.
- **Playbooks**: bundled set ships in the jar; enable external loading for custom `*.md` overrides.

---

## 📁 Project structure (key files)

```
src/main/java/burp/
├── BurpExtender.java            # entry point, tabs, context menu
├── ScanManager.java             # orchestration (fast / staged / site / history / auth-matrix), AI adjudication
├── QwenAPIClient.java           # OpenAI-compatible AI client (cloud/local)
├── Settings.java / SettingsPanel.java / SettingsManager.java
├── SecretsProvider.java         # env → ~/.appsechunter/secrets.json → jar-bundled /secrets.json
├── FindingsPanel.java / DetectionRunView.java
├── AssistantPanel.java          # Copilot surface (Opportunities + context chat + hunter controls)
├── MultiSessionTester.java      # session store + replayAs (header + body-carried tokens)
├── Finding.java / CustomScanIssue.java / DatabaseManager.java
│
├── authz/                       # Authorization Matrix + Scenario BOLA + login profiles
│   ├── AuthMatrixPanel.java     #   colour-coded Yetki Matrisi tab + CSV/HTML export + Login Profilleri button
│   ├── AuthMatrixEngine.java    #   role × endpoint replay orchestration
│   ├── AccessOracle.java        #   V1/V2/V3 verdict rules
│   ├── OwnershipOracle.java     #   NEW — public/own-data discriminators (kills the 2 big IDOR FPs)
│   ├── SessionHarvester.java    #   auto-discover roles from proxy history (403 = authed-but-forbidden)
│   ├── AccessModel.java         #   ground-truth object-ownership map (+ nested-JSON ids)
│   ├── AccessModelBuilder.java  #   history pass + silent active discovery
│   ├── ScenarioAccessTester.java#   cross-owner replay + AI judge + neg-control + write-IDOR (PUT/PATCH oracle)
│   ├── LoginProfilesDialog.java #   login-profiles popup — capture wizard, {user}/{pass} field pickers, copy, search
│   ├── LoginProfileBuilder.java #   pure-logic: draft profile, field mapping, token JSON-path + body-carried detect
│   └── LoginManager.java        #   mints fresh sessions per scan; rich test diagnostics
│
├── spec/                        # NEW v2
│   └── OpenApiImporter.java     #   parse OpenAPI 3.x specs → endpoint seed list
│
├── ai/                          # AI adjudication layer
│   ├── AIFalsePositiveFilter.java  # reused as adjudicator for all findings + matrix cells
│   ├── AITestingAgent.java
│   ├── AIContextAnalyzer.java
│   └── ContextInfo.java
│
├── scan/                        # Fast deterministic engine (opt-in heuristic layer)
│   ├── ActiveScanEngine.java
│   ├── TestSink.java / Baseline.java / Signals.java / Probe.java / RequestKit.java
│   ├── JsonIds.java             #   NEW — nested/array JSON id extraction for IDOR/BOLA
│   ├── EndpointKey.java         #   endpoint-template dedup (collapse id-variants)
│   └── modules/                 #   (InjectionModule + GraphQL removed — Burp covers SQLi/XSS)
│       ├── IdorModule.java          # ownership-aware + nested-JSON + AI body-diff
│       ├── AccessControlModule.java
│       ├── MassAssignmentModule.java
│       ├── CaptchaBypassModule.java
│       ├── MisconfigModule.java
│       ├── SsrfRedirectModule.java
│       ├── BruteForceModule.java    # + B06 success-detection
│       ├── FileUploadModule.java
│       ├── ErrorForcingModule.java  # B01
│       ├── HttpMethodModule.java    # B02
│       ├── TransportModule.java     # B03
│       ├── ContentDiscoveryModule.java  # B04 (dir-scan; off by default)
│       └── ParamGuessModule.java    # B05
│
├── ambient/                     # Ambient Copilot
│   ├── AmbientCoordinator.java / PassiveTriage.java / TargetModel.java
│   ├── OpportunityQueue.java / Opportunity.java
│   ├── SiteAgentOrchestrator.java / BackgroundHunter.java
│
├── engine/                      # AgentPentestEngine (ReAct) + SharedRateLimiter (global WAF/FW funnel)
├── recon/                       # NEW — AiEndpointDiscoverer, ForcedBrowser, ParamMiningTester (surface + hidden params)
├── i18n/                        # NEW — I18n catalog (~460 keys, TR/EN) + I18nUI + Glyphs
├── playbook/                    # Playbook, PlaybookLibrary, PlaybookRouter (+ resources/playbooks/*.md)
├── api/ChainAttackDetector.java
├── businesslogic/WorkflowAnalyzer.java
└── PoCGenerator.java / FilterEngine.java / ColorScheme.java

src/main/resources/
├── secrets.json                 # OPTIONAL bundled keys (gitignored; for internal team distribution)
└── playbooks/*.md               # editable agentic playbooks
```

---

## 📝 Changelog

### 2026-06 → 2026-07 — Access-control focus · WAF-aware · banking login profiles

**Access-control depth (IDOR / BOLA / BAC)**
- `OwnershipOracle` — public-resource + own-data discriminators; anonymous public probe; **suppress-unless-confirmed**. Reports only a proven cross-owner leak (kills the two biggest IDOR FPs).
- `JsonIds` — nested/array JSON id extraction (`{"account":{"id":…}}`, `[{…}]`); byte-offset splice (no re-serialize). Wired into `IdorModule` (single-session) and `AccessModelBuilder` (cross-owner).
- **Write-IDOR** in `ScenarioAccessTester` — idempotent PUT/PATCH replay + status oracle → Critical/CONFIRMED (DELETE/POST excluded; consent-gated).
- Single-session endpoint-param IDOR now runs **always**, alongside cross-owner BOLA (was an either/or branch that 3 accounts skipped).
- `SessionHarvester`: **403 = authenticated-but-forbidden** (VALID), only 401 = expired — a 403 no longer collapses the matrix to anonymous.

**WAF/FW evasion ("min istek, maks bulgu")**
- One global `SharedRateLimiter` funnel; per-minute ceiling (default 100) + per-second smoothing + jitter; reactive per-host WAF circuit-breaker (`noteResult`/`isHostBlocked`), 25 s bounded send, slow-on-first-signal.
- Volume trimming: `InjectionModule` + GraphQL removed, `ParamGuess` 11→7, directory brute-forcing off by default, router `all`→`ai`. Defaults lowered: 100 req/min, 2 parallel probes, 2 agents.
- **SQLi & XSS checks removed** (Burp covers them); `heuristicScanEnabled=false` and `contentDiscoveryEnabled=false` by default → AI scan focuses on access control.
- Login sessions **minted once per campaign** (5-min guard on the shared `MultiSessionTester`): 3 accounts = 3 logins, not 9.

**Banking-grade login profiles**
- `{user}`/`{pass}` **field-mapping pickers** for complex JSON logins (immutable-rawBody re-derivation → switching a mapping never corrupts another field, e.g. the app-channel `ExtUPassword` secret).
- **Body-carried session** auto-config (`tokenBodyField`, e.g. Gateway `sessionToken`); **Copy** profile; **searchable** full-history picker; **OTP/STS login** warning; rich `LoginManager` test diagnostics (status, empty-vs-missing token, response preview) + `[LoginManager]` logs.

**Other**
- Bilingual UI (TR/EN, `burp.i18n`); `SecretsProvider` 3-layer resolution incl. jar-bundled `/secrets.json` for zero-config internal team distribution; run-lifecycle fix ("Close Finished" no longer closes running scans); per-run scan logs under `~/.appsechunter/logs/`.

---

### 2026-06-25 — Settings simplification (always-on) · Login Profiles → Auth Matrix tab

**Always-on modules (toggles removed)**
- Removed the entire Detection-Engine checkbox block from Settings: the OWASP **module toggles** (IDOR / Access Control / Injection / Misconfig / SSRF / CAPTCHA), the **intrusive** tests (brute force / file upload / active SSRF / command-timing), the **deep-AI pass**, the **Agentic-focus** checkboxes, and the Ambient **on/off + hunter + scope-only + share-rate-limiter** checkboxes — plus the now-orphaned **Safe / Balanced / Aggressive** mode buttons.
- All of those features now **default ON** (`Settings.createDefault` / `loadFromJson`). Intrusive tests run on **every scan**, gated only by the per-scan confirmation dialog (`hasAnyIntrusiveEnabled`).
- The **autonomous background hunter auto-starts on extension load** (`ambientHunterEnabled` default-on; ambient flags use default-on, not force-on, so declining consent still persists). Stop it from the **Copilot panel kill switch**, not Settings.
- Settings → Detection Engine now keeps only: fast model, max tokens, parallelism, site-scan limit, and ambient min-score / concurrency / token-budget / time-budget / router-mode.

**Login Profiles moved to the Authorization Matrix tab**
- The whole *AI Pentester (agentic ReAct)* block — agent max-steps/model **and** login profiles (capture wizard + raw-JSON editor + Test) — left Settings and now lives in a popup opened from the **Yetki Matrisi** tab → **🔐 Login Profilleri** button.
- New self-contained `burp.authz.LoginProfilesDialog`: a profiles `JTable` (➕ Add / ✏️ Edit / 🗑️ Delete / 🔑 Test) with **⚙️ Advanced (JSON)** behind a toggle. Persists **directly** via `SettingsManager` (no Settings "Save" needed); wired through `AuthMatrixPanel.setLoginAccess(...)`. Settings shows only a pointer note (`settings.agent.movedNote`).
- Marker: `login-profiles-popup-v1`.

---

### v2.1 (2026-06-18) — Scenario-Based BOLA/IDOR · One-click "Hepsini Tara" · UI simplification

**Scenario-Based BOLA/IDOR (ground truth)**
- `AccessModel` / `AccessModelBuilder` — object-ownership map built from proxy history (HTTP 200 = owned) + silent active discovery to validate ownership (re-sends owned GETs, drops 401/403/404).
- `ScenarioAccessTester` — cross-owner replay (attacker A tries object owned by B≠A), negative control (invalid id), AI `judgeAccessControl` with three-way comparison. Finding: **BOLA (Ground-Truth)**. Cap: 80 tests.
- `ScanManager.runScenarioAccessHunt` — RECON (harvest → validate → build model → log summary) → EXECUTE → REPORT (deduped). GET-only unless `includeMutating` consented.
- `AgentPentestEngine.setAccessModel(model)` — injects full ownership map into agent context; ReAct agent drives provable cross-owner / multi-step scenarios via existing actions.
- `ScanManager.runAgenticAccessHunt` — harvest + validate → register sessions into `MultiSessionTester` → build model → run agentic driver.

**One-click "Hepsini Tara" (menu-v5)**
- Context menu consolidated to **3 items** in a single `AppSecHunter ▸` submenu: *Hepsini Tara*, *Sadece bu istek*, *Add Session*.
- `startEverything(seed)` fires the full campaign with one confirmation dialog: `runActiveScan` + `runPlaybookHunt` (AI) + `runSiteScan` + `runAutoAuthMatrix` always; `runSurfaceScan` + `runScenarioAccessHunt` + `runAgenticAccessHunt` only when AI configured.
- Scanner toolbar slimmed: **🚀 Hepsini Tara** + New Scan + Scan Domain + Close Tab. Removed: Quick Tests / Dynamic Tests / AI Autonomous (all ran the same generic scan internally).
- Build marker: `menu-v5-hepsini-tara` → `access-model-v1` → `agentic-driver-v1`.

---

### v2.0 (2026-06) — AI adjudication · Authorization Matrix · Report probes

**AI Adjudication**
- Every deterministic candidate finding is reviewed by the AI before reporting; refuted = FP-flagged and kept.
- `ScanManager.aiJudge` / `aiJudgeAll` reuse `AIFalsePositiveFilter` — zero extra infrastructure.
- AI-driven BOLA/IDOR: `IdorModule` captures baseline ↔ manipulated bodies; AI confirms cross-owner leakage (`judgeAccessControl`). Gate on `IdorModule` loosened so more candidates reach adjudication.
- Fail-open: AI unavailable → finding reported normally; scanning never blocked.

**Authorization Matrix (Yetki Matrisi)**
- New `burp/authz` package: role × endpoint access-control matrix on top of `MultiSessionTester.replayAs`.
- `SessionHarvester` auto-discovers roles from proxy history (no manual session setup needed).
- `AccessOracle` V1 (status diff) / V2 (body-length diff) / V3 (AI body diff) verdict rules.
- Colour-coded **Yetki Matrisi** tab + CSV/HTML export. `ScanManager.runAuthMatrix`.
- `OpenApiImporter` (`burp/spec`) parses OpenAPI 3.x specs → endpoint seed list.
- Mutating-method (POST/PUT/DELETE) consent dialog before replaying.

**Report-Reproduction Probes (B-series)**
- B01 `ErrorForcingModule` — triggers verbose error pages to surface stack traces and framework banners.
- B02 `HttpMethodModule` — tests non-standard verbs on every endpoint.
- B03 `TransportModule` — checks HTTP→HTTPS downgrade and HSTS absence.
- B04 `ContentDiscoveryModule` — probes common hidden paths and backup files.
- B05 `ParamGuessModule` — appends hidden parameters to reveal additional surfaces.
- B06 `BruteForceModule` (success-detection) — characterises responses to detect missing rate-limiting.
- B07–B08 raw-request escape hatch: `Probe.rawRequest` / `overrideService` + `RequestKit`.

**Other**
- Extension renamed **AppSecHunter**; tab caption updated; context menu relabeled.
- Background menu simplified to 2 actions (scan + unload); heavy work always runs in background threads.

---

### v1.3.7 (2026) — Fast engine + Ambient Copilot

- **Fast deterministic OWASP engine** (`burp.scan`) with 7 modules; AI removed from per-request hot loop (~10–15× faster).
- **Ambient Security Copilot**: passive LLM-free triage, Opportunities feed, autonomous background hunter with token/time/concurrency/rate budgets.
- **Playbook-driven agentic pentester**: `AgentPentestEngine` (ReAct) + `PlaybookRouter` + editable Markdown playbooks.
- **Local AI support** (Ollama / LM Studio / llama.cpp) alongside cloud.
- **Visual Detection tab** with per-run sub-tabs, live Active Tests table, counters, progress bar.
- **Single Findings view** with dedup, Burp Issues integration, learning loop.
- **Security Assistant** chatbot; simplified 2-item context menu.

### v1.1.0 (2025)
- Chain Attack engine, business-logic testing, thread-safety improvements.

### v1.0.0 (2024)
- Initial AI-powered scanning release.

---

## 🔐 Security & privacy
- With a **local model**, no scan data leaves your machine.
- Scan results are stored locally (SQLite); API keys are kept in Burp's preferences.
- Only run active scans against authorized targets.

---

## 📜 License
MIT License — © Zahid Eroglu. See [LICENSE](LICENSE).

## 👨‍💻 Author
**Zahid Eroglu**

---

<div align="center">

**Made with ❤️ by Zahid Eroglu** — if this helps you, consider a ⭐

</div>
