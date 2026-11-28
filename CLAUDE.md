# NetMigrate — Project Rules for Claude Code

Single source of truth: [691114-ทก1.md](691114-ทก1.md) (approved project proposal, ทก.01).
If anything here conflicts with that file, the proposal wins. Do not expand scope beyond it.

## 1. Project status & tech stack

Network Configuration Conversion System for Multi-Vendor Migration.
Bidirectional translation **Cisco IOS-XE ⇄ Huawei VRP**, **IPv4 only**. No other vendor pair.

**Status: feature-complete.** Milestones 1–5 are done and **863 `pytest` tests pass**.

| Milestone | Delivered |
|---|---|
| 1 | Core foundation: IR, enums, security gate (`secret_stripper.py`) |
| 2 | Pre-scan analyzer, bidirectional parsers/renderers, Tier-1 rules |
| 3 | Tier-2 and Tier-3 rules |
| 4 | AI/Hybrid translation engine, bilingual TH/EN web UI |
| 5 | All 8 modules from proposal §2.3.1 |

All 8 modules are implemented. Every page has a bilingual **TH/EN** UI (`app/i18n.py`,
`app/i18n_pages.py`) and **Light/Dark** themes (Tailwind `darkMode: "class"`, saved in
`localStorage["netmigrate-theme"]` and applied before first paint in `base.html`).

**Stack** (Python 3.11+, see [requirements.txt](requirements.txt)):

| Concern | Library |
|---|---|
| Web framework | FastAPI + Uvicorn, Jinja2 templates, `python-multipart` |
| UI | Tailwind CSS (CDN), vanilla JS per page in `app/static/js/` |
| Persistence | SQLite, one file, stdlib `sqlite3` via `app/db.py` (tables created on demand) |
| Settings | `pydantic-settings` + `python-dotenv` (`app/config.py`) |
| LLM client | `httpx`, talking to any **OpenAI-compatible** Chat Completions endpoint |
| SSH deploy | `netmiko` |
| Tests | `pytest` (+ optional Node harness in `tests/js/`) |
| Stdlib | `difflib` (diff/version compare), `zipfile` (batch), `ipaddress` |

## 2. Architecture: source-to-source translator

```
raw text ─► strip_secrets ─► Parser (per vendor) ─► IR (vendor-agnostic) ─► Renderer (per vendor) ─► labelled lines
                                   │
                                   └─► (hybrid / ai_only / user-selected) sanitized lines ─► AI ─► "มาจาก AI ต้องตรวจสอบก่อนใช้"
```

- `app/core/engine.py` is the pipeline entrypoint (`convert`, `convert_selected`).
- `app/core/parsers/` has one parser per vendor. Parsers never emit target syntax.
- `app/core/ir.py` is the Intermediate Representation: it represents config *intent*, not text.
- `app/core/renderers/` has one renderer per vendor. Renderers never read source text.
- `app/core/rules/` holds the conversion rules. Each rule reports whether it converted its block
  **completely** (`complete: bool`) so the mode engine knows whether to fall back.
- Every syntax difference is classified **D** (Direct: 1:1 word/line), **T** (Transform:
  1 line → 1 line, argument format changes, e.g. `10,20,30-35` ⇄ `10 20 30 to 35`) or
  **S** (Structural: block nesting/order changes, e.g. OSPF).
- Round-trip fidelity is compared **at the IR level**, never at the text level.

### Rule coverage (3 risk tiers, all implemented)

| Tier | File(s) | Coverage |
|---|---|---|
| 1 | `tier1_system.py`, `tier1_vlan.py`, `tier1_interface.py`, `tier1_routing.py`, `interface_names.py` | hostname/domain/NTP target/syslog target/file assembly (`configure terminal`⇄`system-view` rendered first, `end`⇄`return`, `write memory`/`copy run start`⇄`save force` after it, `no ip domain-lookup`, bare `enable`, `service password-encryption` and `logging synchronous` (anywhere, incl. inside `line con`/`line vty`) → not needed); view exits `exit`⇄`quit` (one per nested Huawei view; every Huawei `vlan <id>` block always ends with `quit`); banners `banner login <d>…<d>`⇄`header login information <d>…<d>` and `banner motd <d>…<d>`⇄`header shell information <d>…<d>` (never `header banner`; multi-line text kept verbatim; unsafe delimiter replaced with a warning); VLAN & port (access/trunk/STP edge; port-security `maximum <n>`⇄`max-mac-num <n>`, violation⇄`protect-action`, sticky; `ip dhcp snooping trust`⇄`dhcp snooping trusted`; interface-level `spanning-tree bpduguard enable` → not needed because Huawei `stp bpdu-protection` is system-view only); interfaces incl. `interface range`⇄`port-group group-member` (numbers verbatim); static routes; OSPFv2 |
| 2 | `tier2_services.py` | RIP, redistribute, default route, NTP, syslog, VTY/console (`login local`⇄`authentication-mode aaa`, `line con 0`⇄`user-interface con 0`), SSH server (`ip ssh version 2`⇄`ssh server compatible-ssh1x disable`, `time-out`⇄`ssh server timeout`, `authentication-retries`⇄`ssh server authentication-retries`), `clock timezone ICT 7 0`⇄`clock timezone ICT add 07:00:00`, DHCP snooping (`ip dhcp snooping vlan 10,20` → per-VLAN `vlan <id>`/` dhcp snooping enable`/`quit`, never `dhcp snooping enable vlan …`; `dhcp enable` only as a comment advisory), global `spanning-tree portfast bpduguard default`⇄`stp bpdu-protection`, `spanning-tree mode rapid-pvst`⇄`stp mode rstp` and `spanning-tree portfast default`⇄`stp edged-port default` (both with a semantics warning; other STP modes unconverted) (no user-account commands). Final Huawei assembly (`huawei_vrp.order_global_dhcp_snooping`, every mode incl. AI output) keeps global `dhcp snooping enable` + its `dhcp enable` advisory before any interface/port-group with `dhcp snooping trusted` |
| 3 | `tier3_bgp_acl.py` | BGP, ACL, with behavioural tests (silent-failure risk) |

## 3. Pre-scan + 3 conversion modes

- **Pre-scan** (`app/core/prescan.py`, `POST /api/prescan`) always runs first and converts nothing.
  It reports the rule-coverage % for the file and lists the line numbers the rules do not support,
  so the user can choose a mode. `app/services/mode_selector.py` resolves the effective mode.
- `hybrid` (**default**): rules first. AI is called **only** when (a) no rule matches the block,
  (b) a rule matched but reported incomplete, or (c) the block header matches the configured
  complex-command list (`AI_COMPLEX_COMMANDS`; there the AI output replaces the rule output).
  - Hybrid **never auto-sends** lines whose reason is out-of-scope, "not supported", or
    intentionally-not-converted (`rules/base.py::auto_ai_eligible`). Saying `"แปลงไม่ได้"` is
    safer than producing a plausible command whose meaning has shifted.
  - The user can still pick any of those `"แปลงไม่ได้"` lines **manually** and send only them
    via `POST /api/convert/selected` (`engine.convert_selected`).
- `rule_only`: never sends anything externally. Unconvertible lines are kept, labelled
  `"แปลงไม่ได้"`, and listed so the user can *manually* pick which ones to send to AI.
- `ai_only`: sends all (sanitized) commands to AI.
- If the AI service or API key is unavailable, or the AI answers garbage, the result is exactly
  the `rule_only` result plus a notice (`NOTICE_AI_UNAVAILABLE` / `NOTICE_AI_FAILED`).
  The service never stops.
- AI self-reported confidence is **never** used to decide trustworthiness.

## 4. Per-line provenance labels (exact Thai strings, do not paraphrase)

Every output line carries exactly one label, in every mode (`app/core/ir.py::Provenance`):

| Enum (`Provenance`) | Exact string | Deployable |
|---|---|---|
| `RULE` | `"มาจากกฎ"` | yes |
| `AI` (alias `AI_REVIEW`, the same member) | `"มาจาก AI ต้องตรวจสอบก่อนใช้"` | **no** |
| `SYSTEM` | `"ระบบสร้างขึ้นเอง"` | yes (commands only; comments are always stripped) |
| `UNCONVERTED` | `"แปลงไม่ได้"` | **no** |
| `NOT_NEEDED` | `"ไม่ต้องใช้คำสั่งนี้"`: the command is redundant because of a target default (e.g. `switchport trunk encapsulation dot1q` → Huawei). This is **not** the same as `"แปลงไม่ได้"`. | **no** |

`Provenance.deployable` returns true only for `RULE` and `SYSTEM`.

**What `SYSTEM` covers (as implemented):**
- **The only command block the system adds on its own:** for Huawei BGP, `ipv4-family unicast` +
  `peer <ip> enable` per neighbor (see §6). No other command is ever auto-filled.
- ACL header lines whose number the system *assigned* during type-based mapping
  (`acl number …` / `ip access-list … <n>`) carry `SYSTEM` plus a collision warning. These are
  translations of a source line, not added commands.
- Advisories written as target-vendor **comments**, never as commands: credential-stripped notices,
  the AI-secret notice, and `stelnet server enable`. Huawei needs SSH enabled with this command, but
  the renderer only writes it as a `SYSTEM` comment advisory (`ADVISORY_STELNET`) and never emits it
  as a command. Likewise a Cisco trunk with no allowed-VLAN list gets the comment advisory
  `ADVISORY_TRUNK_ALLOW_ALL` ("…port trunk allow-pass vlan all") right after `port link-type trunk`,
  never the command itself.

Nothing is ever silently dropped. Unsupported or out-of-scope commands are written as comments
using the **target** vendor's comment marker (`!` Cisco, `#` Huawei) with a review warning.
Out of scope (comment + review label, never dropped): IPv6, OSPFv3, RIPng, IS-IS, QoS policy,
Route-Map/Route-Policy, VRF, Tunnel & ATM interfaces, and every "not supported" item in §6.

## 5. SECURITY & DEPLOYMENT GUARDRAILS (non-negotiable, every mode, every code path)

1. **Strip before storage.** `history_service` runs `strip_secrets_keep_lines()` (a wrapper over
   `strip_secrets`) before writing to SQLite (`netmigrate.db`). Credential lines are replaced by a
   fixed-text advisory so before/after line numbers still align. The `devices` table has no
   username/password columns. `deployments` stores the filtered commands and the log, never SSH
   credentials.
2. **Strip before AI.** Credentials, usernames, keys and community strings are removed by
   *deterministic rules* (`app/core/secret_stripper.py::strip_secrets`) **before** any request to an
   external AI API is assembled. This applies in `hybrid`, `ai_only`, user-selected sends from
   `rule_only`, and topology descriptions. `ai_translator.py` re-applies the filter (defence in
   depth). **Output sanitization:** every AI answer line is checked with `contains_secret()` and
   dropped, replaced by the `ADVISORY_AI_SECRET` advisory. Never rely on prompt instructions to hide
   secrets. **Interactive commands** (`rsa local-key-pair create`, `crypto key generate`, …;
   `secret_stripper.is_interactive_command`) in AI answers are replaced by the SYSTEM comment
   `ADVISORY_AI_INTERACTIVE` ("ตัดข้อมูลลับออก …") because they prompt `[Y/N]` and hang scripted pushes.
3. **Never output secrets.** Passwords, hashes and keys never appear in converted files, neither as
   commands nor **inside `!` or `#` comments**. Emit a manual-configuration advisory instead, telling
   the admin to reconfigure on the target device.
4. **Strip before deploy** (`app/services/deploy_service.py::build_plan`):
   - Push **only** `RULE` (`"มาจากกฎ"`) and `SYSTEM` (`"ระบบสร้างขึ้นเอง"`) command lines.
   - Always strip comment lines, `UNCONVERTED`, `AI`/`AI_REVIEW`, and `NOT_NEEDED` lines.
   - Mode entry/exit and save lines (`TERMINATORS`: `configure terminal`, `system-view`, `end`,
     `return`, `save force`, `write memory`, …) are not pushed: Netmiko enters/leaves config mode
     itself and saves with `save_config()`.
   - Also strip credential/user lines (`strip_secrets` + `contains_secret`). Removed credentials
     are reported without their text. Interactive commands are stripped too (reason `interactive`).
   - Deployment always shows the full command list and requires explicit user confirmation.
   - **Simulation (dry-run) is the default** and contacts nothing. Real mode needs a device from the
     inventory that the user confirms is a self-built **EVE-NG** lab node.
   - Target SSH credentials stay **in memory only**. They are handed to the worker thread, never
     logged, never written to SQLite, and cleared (`params.clear()`) once the session opens.
5. **Batch `.zip` safety** (`app/services/batch_service.py`):
   - Archives are read entirely **in memory** and never extracted to disk.
   - **Zip Slip:** absolute paths, drive letters, `..` components and backslash tricks are
     rejected, and output names are reduced to a safe basename.
   - Only `.txt`/`.cfg`. **Encrypted** entries and **binary** content (NUL bytes, undecodable) are
     skipped.
   - **Zip-bomb limits:** `MAX_ENTRIES`, `MAX_FILE_BYTES` (read with a hard cap, never trusting the
     declared size), `MAX_TOTAL_BYTES`, `MAX_RATIO`.

Tests asserting zero leakage (AI-bound text, output files incl. comments, SQLite rows, deploy
payload) must always pass. Do not weaken or skip them.

## 6. Critical vendor edge cases

- **BGP → Huawei:** Cisco activates neighbors automatically; Huawei does not. Always
  auto-generate `ipv4-family unicast` + `peer <ip> enable` per neighbor, labelled
  `"ระบบสร้างขึ้นเอง"`. (Without it the session comes up but silently exchanges no routes.)
- **ACL numbers:** map by ACL *type*, never copy the number.

  | Type | Cisco IOS-XE | Huawei VRP |
  |---|---|---|
  | Standard/Basic | 1–99 | 2000–2099 |
  | Standard/Basic | 1300–1999 | 2100–2799 |
  | Extended/Advanced | 100–199 | 3000–3099 |
  | Extended/Advanced | 2000–2699 | 3100–3799 |

  Huawei 2800–2999 and 3800–3999 have no Cisco equivalent → mark unconvertible / warn.
  Any number the system assigns is labelled `"ระบบสร้างขึ้นเอง"` with a collision warning.
  ACL rule sequence numbers are renumbered preserving order.
- **Port numbers are never translated.** Only the interface *type name* changes; slot/port
  numbers are kept as-is, with a warning when the slot is non-zero. Exception: virtual
  interfaces (`Loopback`, `Vlanif`, `Eth-Trunk`) whose number is just a name
  (`Vlanif10` ⇔ `interface Vlan10`).
- **Default mismatches: warn, never guess values.** Static route AD=1 (Cisco) vs
  Preference=60 (Huawei); Serial HDLC (Cisco) vs PPP (Huawei), so cross-vendor serial must be PPP
  on both; default-gateway style; redistribute default metrics; BGP neighbor activation.
  (No warning for default port admin state.) Only auto-fill the BGP block above.
- **Intentionally not converted** (shown as review lines): `port trunk allow-pass vlan all`
  (H→C), `ip route ... name X` (C→H), redistribute without explicit metric (both),
  Huawei ACL 2800–2999/3800–3999 (H→C), `port link-type hybrid`, `vlan 10,20` followed by
  `name X`, anything referencing Route-Map/Route-Policy, RIP with >1 process, password lines.
- **Allowed normalizations:** `vlan batch 10 20 30` → one VLAN block each; prefix length
  → full dotted mask; ACL rule renumbering; Cisco `line vty 0 15` → Huawei `user-interface vty 0 4`
  (with a note: common Huawei maximum); top-level unconverted/AI lines are placed in source order
  (after the section that precedes them in the source), not appended at the end.

### Supported vs not supported

| Group | Supported | Not supported |
|---|---|---|
| OSPFv2 | single process, multi-area, stub, silent-interface, interface params, default-route originate | multi-process, NSSA, virtual link, ABR summarization, authentication, timers, no-summary |
| RIP | v2, single process | authentication, timers |
| BGP | single AS, IPv4 neighbors | peer group, RR, confederation, route filtering, other AFs |
| ACL | IPv4 basic/advanced, named & numbered, applied to interface | L2 ACL, time-range, user-defined, other policy use |
| Serial | type name, basic props, link-layer protocol | clock rate, channelization, frame relay |
| Redistribute | static, direct/connected, OSPF, RIP (metric must be explicit) | route-map/route-policy |

## 7. The 8 modules & route map (proposal §2.3.1)

| # | Module | Pages | API | Code |
|---|---|---|---|---|
| 1 | Single CLI / File Conversion | `GET /` | `GET /api/health`, `POST /api/prescan`, `POST /api/convert`, `POST /api/convert/selected` | `main.py`, `core/engine.py`, `core/prescan.py` |
| 2 | Batch File Conversion | `GET /batch` | `POST /api/batch/convert`, `GET /api/batch/{batch_id}`, `GET /api/batch/{batch_id}/download` (zip + `migration_report.txt/.json`) | `routes/batch.py`, `services/batch_service.py` |
| 3 | Device Inventory (registry only, never reads devices) | `GET /inventory` | `GET/POST /api/devices`, `GET/PUT/DELETE /api/devices/{device_id}` | `routes/inventory.py`, `services/inventory_service.py` |
| 4 | Configuration Deployment | `GET /deploy` | `POST /api/deploy/plan`, `POST /api/deploy/run`, `GET /api/deploy/jobs/{job_id}/events` (SSE log), `GET /api/deployments`, `GET /api/deployments/{id}`, `GET /api/deployments/{id}/log.txt` | `routes/deploy.py`, `services/deploy_service.py` |
| 5 | Dashboard & Audit History | `GET /history`, `GET /history/{conversion_id}` | `GET /api/dashboard`, `GET /api/history`, `GET /api/history/export`, `GET /api/history/compare` (**`difflib` version comparison**), `GET/DELETE /api/history/{id}`, `GET /api/history/{id}/diff`, `/download`, `/export`, `POST /api/diff` | `routes/history.py`, `services/history_service.py`, `core/diff.py` |
| 6 | System Settings & UI | `GET /settings` | `GET /api/settings/coverage` | `routes/settings_page.py`, `i18n*.py`, `web.py` |
| 7 | Topology Analysis & Configuration Advisory (3-level templates) | `GET /topology` | `POST /api/topology/analyze`, `POST /api/topology/describe` (optional AI prose, sanitized) | `routes/topology.py`, `core/topology.py`, `core/advisory.py` |
| 8 | Hardware Compatibility Validation (pure rules, 4 verdicts) | `GET /hardware` | `GET /api/hardware/catalog`, `POST /api/hardware/check` | `routes/hardware.py`, `core/hardware.py` |

## 8. Repository layout

```
691114-ทก1.md               approved proposal (single source of truth)
CLAUDE.md  README.md
requirements.txt  pytest.ini  .env.example  .gitignore
app/
  main.py                   FastAPI app: module 1 routes + includes routers below
  config.py                 Settings (pydantic-settings, .env)
  db.py                     stdlib sqlite3; tables conversions, devices, deployments, batch_skipped
  deps.py                   get_db / get_translator dependencies
  web.py                    Jinja2 env, nav, lang helpers, ASSET_VERSION
  i18n.py  i18n_pages.py    TH/EN strings (every UI key must have both languages)
  routes/
    batch.py  deploy.py  hardware.py  history.py  inventory.py  settings_page.py  topology.py
  core/
    ir.py                   IR + enums (Vendor, ConversionMode, SyntaxCategory, Provenance)
    engine.py               pipeline: strip → parse → rules/AI → render; convert / convert_selected
    prescan.py              coverage % + unsupported line list (no conversion)
    secret_stripper.py      deterministic credential filter (security gate)
    vendor_detect.py        Cisco vs Huawei auto-detection
    diff.py                 difflib-based before/after and version diffs
    topology.py             module 7 rule-based topology analysis
    advisory.py             module 7 three-level configuration templates
    hardware.py             module 8 catalogue + 4-verdict compatibility (pure rules)
    parsers/    __init__.py  common.py  cisco_iosxe.py  huawei_vrp.py
    renderers/  __init__.py  common.py  cisco_iosxe.py  huawei_vrp.py
    rules/      __init__.py  base.py  interface_names.py
                tier1_system.py  tier1_vlan.py  tier1_interface.py  tier1_routing.py
                tier2_services.py  tier3_bgp_acl.py
  services/
    ai_translator.py        OpenAI-compatible httpx client + input/output secret filtering
    mode_selector.py        resolves hybrid / rule_only / ai_only (+ unavailable fallback)
    batch_service.py        in-memory zip handling + batch conversion + reports
    deploy_service.py       deploy plan filter, simulation & Netmiko jobs, SSE logs
    history_service.py      sanitized audit history + dashboard stats
    inventory_service.py    device registry CRUD
  templates/
    base.html  convert_single.html  batch.html  inventory.html  deploy.html
    history.html  history_detail.html  settings.html  topology.html  hardware.html
  static/
    js/       app.js  convert.js  batch.js  inventory.js  deploy.js
              history.js  history_detail.js  topology.js  hardware.js
    samples/  cisco_sample.txt  huawei_sample.txt
tests/
  conftest.py               per-test temp SQLite (real netmigrate.db never touched)
  helpers.py
  fixtures/                 cisco_tier1.txt  cisco_tier23.txt  cisco_with_secrets.txt
                            huawei_tier1.txt huawei_tier23.txt huawei_with_secrets.txt
  js/convert_harness.js     Node harness running real page scripts (skipped without Node)
  test_secret_stripper.py  test_prescan.py  test_tier1_rules.py  test_tier2_rules.py
  test_tier3_rules.py  test_ai_hybrid.py  test_batch.py  test_deploy.py  test_history.py
  test_inventory_hardware.py  test_topology_settings.py  test_web_ui.py  test_ui_samples.py
  test_ai_translator.py  test_huawei_accuracy.py  test_hybrid_verification.py
  test_two_tuple_ports.py  test_medium_verification.py  test_banner_stp_vlan_order.py
```

Static URLs carry `?v={{ asset_v }}`. Bump `web.ASSET_VERSION` on any UI/JS change.

## 9. Environment configuration (`.env`, see `.env.example`)

| Variable | Default | Purpose |
|---|---|---|
| `LLM_API_KEY` | *(empty)* | Empty → AI unavailable → automatic `rule_only` fallback with a notice |
| `LLM_API_BASE_URL` | `https://api.openai.com/v1` | Any OpenAI-compatible base; the client POSTs to `{base}/chat/completions` |
| `LLM_MODEL` | `gpt-4o-mini` | Model name sent to the endpoint |
| `LLM_TIMEOUT_SECONDS` | `60` | Request timeout |
| `AI_COMPLEX_COMMANDS` | *(empty)* | Comma-separated, case-insensitive block-header prefixes hybrid always sends to AI, e.g. `router bgp,bgp` |
| `DATABASE_URL` | `sqlite:///./netmigrate.db` | Single SQLite file |

**Google AI Studio / Gemini**: when the base URL contains `generativelanguage.googleapis.com` or the
model starts with `gemini-`, `ai_translator.py` automatically uses the native REST API
(`/v1beta/models/{model}:generateContent`, `x-goog-api-key` header, JSON response mode) instead of
`/chat/completions`. On failure, the fallback banner shows the reason (auth / invalid model / rate
limit / timeout / network / server / bad request / unusable answer), and the client logs the HTTP
status and provider message. The key is never logged.

```
LLM_API_KEY=<AI Studio key>
LLM_API_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-2.5-flash
```

Never commit `.env` or real device configs containing secrets.

## 10. Running & testing

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
copy .env.example .env                                   # then fill in LLM_* if AI is wanted
.venv\Scripts\python -m uvicorn app.main:app --reload    # http://127.0.0.1:8000
.venv\Scripts\python -m pytest -v                        # must be all green before "done"
```

- `tests/conftest.py` gives every test its own throw-away SQLite file. Tests must **never**
  touch the live `netmigrate.db`; keep any new DB-using test on that fixture.
- AI tests use fake translators and never call a real LLM endpoint.
- JS harness tests in `tests/js/` are skipped automatically when Node is not installed.

## 11. Development methodology

- **TDD with pytest**: write the failing test for a rule *before* the rule. Fixtures live in
  `tests/fixtures/`. Run `.venv\Scripts\python -m pytest -v` before declaring work done.
- Rules were built in the 3 risk tiers of §2, in order. Tier 3 (BGP, ACL) is not "done"
  without behavioural tests (silent-failure risk).
- Hardware compatibility checks (module 8) are pure rules, deterministic and fully unit-tested.
- Every new UI string needs both TH and EN entries. Every new page must work in Light and Dark.
