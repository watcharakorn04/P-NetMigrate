# NetMigrate — Project Rules for Claude Code

Single source of truth: [691114-ทก1.md](691114-ทก1.md) (approved project proposal, ทก.01).
If anything here conflicts with that file, the proposal wins. Do not expand scope beyond it.

## 1. What this system is

Network Configuration Conversion System for Multi-Vendor Migration.
Bidirectional translation **Cisco IOS-XE ⇄ Huawei VRP**, **IPv4 only**. No other vendor pair.

Stack: Python 3.11+, FastAPI + Uvicorn + Jinja2, python-multipart, Netmiko, pytest,
SQLite (single file), Tailwind CSS, stdlib `difflib` / `zipfile` / `ipaddress`.

### Architecture: Source-to-Source Translator

```
source text ──► Parser (per vendor) ──► IR (vendor-agnostic) ──► Renderer (per vendor) ──► target text
```

- `app/core/parsers/` — one parser per vendor. Parsers never emit target syntax.
- `app/core/ir.py` — Intermediate Representation; represents config *intent*, not text.
- `app/core/renderers/` — one renderer per vendor. Renderers never read source text.
- `app/core/rules/` — conversion rules. Each rule reports whether it converted its block
  **completely** (`complete: bool`) so the mode engine knows whether to fall back.
- Every syntax difference is classified **D** (Direct 1:1 word/line), **T** (Transform —
  1 line → 1 line, argument format changes, e.g. `10,20,30-35` ⇄ `10 20 30 to 35`) or
  **S** (Structural — block nesting/order changes, e.g. OSPF).
- Round-trip fidelity is compared **at the IR level**, never at the text level.

## 2. Pre-scan + 3 conversion modes

- **Pre-scan** (always first, no conversion): report rule-coverage % for the file and list
  the line numbers the rules do not support, so the user can choose a mode.
- `hybrid` (**default**): rules first; call AI **only** when (a) no rule matches the block,
  (b) a rule matched but reported incomplete, or (c) the block is on the configured
  complex-command list.
- `rule_only`: never send anything externally. Unconvertible lines are kept, labelled
  `"แปลงไม่ได้"`, and listed so the user can *manually* pick which ones to send to AI.
- `ai_only`: send all (sanitized) commands to AI.
- If the AI service / API key is unavailable → behave as `rule_only` and tell the user.
  The service never stops.
- AI self-reported confidence is **never** used to decide trustworthiness.

## 3. Per-line provenance labels (exact Thai strings — do not paraphrase)

Every output line carries exactly one label, in every mode:

| Enum (`Provenance`) | Exact string |
|---|---|
| `RULE` | `"มาจากกฎ"` |
| `AI` | `"มาจาก AI ต้องตรวจสอบก่อนใช้"` |
| `SYSTEM` | `"ระบบสร้างขึ้นเอง"` |
| `UNCONVERTED` | `"แปลงไม่ได้"` |
| `NOT_NEEDED` | `"ไม่ต้องใช้คำสั่งนี้"` — command redundant by target default (e.g. `switchport trunk encapsulation dot1q` → Huawei). This is **not** the same as `"แปลงไม่ได้"`. |

- Nothing is ever silently dropped. Unsupported/out-of-scope commands are written as comments
  using the **target** vendor's comment marker (`!` Cisco, `#` Huawei) with a review warning.
- Out of scope (comment + review label, never dropped): IPv6, OSPFv3, RIPng, IS-IS, QoS policy,
  Route-Map/Route-Policy, VRF, Tunnel & ATM interfaces, and every "not supported" item in §4.

## 4. SECURITY NON-NEGOTIABLES (must hold in every mode, every code path)

1. **Strip before AI.** Credentials, usernames, keys, community strings are removed by
   *deterministic rules* (`app/core/secret_stripper.py::strip_secrets`) **before** any request
   to an external AI API is assembled — in `hybrid`, `ai_only`, and user-selected sends from
   `rule_only`. Never rely on prompt instructions to hide secrets.
2. **Never output secrets.** Passwords/hashes/keys never appear in converted files — not as
   commands and **not inside `!` or `#` comments**. Emit a manual-configuration advisory
   instead, telling the admin to reconfigure on the target device.
3. **Strip before deploy.** Before any Netmiko SSH push, remove: comment lines, lines labelled
   review-required (`AI`) or `"แปลงไม่ได้"`, and credential/user lines. Deployment always shows
   the full command list and requires explicit user confirmation. Simulation mode is default;
   real mode only targets self-built EVE-NG virtual devices.

Tests asserting zero leakage (AI-bound text, output files incl. comments, deploy payload) must
always pass. Do not weaken or skip them.

## 5. Critical vendor edge cases

- **BGP → Huawei:** Cisco activates neighbors automatically; Huawei does not. Always
  auto-generate `ipv4-family unicast` + `peer <ip> enable` per neighbor, labelled
  `"ระบบสร้างขึ้นเอง"`. (Without it the session comes up but exchanges no routes, silently.)
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
- **Default mismatches — warn, never guess values:** static route AD=1 (Cisco) vs
  Preference=60 (Huawei); Serial HDLC (Cisco) vs PPP (Huawei) — cross-vendor serial must be PPP
  on both; default-gateway style; redistribute default metrics; BGP neighbor activation.
  (No warning for default port admin state.) Only auto-fill the BGP block above.
- **Intentionally not converted** (shown as review lines): `port trunk allow-pass vlan all`
  (H→C), `ip route ... name X` (C→H), redistribute without explicit metric (both),
  Huawei ACL 2800–2999/3800–3999 (H→C), `port link-type hybrid`, `vlan 10,20` followed by
  `name X`, anything referencing Route-Map/Route-Policy, RIP with >1 process, password lines.
- **Allowed normalizations:** `vlan batch 10 20 30` → one VLAN block each; prefix length
  → full dotted mask; ACL rule renumbering.

### Supported vs not supported

| Group | Supported | Not supported |
|---|---|---|
| OSPFv2 | single process, multi-area, stub, silent-interface, interface params, default-route originate | multi-process, NSSA, virtual link, ABR summarization, authentication, timers, no-summary |
| RIP | v2, single process | authentication, timers |
| BGP | single AS, IPv4 neighbors | peer group, RR, confederation, route filtering, other AFs |
| ACL | IPv4 basic/advanced, named & numbered, applied to interface | L2 ACL, time-range, user-defined, other policy use |
| Serial | type name, basic props, link-layer protocol | clock rate, channelization, frame relay |
| Redistribute | static, direct/connected, OSPF, RIP — metric must be explicit | route-map/route-policy |

## 6. Development methodology

- **TDD with pytest**: write the failing test for a rule *before* the rule. Fixtures in
  `tests/fixtures/`. Run `.venv\Scripts\python -m pytest -v` before declaring work done.
- Implement rules in **3 risk tiers**, in order:
  1. Tier 1 — System (hostname/domain/NTP target/syslog target/file assembly), VLAN & port
     (access/trunk/STP edge), Interface, Static route, OSPFv2.
  2. Tier 2 — RIP, Redistribute, Default route, NTP, Syslog, VTY/SSH (no user-account commands).
  3. Tier 3 — BGP, ACL. Not "done" until behavioural tests exist (silent-failure risk).
- Hardware compatibility checks (module 8) are pure rules, deterministic, fully unit-tested.

## 7. Layout

```
app/
  main.py                 FastAPI app: module 1 (convert/prescan/health) + includes routers
  routes/                 modules 2–8 (batch, inventory, deploy, history, settings_page, topology, hardware)
  web.py  deps.py         templates/nav/lang helpers; get_db / get_translator dependencies
  db.py                   stdlib sqlite3, tables auto-created (conversions, devices, deployments, batch_skipped)
  config.py               settings (LLM_API_KEY, DATABASE_URL) via pydantic-settings
  i18n.py  i18n_pages.py  TH/EN strings (every UI key must have both languages)
  core/
    ir.py                 IR + enums (Vendor, ConversionMode, SyntaxCategory, Provenance)
    secret_stripper.py    deterministic credential filter (security gate)
    parsers/  renderers/  rules/
    hardware.py           module 8 catalogue + 4-verdict compatibility (pure rules)
    topology.py advisory.py  module 7 rule-based topology + 3-level templates
    diff.py  vendor_detect.py
  services/               AI client, history, batch (in-memory zip), inventory, deploy (Netmiko)
  templates/  static/     static URLs carry ?v={{ asset_v }} — bump web.ASSET_VERSION on UI changes
tests/
  conftest.py             per-test temp SQLite (real netmigrate.db never touched)
  fixtures/  js/          js/ = Node harness running real page scripts (skipped without Node)
```

Never commit `.env` or real device configs containing secrets.
