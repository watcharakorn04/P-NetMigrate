"""Bilingual UI dictionary (Thai default, English) — proposal §2.3.1 module 6.

* `t(key, lang)`            — UI strings (navigation, modes, buttons, pre-scan metrics …)
* `provenance_label(p, lang)` — Thai labels are EXACTLY the `Provenance` enum values
* `translate_message(msg, lang)` — English rendering of the engine's Thai warnings, reasons
  and notices. The engine and the converted config always stay Thai (the provenance labels
  inside comments are part of the spec); only what the UI shows around them is translated.
  Unknown messages are returned unchanged, so nothing is ever hidden.
"""

from __future__ import annotations

import re
from typing import Optional

from app.core import engine
from app.core.ir import Provenance
from app.core.renderers import common as R
from app.core.rules import base as B
from app.core.rules import tier1_interface as T1I
from app.core.rules import tier1_vlan as T1V
from app.core.rules import tier2_services as T2
from app.core.rules import tier3_bgp_acl as T3
from app.i18n_pages import MESSAGES_EN, UI_PAGES

LANGS = ("th", "en")
DEFAULT_LANG = "th"


def normalize_lang(value: Optional[str]) -> str:
    value = (value or "").strip().lower()
    return value if value in LANGS else DEFAULT_LANG


# ----------------------------------------------------------------------------- provenance

PROVENANCE_EN = {
    Provenance.RULE: "Rule-based",
    Provenance.AI: "AI-generated (Review Required)",
    Provenance.SYSTEM: "System-generated",
    Provenance.UNCONVERTED: "Unconverted",
    Provenance.NOT_NEEDED: "Not Needed",
}


def provenance_label(p: Provenance, lang: str) -> str:
    return p.value if normalize_lang(lang) == "th" else PROVENANCE_EN[p]


# ----------------------------------------------------------------------------- UI strings

UI: dict[str, dict[str, str]] = {
    "app_name": {"th": "NetMigrate", "en": "NetMigrate"},
    "app_tagline": {"th": "ระบบแปลงการตั้งค่าอุปกรณ์เครือข่ายหลายผู้ผลิต", "en": "Multi-Vendor Network Configuration Conversion"},
    # navigation — the 8 modules of proposal §2.3.1
    "nav_m1": {"th": "แปลงไฟล์เดี่ยว", "en": "Single Conversion"},
    "nav_m2": {"th": "แปลงแบบกลุ่ม", "en": "Batch Conversion"},
    "nav_m3": {"th": "ทะเบียนอุปกรณ์", "en": "Device Inventory"},
    "nav_m4": {"th": "ส่งคำสั่งไปอุปกรณ์", "en": "Deployment"},
    "nav_m5": {"th": "ภาพรวมและประวัติ", "en": "Dashboard & History"},
    "nav_m6": {"th": "ตั้งค่าและสถานะ API", "en": "Settings & API Health"},
    "nav_m7": {"th": "วิเคราะห์โทโพโลยี", "en": "Topology Analysis"},
    "nav_m8": {"th": "ตรวจความเข้ากันได้ฮาร์ดแวร์", "en": "Hardware Compatibility"},
    "menu": {"th": "เมนู", "en": "Menu"},
    # header controls
    "theme_toggle": {"th": "สลับธีมสว่าง/มืด", "en": "Toggle light/dark theme"},
    "lang_toggle": {"th": "เปลี่ยนภาษา", "en": "Change language"},
    "health_checking": {"th": "กำลังตรวจสอบ API…", "en": "Checking API…"},
    "health_ai_ready": {"th": "AI พร้อมใช้งาน", "en": "AI ready"},
    "health_rule_only": {"th": "ไม่มี API Key — โหมดกฎอย่างเดียว", "en": "No API key — rule-only mode"},
    "health_offline": {"th": "เชื่อมต่อเซิร์ฟเวอร์ไม่ได้", "en": "Server unreachable"},
    # workspace
    "page_title": {"th": "แปลงคำสั่งแบบไฟล์เดี่ยว", "en": "Single File / CLI Conversion"},
    "page_subtitle": {
        "th": "แปลงสองทิศทางระหว่าง Cisco IOS-XE และ Huawei VRP (IPv4) — ตรวจสอบก่อนแปลง แล้วเลือกโหมดที่เหมาะกับไฟล์",
        "en": "Bidirectional Cisco IOS-XE ⇄ Huawei VRP (IPv4) — pre-scan first, then pick the mode that fits your file",
    },
    "direction": {"th": "ทิศทางการแปลง", "en": "Direction"},
    "dir_c2h": {"th": "Cisco IOS-XE → Huawei VRP", "en": "Cisco IOS-XE → Huawei VRP"},
    "dir_h2c": {"th": "Huawei VRP → Cisco IOS-XE", "en": "Huawei VRP → Cisco IOS-XE"},
    "source_config": {"th": "คอนฟิกต้นทาง", "en": "Source configuration"},
    "editor_placeholder": {"th": "วางคำสั่ง CLI ที่นี่ หรืออัปโหลดไฟล์ .txt", "en": "Paste CLI commands here, or upload a .txt file"},
    "upload_txt": {"th": "อัปโหลด .txt", "en": "Upload .txt"},
    "sample_cisco": {"th": "ตัวอย่าง Cisco", "en": "Cisco sample"},
    "sample_huawei": {"th": "ตัวอย่าง Huawei", "en": "Huawei sample"},
    "clear": {"th": "ล้าง", "en": "Clear"},
    "lines": {"th": "บรรทัด", "en": "lines"},
    "btn_prescan": {"th": "ตรวจสอบก่อนแปลง", "en": "Run Pre-scan"},
    "btn_convert": {"th": "แปลง", "en": "Convert"},
    "working": {"th": "กำลังประมวลผล…", "en": "Working…"},
    "empty_input": {"th": "กรุณาวางคำสั่งหรืออัปโหลดไฟล์ก่อน", "en": "Please paste commands or upload a file first"},
    "request_failed": {"th": "คำขอไม่สำเร็จ", "en": "Request failed"},
    # modes
    "mode": {"th": "โหมดการแปลง", "en": "Conversion mode"},
    "mode_hybrid": {"th": "ผสม (Hybrid)", "en": "Hybrid"},
    "mode_rule_only": {"th": "กฎอย่างเดียว", "en": "Rule Only"},
    "mode_ai_only": {"th": "AI อย่างเดียว", "en": "AI Only"},
    "mode_hybrid_desc": {
        "th": "แปลงด้วยกฎก่อน แล้วส่งเฉพาะส่วนที่กฎแปลงไม่ได้ (ตัดข้อมูลลับแล้ว) ให้ AI",
        "en": "Rules first; only the gaps (secrets stripped) are sent to AI",
    },
    "mode_rule_only_desc": {
        "th": "แปลงด้วยกฎทั้งหมด ไม่ส่งข้อมูลออกไปข้างนอก",
        "en": "Rules only — nothing leaves this server",
    },
    "mode_ai_only_desc": {
        "th": "ส่งคำสั่งทั้งหมด (ตัดข้อมูลลับแล้ว) ให้ AI แปล",
        "en": "All commands (secrets stripped) are translated by AI",
    },
    "mode_default": {"th": "ค่าเริ่มต้น", "en": "default"},
    "mode_disabled_tip": {
        "th": "ยังไม่ได้ตั้งค่า LLM_API_KEY — ใช้ได้เฉพาะโหมดกฎอย่างเดียว",
        "en": "LLM_API_KEY is not set — only Rule Only mode is available",
    },
    # pre-scan
    "prescan_title": {"th": "ผลการตรวจสอบก่อนแปลง", "en": "Pre-scan Report"},
    "prescan_hint": {
        "th": "อ่านไฟล์หนึ่งรอบโดยยังไม่แปลงจริง เพื่อดูว่ากฎครอบคลุมกี่เปอร์เซ็นต์",
        "en": "Reads the file once without converting, to show how much the rules cover",
    },
    "coverage": {"th": "กฎครอบคลุม", "en": "Rule coverage"},
    "total_lines": {"th": "บรรทัดคำสั่งทั้งหมด", "en": "Effective lines"},
    "supported_lines": {"th": "กฎรองรับ", "en": "Supported"},
    "unsupported_lines": {"th": "กฎไม่รองรับ", "en": "Unsupported"},
    "secret_stripped": {"th": "ตัดข้อมูลลับออก", "en": "Secrets stripped"},
    "unsupported_list": {"th": "บรรทัดที่กฎไม่รองรับ", "en": "Lines the rules do not support"},
    "none": {"th": "ไม่มี", "en": "None"},
    "line_no": {"th": "บรรทัด", "en": "Line"},
    "command": {"th": "คำสั่ง", "en": "Command"},
    "reason": {"th": "เหตุผล", "en": "Reason"},
    # result
    "result_title": {"th": "ผลลัพธ์การแปลง", "en": "Conversion Result"},
    "result_empty": {"th": "ยังไม่มีผลลัพธ์ — กด \"แปลง\" เพื่อเริ่ม", "en": "No result yet — press \"Convert\" to start"},
    "requested_mode": {"th": "โหมดที่เลือก", "en": "Requested mode"},
    "effective_mode": {"th": "โหมดที่ใช้จริง", "en": "Effective mode"},
    "copy": {"th": "คัดลอก", "en": "Copy"},
    "copied": {"th": "คัดลอกแล้ว", "en": "Copied"},
    "download_txt": {"th": "ดาวน์โหลด .txt", "en": "Download .txt"},
    "show_labels": {"th": "แสดงป้ายที่มา", "en": "Show labels"},
    "warnings": {"th": "คำเตือน", "en": "Warnings"},
    "notices": {"th": "ประกาศจากระบบ", "en": "System notices"},
    "legend": {"th": "ความหมายของป้าย", "en": "Label legend"},
    "ai_sent": {"th": "บรรทัดที่ส่งให้ AI (ตัดข้อมูลลับแล้ว)", "en": "Lines sent to AI (secrets stripped)"},
    # selective AI
    "selective_title": {"th": "เลือกบรรทัดที่แปลงไม่ได้เพื่อส่งให้ AI", "en": "Pick unconverted lines to send to AI"},
    "selective_hint": {
        "th": "ระบบจะไม่ส่งเองในโหมดกฎอย่างเดียว — เลือกเฉพาะบรรทัดที่ต้องการ (ข้อมูลลับถูกตัดออกเสมอ)",
        "en": "Rule Only never sends on its own — tick only the lines you want (secrets are always stripped)",
    },
    "select_all": {"th": "เลือกทั้งหมด", "en": "Select all"},
    "send_selected": {"th": "ส่งบรรทัดที่เลือกให้ AI", "en": "Send Selected to AI"},
    "selective_need_key": {
        "th": "ต้องตั้งค่า LLM_API_KEY ก่อนจึงจะส่งให้ AI ได้",
        "en": "Set LLM_API_KEY to enable sending to AI",
    },
    "footer": {
        "th": "ทุกบรรทัดมีป้ายบอกที่มา • บรรทัดจาก AI ต้องตรวจสอบก่อนใช้ • ไม่มีการส่งรหัสผ่านออกนอกระบบ",
        "en": "Every line carries a provenance label • AI lines need review • Credentials never leave the system",
    },
}


UI.update(UI_PAGES)


def t(key: str, lang: str) -> str:
    entry = UI.get(key)
    if entry is None:
        if key.startswith("prov_") and key[5:] in Provenance.__members__:
            return provenance_label(Provenance[key[5:]], lang)
        return key
    return entry[normalize_lang(lang)]


def ui_dict(lang: str) -> dict[str, str]:
    """All UI strings for one language (handed to the browser for dynamic rendering)."""
    lang = normalize_lang(lang)
    out = {k: v[lang] for k, v in UI.items()}
    for p in Provenance:
        out[f"prov_{p.name}"] = provenance_label(p, lang)
    return out


# ----------------------------------------------------------------------------- messages (Thai -> English)

_EXACT: dict[str, str] = {
    # reasons
    B.REASON_NO_RULE: "No rule supports this command yet",
    B.REASON_ORPHAN: "Sub-command without a supported parent block",
    B.REASON_BAD_VALUE: "Invalid value in this command",
    B.REASON_UNKNOWN_IF: "Unknown interface name in this command",
    T1I.REASON_UNKNOWN_IF_TYPE: "No rule supports this interface type yet",
    T1I.REASON_NO_IP: "The target has no IP address on the interface by default",
    T1V.REASON_BAD_VLAN: "Invalid VLAN ID (must be 1–4094)",
    T1V.REASON_DOT1Q: "Huawei supports 802.1Q only, so no encapsulation command is needed",
    T2.REASON_SERVER_NOT_IPV4: "Only servers given as an IPv4 address are supported",
    T2.REASON_STELNET: "Cisco has no separate SSH service switch — SSH runs once an RSA key exists "
                       "(crypto key generate rsa), which must be created on the target device",
    T2.REASON_TELNET_SERVER: "Cisco already serves Telnet on VTY lines; it is controlled by transport input",
    T3.REASON_BGP_SYNC: "BGP synchronization is already disabled by default on the target",
    T3.REASON_BGP_AUTO_SUMMARY: "Huawei already disables BGP auto-summary by default",
    T3.REASON_ACL_REMARK: "ACL remarks have no direct equivalent, kept as a comment (no filtering effect)",
    T3.REASON_ACL_STEP: "Rule ids are renumbered automatically and Cisco has no step command",
    T3.REASON_ACL_KIND_CONFLICT: "This ACL name is used for ACLs of different kinds (basic/advanced)",
    # warnings
    R.WARN_STATIC_DEFAULT_PREFERENCE: "Route preference not stated — Cisco default AD=1 but Huawei Preference=60. "
                                      "The system does not guess; verify route selection is unchanged",
    R.WARN_DEFAULT_GATEWAY: "Cisco uses ip default-gateway when IP routing is off; Huawei has no such command, so it "
                            "is written as a static route to 0.0.0.0 0.0.0.0 (default Preference 60). "
                            "Verify it suits the target device's role",
    R.WARN_RIP_NO_VERSION: "version 2 not stated — only RIPv2 is supported and neither vendor defaults to RIPv2. "
                           "The system does not guess; verify the RIP version",
    R.WARN_BGP_PEER_ENABLE: "Cisco activates BGP neighbors automatically, Huawei requires peer <ip> enable under "
                            "ipv4-family unicast. Without it the session comes up but silently exchanges no routes, "
                            "so the system adds it",
    R.WARN_ACL_NUMBER_ASSIGNED: "The ACL number was assigned by ACL type (the source number is not copied) — it may "
                                "collide with an existing ACL on the target; check before use",
    R.WARN_HUAWEI_ACL_NAME: "Huawei ACL names must start with a letter and be at most 32 characters; please check",
    R.WARN_STELNET: "Huawei needs stelnet server enable for SSH — the system does not add it (it is written as a "
                    "comment advisory). You must also create an RSA key (rsa local-key-pair create) and configure "
                    "SSH users on the target device (user accounts are never converted)",
    R.WARN_CISCO_SSH: "Cisco needs ip domain name and an RSA key (crypto key generate rsa) before SSH works. "
                      "The system creates no keys and converts no user accounts; configure them on the target device",
    R.WARN_HUAWEI_VTY_RANGE: "Many Huawei models support VTY 0–4 (some up to 0–14); check the VTY range on the target",
    R.WARN_TWO_TUPLE_PORTS: "2-tuple interface numbering (e.g., 0/1) was preserved from the source — if the target "
                            "Huawei device uses 3-tuple port numbering (e.g., S5700, S6700, AR series), adjust to "
                            "0/0/1 before applying.",
    # notices
    engine.NOTICE_AI_UNAVAILABLE: "The AI service is unavailable, so the file was converted in rule-only mode. "
                                  "Unconverted lines keep the \"Unconverted\" label and can be sent to AI later",
    engine.NOTICE_AI_FAILED: "The AI call failed or returned an unusable answer, so rule-only output is shown. "
                             "Unconverted lines keep the \"Unconverted\" label",
    engine.NOTICE_AI_REVIEW: "Some lines were translated by AI and are labelled \"AI-generated (Review Required)\". "
                             "Verify them against vendor documentation before use (AI self-reported confidence is never used)",
    engine.NOTICE_HYBRID_NOTHING_TO_SEND: "The rules converted every line that may be sent to AI, so AI was not called",
    engine.NOTICE_NO_SELECTION: "None of the selected lines is labelled \"Unconverted\", so nothing was sent to AI",
}
_EXACT.update(MESSAGES_EN)

# Feature names / explanations used inside reason_out_of_scope / reason_not_supported / reason_intentional.
_PHRASES: dict[str, str] = {
    "Interface ประเภท Tunnel": "Tunnel interfaces",
    "Interface ประเภท ATM": "ATM interfaces",
    "OSPF หลาย Process (Multi-Process)": "multi-process OSPF",
    "ตัวเลือก no-summary": "the no-summary option",
    "การยืนยันตัวตน OSPF (Authentication)": "OSPF authentication",
    "คำสั่งปรับจังหวะเวลา OSPF (Timers)": "OSPF timers",
    "รายการ VLAN แบบ all/none/add/remove/except": "VLAN lists using all/none/add/remove/except",
    "ชื่อเส้นทาง (name) จะหายไปโดยไม่มีอะไรเตือน": "the route name would be silently lost",
    "คำอธิบายเส้นทาง (description) จะหายไปโดยไม่มีอะไรเตือน": "the route description would be silently lost",
    "คำสั่ง vlan หลายหมายเลขที่ตามด้วย name จะตั้งชื่อเดียวกันให้ทุก VLAN ซึ่งแปลงตรง ๆ ไม่ได้โดยไม่เปลี่ยนความหมาย":
        "a multi-VLAN command followed by name gives every VLAN the same name, which cannot be converted "
        "without changing its meaning",
    'ระบบเก็บรายการ VLAN เป็นหมายเลขที่ระบุชัดทีละตัว จึงไม่มีที่ให้เก็บคำว่า "ทั้งหมด"':
        'VLAN lists are stored as explicit IDs, so there is no way to represent "all"',
    "Cisco ไม่มีพอร์ตแบบ hybrid ที่ความหมายตรงกัน": "Cisco has no hybrid port type with the same meaning",
    "ต้นทางไม่ได้ระบุค่าตัววัด (metric) — ค่าเริ่มต้นตอนดึงเส้นทางจากโปรโตคอลอื่นของสองยี่ห้อไม่เท่ากัน "
    "ระบบไม่เดาค่าให้ กรุณาระบุ metric ในคำสั่งต้นทางแล้วแปลงใหม่":
        "no metric stated — the vendors' default redistribution metrics differ. The system does not guess; "
        "add a metric to the source command and convert again",
    "การดึงเส้นทางจากโปรโตคอลนี้ (รองรับเฉพาะ static, connected/direct, OSPF, RIP)":
        "redistributing from this protocol (only static, connected/direct, OSPF, RIP are supported)",
    "RIP มากกว่าหนึ่ง Process (Multi-Process)": "more than one RIP process",
    "การยืนยันตัวตนด้วยรหัสผ่านของ line — ระบบไม่แปลงรหัสผ่าน กรุณาตั้งค่าการยืนยันตัวตนเองบนอุปกรณ์ปลายทาง":
        "password authentication on lines — passwords are never converted; configure authentication on the target",
    "VTY ที่ไม่มีการยืนยันตัวตนไม่ปลอดภัย กรุณาตั้งค่าเองบนอุปกรณ์ปลายทาง":
        "VTY without authentication is insecure; configure it on the target device",
    "การยืนยันตัวตน RIP (Authentication)": "RIP authentication",
    "คำสั่งปรับจังหวะเวลา RIP (Timers)": "RIP timers",
    "การนำ ACL ไปใช้กับ Policy อื่น (ACL บน VTY)": "ACL used by other policies (ACL on VTY)",
    "RIPv1 (ระบบรองรับเฉพาะ RIPv2)": "RIPv1 (only RIPv2 is supported)",
    "การกรองเส้นทาง BGP (Route Filtering)": "BGP route filtering",
    "Address Family อื่นนอกจาก IPv4 Unicast": "address families other than IPv4 unicast",
    "BGP มากกว่าหนึ่ง AS (ระบบรองรับ AS เดียว)": "BGP with more than one AS (single AS only)",
    "ACL ชั้นที่ 2 หรือ ACL ที่ไม่ใช่ IPv4 (Layer 2 / non-IPv4 ACL)": "Layer 2 / non-IPv4 ACLs",
    "match-order auto (ลำดับการตรวจกฎอัตโนมัติ)": "match-order auto",
    "ช่วงหมายเลข ACL นี้ของ Huawei ไม่มีช่วงหมายเลขที่ตรงกันฝั่ง Cisco "
    "(Huawei 2800–2999, 3800–3999 และ 2099 อยู่นอกช่วงของ Cisco ซึ่งแคบกว่า) — เป็นข้อกำหนดของผู้ผลิต":
        "this Huawei ACL number range has no Cisco equivalent (Huawei 2800–2999, 3800–3999 and 2099 fall outside "
        "Cisco's narrower ranges) — a vendor constraint",
    "ACL นี้มีบางกฎที่แปลงไม่ได้ จึงไม่แปลงทั้งชุด เพราะการตัดกฎบางข้อออกจะทำให้ผลการกรองเปลี่ยนโดยไม่มีอะไรเตือน":
        "some rules of this ACL cannot be converted, so the whole ACL is left unconverted — dropping entries "
        "would silently change what it filters",
    "ACL ที่ผูกไว้ไม่ได้ถูกแปลง จึงไม่แปลงคำสั่งผูกนี้ เพื่อไม่ให้ผูกกับ ACL ที่ไม่มีอยู่หรือไม่ครบ":
        "the bound ACL was not converted, so this binding is not converted either (it would reference a "
        "missing or incomplete ACL)",
}

_PHRASES.update({
    engine.AI_FAILURE_LABELS["auth"]: "invalid API key or no permission (auth error)",
    engine.AI_FAILURE_LABELS["model"]: "model name not found or not supported (invalid model name)",
    engine.AI_FAILURE_LABELS["rate_limit"]: "quota exceeded or too many requests (rate limit)",
    engine.AI_FAILURE_LABELS["timeout"]: "no answer within the time limit (timeout)",
    engine.AI_FAILURE_LABELS["network"]: "cannot connect to the AI service (network error)",
    engine.AI_FAILURE_LABELS["server"]: "the AI provider had an internal error (server error)",
    engine.AI_FAILURE_LABELS["bad_request"]: "the provider rejected the request (bad request)",
    engine.AI_FAILURE_LABELS["bad_answer"]: "the AI answer was not in a usable format (unusable answer)",
})

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile("^" + re.escape(engine.NOTICE_AI_FAILED_REASON_PREFIX.strip()) + r" (?P<x>.+?) — (?P<y>.*)$", re.S),
     "AI failure reason: {x} — {y}"),
    (re.compile(r"^อยู่นอกขอบเขตของระบบ \((?P<x>.+)\) — ต้องตรวจสอบและตั้งค่าเอง$"),
     "Out of scope ({x}) — review and configure manually"),
    (re.compile(r"^ยังไม่รองรับ: (?P<x>.+) — ต้องตรวจสอบและตั้งค่าเอง$"),
     "Not supported: {x} — review and configure manually"),
    (re.compile(r"^ระบบตั้งใจไม่แปลงคำสั่งนี้: (?P<x>.+)$", re.S), "Intentionally not converted: {x}"),
    (re.compile(r"^VLAN (?P<x>\d+): ชื่อมีช่องว่าง ซึ่ง Cisco อาจไม่รับ กรุณาตรวจสอบ$"),
     "VLAN {x}: the name contains spaces, which Cisco may reject; please check"),
    (re.compile(r"^Cisco มี RIP ได้ Process เดียวและไม่มีหมายเลข — หมายเลข Process (?P<x>\d+) ของ Huawei จะไม่ถูกใช้$"),
     "Cisco has a single, unnumbered RIP process — Huawei process number {x} is not used"),
    (re.compile(r"^(?P<x>\S+): หมายเลขสล็อต (?P<y>\S+) ไม่ใช่ 0 — ระบบไม่แปลงหมายเลขพอร์ต กรุณาตรวจสอบว่าพอร์ตนี้มีอยู่จริงบนอุปกรณ์ปลายทาง$"),
     "{x}: slot number {y} is not 0 — port numbers are never translated; verify this port exists on the target"),
    (re.compile(r"^(?P<x>\S+): ต้นทางไม่ได้ระบุโปรโตคอลของพอร์ต Serial — .*$"),
     "{x}: serial link protocol not stated — Cisco defaults to HDLC, Huawei to PPP. The system does not guess; "
     "cross-vendor links must use PPP on both ends"),
    (re.compile(r"^(?P<x>\S+): HDLC ของ Cisco กับ HDLC ของ Huawei ทำงานร่วมกันไม่ได้ .*$"),
     "{x}: Cisco HDLC and Huawei HDLC are not interoperable — cross-vendor links must use PPP on both ends"),
    (re.compile(r"^(?P<x>\S+): พอร์ต trunk ไม่ได้ระบุรายการ VLAN — .*$"),
     "{x}: trunk port lists no VLANs — Cisco allows all VLANs but Huawei only VLAN 1. "
     "The system does not guess; list the VLANs explicitly"),
    (re.compile(r"^Cisco ปฏิเสธแพ็กเก็ตที่ไม่ตรงกฎใดเลย \(implicit deny\) .*$"),
     "Cisco denies packets matching no rule (implicit deny) but a Huawei traffic-filter forwards them — "
     "add a final deny rule to keep the original behaviour"),
    (re.compile(r"^traffic-filter ของ Huawei ปล่อยแพ็กเก็ตที่ไม่ตรงกฎใดเลยผ่าน .*$"),
     "A Huawei traffic-filter forwards packets matching no rule but Cisco denies them (implicit deny) — "
     "add a final permit to keep the original behaviour"),
    (re.compile(r"^ไม่รู้จักชื่อพอร์ต (?P<x>\S+) — กรุณาใช้หมายเลขพอร์ต$"),
     "Unknown port name {x} — please use the port number"),
]


def _one(part: str) -> str:
    part = part.strip()
    if part in _EXACT:
        return _EXACT[part]
    for pattern, template in _PATTERNS:
        m = pattern.match(part)
        if m:
            return template.format(**{k: _PHRASES.get(v, v) for k, v in m.groupdict().items()})
    return _PHRASES.get(part, part)


def translate_message(message: Optional[str], lang: str) -> str:
    """English for a Thai engine message when lang == 'en'; unknown text is returned as-is."""
    if not message:
        return message or ""
    if normalize_lang(lang) == "th":
        return message
    return " | ".join(_one(p) for p in message.split(" | "))
