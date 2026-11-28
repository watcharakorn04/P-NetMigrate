"""Tier 1 — System-level rules (proposal §2.3.1 item 1.3.1).

  hostname <name>                         <-> sysname <name>          (D)
  ip domain-name <d> / ip domain name <d> <-> dns domain <d>          (D)
  configure terminal (conf t)             <-> system-view (sys)       (D, rendered first)
  end                                     <-> return                  (D, file assembly)
  exit (top level, closes no view)         -> "ไม่ต้องใช้คำสั่งนี้" (the file already ends
                                              with end/return); `exit` that closes a view is
                                              a child rule (base.view_exit): exit <-> quit
  write [memory] / copy run start         <-> save force / save       (T, rendered after
                                              end/return, with a warning)
  no ip domain-lookup                      -> "ไม่ต้องใช้คำสั่งนี้" (Huawei default)
  enable (bare, not enable secret/password) -> "ไม่ต้องใช้คำสั่งนี้" (no separate exec modes)
  service password-encryption              -> "ไม่ต้องใช้คำสั่งนี้" (cipher encrypts by default)
  logging synchronous (top level or inside  -> "ไม่ต้องใช้คำสั่งนี้" (VRP does not interrupt
    any line block, even an unclaimed one)      typed CLI input with logs by default)
  "!" comment                             <-> "#" comment             (D, comment prefix)

Mode-navigation and save lines are not configuration intent: they are recorded only in
`DeviceConfigIR.field_lines` (excluded from IR round-trip comparison).
"""

from __future__ import annotations

import re
from typing import Callable, Optional

from app.core.ir import SyntaxCategory, Vendor
from app.core.rules.base import REASON_NO_RULE, Block, BlockHandler, Line, ParseContext

D, T = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM

REASON_DOMAIN_LOOKUP = (
    "Huawei VRP ไม่เปิดการแปลงชื่อผ่าน DNS (domain lookup) เป็นค่าเริ่มต้นอยู่แล้ว จึงไม่ต้องสั่งปิด"
)
REASON_TOP_LEVEL_EXIT = "ไฟล์ผลลัพธ์ปิดท้ายด้วยคำสั่งออกจากโหมดตั้งค่า (end/return) ให้อยู่แล้ว"
REASON_LOGGING_SYNCHRONOUS = (
    "Huawei VRP ไม่ขัดจังหวะคำสั่งที่กำลังพิมพ์ด้วยข้อความ log บน console/VTY เป็นค่าเริ่มต้นอยู่แล้ว"
)
REASON_ENABLE = (
    "Huawei VRP ไม่มีโหมด user/privileged exec แยกกัน สิทธิ์ควบคุมด้วย user privilege level"
)
REASON_SERVICE_PASSWORD_ENCRYPTION = (
    "Huawei VRP เข้ารหัสรหัสผ่านที่ตั้งด้วย cipher ให้อัตโนมัติเป็นค่าเริ่มต้นอยู่แล้ว"
)

# Cisco lines that are redundant on Huawei wherever they appear: at top level and inside
# any block (also blocks no rule claims, e.g. `line con 0`), so hybrid never sends them to AI.
CISCO_NOT_NEEDED_ANYWHERE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^logging\s+synchronous(\s|$)", re.IGNORECASE), REASON_LOGGING_SYNCHRONOUS),
]


def cisco_not_needed_reason(body: str) -> Optional[str]:
    """Reason when a Cisco line is "ไม่ต้องใช้คำสั่งนี้" wherever it appears, else None."""
    for pattern, reason in CISCO_NOT_NEEDED_ANYWHERE:
        if pattern.match(body):
            return reason
    return None

_CISCO_COMMENT = re.compile(r"^!+\s*(.*)$")
_HUAWEI_COMMENT = re.compile(r"^[#!]+\s*(.*)$")  # VRP output also uses "!Software Version ..."


def comment_body(body: str, vendor: Vendor) -> Optional[str]:
    """Text of a comment line ("" for a bare separator); None if the line is not a comment."""
    m = (_CISCO_COMMENT if vendor is Vendor.CISCO_IOS_XE else _HUAWEI_COMMENT).match(body)
    return m[1].strip() if m else None


def _abbrev(word: str, full: str, minimum: int) -> bool:
    word = word.lower()
    return len(word) >= minimum and full.startswith(word)


def is_cisco_configure_terminal(body: str) -> bool:
    """`configure terminal` and its abbreviations (`conf t`, `config term`, ...)."""
    words = body.split()
    return len(words) == 2 and _abbrev(words[0], "configure", 4) and _abbrev(words[1], "terminal", 1)


def is_huawei_system_view(body: str) -> bool:
    """`system-view` and its abbreviations (`sys`, `system`, ...)."""
    words = body.split()
    return len(words) == 1 and _abbrev(words[0], "system-view", 3)


# A line rule: (predicate on the body, action(ctx, line) -> category or None for not-needed).
_LineRule = tuple[Callable[[str], bool], Callable[[ParseContext, Line], Optional[SyntaxCategory]]]


def _regex(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern, re.IGNORECASE)
    return lambda body: compiled.match(body) is not None


def _capture(pattern: str, field: str) -> _LineRule:
    """hostname / domain: store the single argument on the IR."""
    compiled = re.compile(pattern, re.IGNORECASE)

    def action(ctx: ParseContext, line: Line) -> SyntaxCategory:
        setattr(ctx.ir, field, compiled.match(line.body)[1])
        ctx.ir.field_lines[field] = line.no
        return D

    return (lambda body: compiled.match(body) is not None), action


def _mark(field: str, category: SyntaxCategory) -> Callable[[ParseContext, Line], SyntaxCategory]:
    def action(ctx: ParseContext, line: Line) -> SyntaxCategory:
        ctx.ir.field_lines[field] = line.no
        return category

    return action


def _plain(category: SyntaxCategory) -> Callable[[ParseContext, Line], SyntaxCategory]:
    return lambda ctx, line: category


def _not_needed(reason: str) -> Callable[[ParseContext, Line], None]:
    def action(ctx: ParseContext, line: Line) -> None:
        ctx.not_needed(line, reason, ctx.ir.notes)

    return action


def _system_handler(name: str, rules: list[_LineRule]) -> BlockHandler:
    def handler(block: Block, ctx: ParseContext) -> bool:
        line = block.header
        for matches, action in rules:
            if matches(line.body):
                break
        else:
            return False
        category = action(ctx, line)
        if category is not None:
            ctx.rule(line, category)
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
        return True

    handler.__name__ = name
    return handler


cisco_system = _system_handler(
    "cisco_system",
    [
        _capture(r"^hostname\s+(\S+)$", "hostname"),
        _capture(r"^ip\s+domain[-\s]name\s+(\S+)$", "domain_name"),
        (is_cisco_configure_terminal, _mark("config_mode", D)),
        (_regex(r"^end$"), _plain(D)),
        (_regex(r"^exit$"), _not_needed(REASON_TOP_LEVEL_EXIT)),
        (_regex(r"^no\s+ip\s+domain[-\s]lookup$"), _not_needed(REASON_DOMAIN_LOOKUP)),
        (_regex(r"^enable$"), _not_needed(REASON_ENABLE)),
        (_regex(r"^service\s+password-encryption$"), _not_needed(REASON_SERVICE_PASSWORD_ENCRYPTION)),
        (lambda body: cisco_not_needed_reason(body) is not None,
         lambda ctx, line: ctx.not_needed(line, cisco_not_needed_reason(line.body), ctx.ir.notes)),
        (_regex(r"^(wr(ite)?(\s+mem(ory)?)?|copy\s+run(ning-config)?\s+start(up-config)?)$"), _mark("save", T)),
    ],
)
huawei_system = _system_handler(
    "huawei_system",
    [
        _capture(r"^sysname\s+(\S+)$", "hostname"),
        _capture(r"^dns\s+domain\s+(\S+)$", "domain_name"),
        (is_huawei_system_view, _mark("config_mode", D)),
        (_regex(r"^return$"), _plain(D)),
        (_regex(r"^quit$"), _not_needed(REASON_TOP_LEVEL_EXIT)),
        (_regex(r"^save(\s+force)?$"), _mark("save", T)),
    ],
)

CISCO_HANDLERS: list[BlockHandler] = [cisco_system]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_system]
