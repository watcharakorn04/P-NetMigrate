"""Tier 1 — VLAN & switchport rules (proposal §2.3.1 item 1.3.2).

  vlan <id> + name <n>                    <-> vlan <id> + description <n>        (D)
  vlan 10,20,30-32 (no name)              <-> vlan batch 10 20 30 to 32          (T, expanded per VLAN)
  switchport mode access|trunk            <-> port link-type access|trunk        (D)
  switchport access vlan <id>             <-> port default vlan <id>             (D)
  switchport trunk allowed vlan 10,30-35  <-> port trunk allow-pass vlan 10 30 to 35  (T)
  spanning-tree portfast [edge]           <-> stp edged-port enable              (D)
  switchport trunk encapsulation dot1q     -> "ไม่ต้องใช้คำสั่งนี้" (Huawei is 802.1Q only)

Intentionally unconverted (§2.3.2 item 7): `vlan 10,20` followed by `name X`,
`port trunk allow-pass vlan all`, `port link-type hybrid`.
"""

from __future__ import annotations

import re
from typing import Optional

from app.core.ir import InterfaceIR, SyntaxCategory, VlanIR
from app.core.rules.base import (
    CISCO_EXIT_RULES,
    HUAWEI_EXIT_RULES,
    REASON_NO_RULE,
    Block,
    BlockHandler,
    Line,
    ParseContext,
    apply_child_rules,
    compile_rules,
    reason_intentional,
    reason_not_supported,
)

D, T = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM
MIN_VLAN, MAX_VLAN = 1, 4094

REASON_BAD_VLAN = "หมายเลข VLAN ไม่ถูกต้อง (ต้องอยู่ระหว่าง 1–4094)"
REASON_VLAN_LIST_WITH_NAME = reason_intentional(
    "คำสั่ง vlan หลายหมายเลขที่ตามด้วย name จะตั้งชื่อเดียวกันให้ทุก VLAN ซึ่งแปลงตรง ๆ ไม่ได้โดยไม่เปลี่ยนความหมาย"
)
REASON_ALLOW_ALL = reason_intentional(
    'ระบบเก็บรายการ VLAN เป็นหมายเลขที่ระบุชัดทีละตัว จึงไม่มีที่ให้เก็บคำว่า "ทั้งหมด"'
)
REASON_HYBRID = reason_intentional("Cisco ไม่มีพอร์ตแบบ hybrid ที่ความหมายตรงกัน")
REASON_DOT1Q = "Huawei รองรับเฉพาะ 802.1Q อยู่แล้ว จึงไม่ต้องกำหนด encapsulation"


# ----------------------------------------------------------------------------- VLAN list syntax


def _valid(ids: list[int]) -> Optional[list[int]]:
    if not ids or any(not MIN_VLAN <= i <= MAX_VLAN for i in ids):
        return None
    return sorted(set(ids))


def parse_cisco_vlan_list(text: str) -> Optional[list[int]]:
    """'10,20,30-35' -> [10, 20, 30, ..., 35]; None if malformed."""
    ids: list[int] = []
    for token in text.split(","):
        m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+)\s*)?", token)
        if not m:
            return None
        lo, hi = int(m[1]), int(m[2] or m[1])
        if hi < lo:
            return None
        ids.extend(range(lo, hi + 1))
    return _valid(ids)


def parse_huawei_vlan_list(text: str) -> Optional[list[int]]:
    """'10 20 30 to 35' -> [10, 20, 30, ..., 35]; None if malformed."""
    tokens = text.split()
    ids: list[int] = []
    i = 0
    while i < len(tokens):
        if not tokens[i].isdigit():
            return None
        lo = int(tokens[i])
        if i + 2 < len(tokens) and tokens[i + 1].lower() == "to" and tokens[i + 2].isdigit():
            hi = int(tokens[i + 2])
            if hi < lo:
                return None
            ids.extend(range(lo, hi + 1))
            i += 3
        else:
            ids.append(lo)
            i += 1
    return _valid(ids)


def _runs(ids: list[int]) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    for i in sorted(set(ids)):
        if runs and i == runs[-1][1] + 1:
            runs[-1] = (runs[-1][0], i)
        else:
            runs.append((i, i))
    return runs


def _format(ids: list[int], sep: str, range_fmt: str) -> str:
    parts: list[str] = []
    for lo, hi in _runs(ids):
        if hi - lo >= 2:
            parts.append(range_fmt.format(lo=lo, hi=hi))
        else:
            parts.extend(str(i) for i in range(lo, hi + 1))
    return sep.join(parts)


def format_cisco_vlan_list(ids: list[int]) -> str:
    return _format(ids, ",", "{lo}-{hi}")


def format_huawei_vlan_list(ids: list[int]) -> str:
    return _format(ids, " ", "{lo} to {hi}")


# ----------------------------------------------------------------------------- VLAN blocks


def _vlan(ctx: ParseContext, vlan_id: int, line: Line) -> VlanIR:
    for v in ctx.ir.vlans:
        if v.vlan_id == vlan_id:
            break
    else:
        v = VlanIR(vlan_id=vlan_id)
        ctx.ir.vlans.append(v)
    v.source_lines.append(line.no)
    return v


def _set_vlan_name(m: re.Match, line: Line, ctx: ParseContext, vlan: VlanIR) -> None:
    vlan.name = m[m.lastindex]
    vlan.field_lines["name"] = line.no
    ctx.rule(line, D)


_CISCO_VLAN = re.compile(r"^vlan\s+([\d,\-\s]+)$", re.IGNORECASE)
_CISCO_VLAN_CHILD = compile_rules([(r"^name\s+(.+)$", _set_vlan_name)]) + CISCO_EXIT_RULES
_HUAWEI_VLAN = re.compile(r"^vlan\s+(\d+)$", re.IGNORECASE)
_HUAWEI_VLAN_BATCH = re.compile(r"^vlan\s+batch\s+(.+)$", re.IGNORECASE)
_HUAWEI_VLAN_CHILD = compile_rules([(r"^(description|name)\s+(.+)$", _set_vlan_name)]) + HUAWEI_EXIT_RULES


def cisco_vlan(block: Block, ctx: ParseContext) -> bool:
    m = _CISCO_VLAN.match(block.header.body)
    if not m:
        return False
    ids = parse_cisco_vlan_list(m[1])
    if ids is None:
        ctx.unconverted_block(block, REASON_BAD_VLAN, ctx.ir.notes)
        return True
    is_list = not m[1].strip().isdigit()
    if is_list and any(re.match(r"^name\b", c.header.body, re.IGNORECASE) for c in block.children):
        ctx.unconverted_block(block, REASON_VLAN_LIST_WITH_NAME, ctx.ir.notes)
        return True
    vlans = [_vlan(ctx, i, block.header) for i in ids]
    ctx.rule(block.header, T if is_list else D)
    if is_list:
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
    else:
        apply_child_rules(block, ctx, _CISCO_VLAN_CHILD, vlans[0], vlans[0].notes)
    return True


def huawei_vlan(block: Block, ctx: ParseContext) -> bool:
    if m := _HUAWEI_VLAN_BATCH.match(block.header.body):
        ids = parse_huawei_vlan_list(m[1])
        if ids is None:
            ctx.unconverted_block(block, REASON_BAD_VLAN, ctx.ir.notes)
            return True
        for i in ids:
            _vlan(ctx, i, block.header)
        ctx.rule(block.header, T)
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
        return True
    if m := _HUAWEI_VLAN.match(block.header.body):
        ids = _valid([int(m[1])])
        if ids is None:
            ctx.unconverted_block(block, REASON_BAD_VLAN, ctx.ir.notes)
            return True
        vlan = _vlan(ctx, ids[0], block.header)
        ctx.rule(block.header, D)
        apply_child_rules(block, ctx, _HUAWEI_VLAN_CHILD, vlan, vlan.notes)
        return True
    return False


# ----------------------------------------------------------------------------- switchport (interface children)


def _set(iface: InterfaceIR, attr: str, value, line: Line) -> None:
    setattr(iface, attr, value)
    iface.field_lines[attr] = line.no


def _mode(m, line, ctx, iface):
    _set(iface, "port_mode", m[1].lower(), line)
    ctx.rule(line, D)


def _access_vlan(m, line, ctx, iface):
    ids = _valid([int(m[1])])
    if ids is None:
        ctx.unconverted(line, REASON_BAD_VLAN, iface.notes)
        return
    _set(iface, "access_vlan", ids[0], line)
    ctx.rule(line, D)


def _trunk_list(parser, accumulate: bool):
    def fn(m, line, ctx, iface):
        ids = parser(m[1])
        if ids is None:
            ctx.unconverted(line, REASON_BAD_VLAN, iface.notes)
            return
        if accumulate and iface.trunk_allowed_vlans:  # Huawei allow-pass lines add up
            ids = sorted(set(iface.trunk_allowed_vlans) | set(ids))
        _set(iface, "trunk_allowed_vlans", ids, line)
        ctx.rule(line, T)

    return fn


def _stp_edge(m, line, ctx, iface):
    _set(iface, "stp_edge", True, line)
    ctx.rule(line, D)


def _not_needed_dot1q(m, line, ctx, iface):
    ctx.not_needed(line, REASON_DOT1Q, iface.notes)


def _unconverted(reason: str):
    def fn(m, line, ctx, iface):
        ctx.unconverted(line, reason, iface.notes)

    return fn


CISCO_SWITCHPORT_RULES = compile_rules(
    [
        (r"^switchport\s+mode\s+(access|trunk)$", _mode),
        (r"^switchport\s+access\s+vlan\s+(\d+)$", _access_vlan),
        (r"^switchport\s+trunk\s+allowed\s+vlan\s+([\d,\-]+)$", _trunk_list(parse_cisco_vlan_list, False)),
        (r"^switchport\s+trunk\s+allowed\s+vlan\s+(all|none|add|remove|except)\b",
         _unconverted(reason_not_supported("รายการ VLAN แบบ all/none/add/remove/except"))),
        (r"^switchport\s+trunk\s+encapsulation\s+dot1q$", _not_needed_dot1q),
        (r"^spanning-tree\s+portfast(\s+edge)?$", _stp_edge),
    ]
)

HUAWEI_SWITCHPORT_RULES = compile_rules(
    [
        (r"^port\s+link-type\s+(access|trunk)$", _mode),
        (r"^port\s+link-type\s+hybrid$", _unconverted(REASON_HYBRID)),
        (r"^port\s+default\s+vlan\s+(\d+)$", _access_vlan),
        (r"^port\s+trunk\s+allow-pass\s+vlan\s+all$", _unconverted(REASON_ALLOW_ALL)),
        (r"^port\s+trunk\s+allow-pass\s+vlan\s+((?:\d+|to|\s)+)$", _trunk_list(parse_huawei_vlan_list, True)),
        (r"^stp\s+edged-port\s+enable$", _stp_edge),
    ]
)

CISCO_HANDLERS: list[BlockHandler] = [cisco_vlan]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_vlan]
