"""Tier 1 — Interface & Serial rules (proposal §2.3.1 item 1.3.3).

  interface <Type><number>      type name mapped (D); number kept verbatim (§2.3.2 item 4)
  description <text>            <-> description <text>              (D)
  ip address <ip> <mask>        <-> ip address <ip> <mask|len>      (D; T when a prefix length
                                                                     is normalised to a mask)
  shutdown / no shutdown        <-> shutdown / undo shutdown        (D; unset if omitted)
  encapsulation ppp|hdlc        <-> link-protocol ppp|hdlc          (D; renderer warns on HDLC)
  no ip address                  -> "ไม่ต้องใช้คำสั่งนี้" (target default is no address)

The interface block also accepts switchport rules (tier1_vlan) and interface-level OSPF
rules (tier1_routing). Tunnel/ATM interfaces are out of scope; Clock Rate / Frame Relay are
"not supported" (§2.3.2 item 3) — all kept as unconverted comments.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Interface
from typing import Optional

from app.core.ir import InterfaceIR, InterfaceRef, SyntaxCategory, Vendor
from app.core.rules import interface_names
from app.core.rules.base import (
    REASON_NO_RULE,
    Block,
    BlockHandler,
    ChildRule,
    Line,
    ParseContext,
    apply_child_rules,
    compile_rules,
    reason_out_of_scope,
    reason_not_supported,
)
from app.core.rules.tier1_routing import (
    CISCO_OSPF_INTERFACE_RULES,
    HUAWEI_OSPF_INTERFACE_RULES,
    REASON_BAD_VALUE,
    parse_mask,
)
from app.core.rules.tier1_vlan import CISCO_SWITCHPORT_RULES, HUAWEI_SWITCHPORT_RULES

D, T = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM

REASON_UNKNOWN_IF_TYPE = "ยังไม่มีกฎรองรับ Interface ประเภทนี้"
REASON_NO_IP = "อุปกรณ์ปลายทางไม่มี IP address บน Interface อยู่แล้วเป็นค่าเริ่มต้น"

_INTERFACE = re.compile(rf"^interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", re.IGNORECASE)


def _set(iface: InterfaceIR, attr: str, value, line: Line, ctx: ParseContext, category=D) -> None:
    setattr(iface, attr, value)
    iface.field_lines[attr] = line.no
    ctx.rule(line, category)


def _description(m, line, ctx, iface):
    _set(iface, "description", m[1], line, ctx)


def _ip_address(allow_len: bool):
    def fn(m, line, ctx, iface):
        plen = parse_mask(m[2], allow_len)
        try:
            ipv4: Optional[IPv4Interface] = IPv4Interface(f"{m[1]}/{plen}") if plen is not None else None
        except ValueError:
            ipv4 = None
        if ipv4 is None:
            ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
            return
        _set(iface, "ipv4", ipv4, line, ctx, T if m[2].isdigit() else D)

    return fn


def _shutdown(value: bool):
    def fn(m, line, ctx, iface):
        _set(iface, "shutdown", value, line, ctx)

    return fn


def _link_protocol(m, line, ctx, iface):
    _set(iface, "link_protocol", m[1].lower(), line, ctx)


def _no_ip(m, line, ctx, iface):
    ctx.not_needed(line, REASON_NO_IP, iface.notes)


def _unsupported(feature: str):
    reason = reason_not_supported(feature)

    def fn(m, line, ctx, iface):
        ctx.unconverted(line, reason, iface.notes)

    return fn


_CISCO_BASE = compile_rules(
    [
        (r"^description\s+(.+)$", _description),
        (r"^ip\s+address\s+(\S+)\s+(\S+)$", _ip_address(False)),
        (r"^no\s+ip\s+address$", _no_ip),
        (r"^shutdown$", _shutdown(True)),
        (r"^no\s+shutdown$", _shutdown(False)),
        (r"^encapsulation\s+(ppp|hdlc)$", _link_protocol),
        (r"^(encapsulation\s+frame-relay|frame-relay)\b", _unsupported("Frame Relay")),
        (r"^clock\s+rate\b", _unsupported("Clock Rate")),
    ]
)

_HUAWEI_BASE = compile_rules(
    [
        (r"^description\s+(.+)$", _description),
        (r"^ip\s+address\s+(\S+)\s+(\S+)$", _ip_address(True)),
        (r"^shutdown$", _shutdown(True)),
        (r"^undo\s+shutdown$", _shutdown(False)),
        (r"^link-protocol\s+(ppp|hdlc)$", _link_protocol),
        (r"^(link-protocol\s+fr|fr)\b", _unsupported("Frame Relay")),
        (r"^(virtualbaudrate|baudrate)\b", _unsupported("Clock Rate")),
    ]
)

CISCO_INTERFACE_RULES: list[ChildRule] = _CISCO_BASE + CISCO_SWITCHPORT_RULES + CISCO_OSPF_INTERFACE_RULES
HUAWEI_INTERFACE_RULES: list[ChildRule] = _HUAWEI_BASE + HUAWEI_SWITCHPORT_RULES + HUAWEI_OSPF_INTERFACE_RULES


def _interface(ctx: ParseContext, ref: InterfaceRef, line: Line) -> InterfaceIR:
    for iface in ctx.ir.interfaces:
        if iface.ref == ref:
            break
    else:
        iface = InterfaceIR(
            if_type=ref.if_type, number=ref.number, is_virtual=interface_names.is_virtual(ref.if_type)
        )
        ctx.ir.interfaces.append(iface)
    iface.source_lines.append(line.no)
    return iface


def _interface_handler(vendor: Vendor, rules: list[ChildRule]) -> BlockHandler:
    def handler(block: Block, ctx: ParseContext) -> bool:
        m = _INTERFACE.match(block.header.body)
        if not m:
            if re.match(r"^interface\s", block.header.body, re.IGNORECASE):  # extra args, e.g. "point-to-point"
                ctx.unconverted_block(block, REASON_NO_RULE, ctx.ir.notes)
                return True
            return False
        ref = interface_names.resolve(m[1], vendor)
        if ref is None:
            oos = interface_names.out_of_scope_type(m[1])
            reason = reason_out_of_scope(oos) if oos else REASON_UNKNOWN_IF_TYPE
            ctx.unconverted_block(block, reason, ctx.ir.notes)
            return True
        iface = _interface(ctx, ref, block.header)
        ctx.rule(block.header, D)
        apply_child_rules(block, ctx, rules, iface, iface.notes)
        return True

    handler.__name__ = f"{'cisco' if vendor is Vendor.CISCO_IOS_XE else 'huawei'}_interface"
    return handler


cisco_interface = _interface_handler(Vendor.CISCO_IOS_XE, CISCO_INTERFACE_RULES)
huawei_interface = _interface_handler(Vendor.HUAWEI_VRP, HUAWEI_INTERFACE_RULES)

CISCO_HANDLERS: list[BlockHandler] = [cisco_interface]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_interface]
