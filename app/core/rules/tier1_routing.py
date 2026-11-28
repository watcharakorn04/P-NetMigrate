"""Tier 1 — Static route and OSPFv2 rules (proposal §2.3.1 item 1.3.4).

Static route (T):
  ip route <dst> <mask> [<if>] [<nh>] [<ad>]  <-> ip route-static <dst> <mask|len> [<if>] [<nh>] [preference <n>]
  Omitted AD/preference stays None (defaults differ: Cisco AD=1, Huawei 60 -> renderer warns).
  `ip route ... name X` is intentionally unconverted (§2.3.2 item 7).

OSPFv2, single process (S — block nesting differs):
  router ospf <pid>                 <-> ospf <pid> [router-id <id>]
   router-id <id>                   <-> (folded into the ospf header)
   network <ip> <wc> area <a>       <-> area <a> / network <ip> <wc>
   area <a> stub                    <-> area <a> / stub
   passive-interface <if>           <-> silent-interface <if>
   passive-interface default        <-> silent-interface all
   no passive-interface <if>        <-> undo silent-interface <if>
   default-information originate    <-> default-route-advertise
  Interface level (D): ip ospf cost / priority / network point-to-point
                   <-> ospf cost / dr-priority / network-type p2p
  Not supported (§2.3.2 item 3) -> unconverted comment: multi-process, NSSA, virtual link,
  ABR summarization, authentication, timers, no-summary.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Network
from typing import Optional

from app.core.ir import OspfIR, OspfNetworkIR, StaticRouteIR, SyntaxCategory, Vendor
from app.core.rules import interface_names
from app.core.rules.base import (
    CISCO_EXIT_RULES,
    HUAWEI_EXIT_RULES,
    REASON_BAD_VALUE,
    REASON_NO_RULE,
    REASON_UNKNOWN_IF,
    Block,
    BlockHandler,
    Line,
    ParseContext,
    apply_child_rules,
    apply_line_rules,
    compile_rules,
    parse_ipv4,
    parse_mask,
    reason_intentional,
    reason_not_supported,
)
from app.core.rules.tier2_services import CISCO_REDISTRIBUTE_RULES, HUAWEI_REDISTRIBUTE_RULES

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL

REASON_ROUTE_NAME = reason_intentional("ชื่อเส้นทาง (name) จะหายไปโดยไม่มีอะไรเตือน")
REASON_ROUTE_DESCRIPTION = reason_intentional("คำอธิบายเส้นทาง (description) จะหายไปโดยไม่มีอะไรเตือน")
REASON_MULTI_PROCESS = reason_not_supported("OSPF หลาย Process (Multi-Process)")


_ip = parse_ipv4


def parse_area(text: str) -> Optional[int]:
    if text.isdigit():
        n = int(text)
        return n if n <= 0xFFFFFFFF else None
    ip = _ip(text)
    return int(ip) if ip is not None else None


# ----------------------------------------------------------------------------- static routes


def _static_handler(vendor: Vendor, header_re: str, allow_len: bool) -> BlockHandler:
    header = re.compile(header_re, re.IGNORECASE)
    is_cisco = vendor is Vendor.CISCO_IOS_XE

    def handler(block: Block, ctx: ParseContext) -> bool:
        m = header.match(block.header.body)
        if not m:
            return False
        line = block.header
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
        dest, plen = _ip(m[1]), parse_mask(m[2], allow_len)
        if dest is None or plen is None:
            ctx.unconverted(line, REASON_BAD_VALUE, ctx.ir.notes)
            return True
        tokens = m[3].split()
        route = StaticRouteIR(destination=IPv4Network(f"{dest}/{plen}", strict=False))
        i = 0
        if i < len(tokens) and (nh := _ip(tokens[i])) is not None:
            route.next_hop = nh
            i += 1
        elif i < len(tokens):
            ref = interface_names.resolve(tokens[i], vendor)
            if ref is None:
                ctx.unconverted(line, REASON_UNKNOWN_IF, ctx.ir.notes)
                return True
            route.exit_interface = ref
            i += 1
            if i < len(tokens) and (nh := _ip(tokens[i])) is not None:
                route.next_hop = nh
                i += 1
        # Administrative distance / preference
        if is_cisco and i < len(tokens) and tokens[i].isdigit():
            route.preference, i = int(tokens[i]), i + 1
        elif not is_cisco and i + 1 < len(tokens) and tokens[i].lower() == "preference" and tokens[i + 1].isdigit():
            route.preference, i = int(tokens[i + 1]), i + 2
        rest = [t.lower() for t in tokens[i:]]
        if route.preference is not None and not 1 <= route.preference <= 255:
            reason = REASON_BAD_VALUE
        elif rest and rest[0] == ("name" if is_cisco else "description"):
            reason = REASON_ROUTE_NAME if is_cisco else REASON_ROUTE_DESCRIPTION
        elif rest:
            reason = REASON_NO_RULE
        else:
            route.source_lines.append(line.no)
            ctx.ir.static_routes.append(route)
            ctx.rule(line, T)
            return True
        ctx.unconverted(line, reason, ctx.ir.notes)
        return True

    handler.__name__ = f"{'cisco' if is_cisco else 'huawei'}_static_route"
    return handler


cisco_static_route = _static_handler(Vendor.CISCO_IOS_XE, r"^ip\s+route\s+(\S+)\s+(\S+)\s+(.+)$", False)
huawei_static_route = _static_handler(Vendor.HUAWEI_VRP, r"^ip\s+route-static\s+(\S+)\s+(\S+)\s+(.+)$", True)


# ----------------------------------------------------------------------------- OSPF helpers


def _unsupported(feature: str):
    reason = reason_not_supported(feature)

    def fn(m, line, ctx, target):
        ctx.unconverted(line, reason, target.notes)

    return fn


def _router_id(m, line, ctx, ospf: OspfIR):
    rid = _ip(m[1])
    if rid is None:
        ctx.unconverted(line, REASON_BAD_VALUE, ospf.notes)
        return
    ospf.router_id = rid
    ospf.field_lines["router_id"] = line.no
    ctx.rule(line, S)


def _add_network(ospf: OspfIR, area_id: int, addr: str, wc: str, line: Line, ctx: ParseContext) -> None:
    a, w = _ip(addr), _ip(wc)
    if a is None or w is None:
        ctx.unconverted(line, REASON_BAD_VALUE, ospf.notes)
        return
    ospf.area(area_id).networks.append(OspfNetworkIR(address=a, wildcard=w, source_line=line.no))
    ctx.rule(line, S)


def _cisco_network(m, line, ctx, ospf: OspfIR):
    area_id = parse_area(m[3])
    if area_id is None:
        ctx.unconverted(line, REASON_BAD_VALUE, ospf.notes)
        return
    _add_network(ospf, area_id, m[1], m[2], line, ctx)


def _set_stub(ospf: OspfIR, area_id: int, line: Line, ctx: ParseContext) -> None:
    area = ospf.area(area_id)
    area.stub = True
    area.field_lines["stub"] = line.no
    ctx.rule(line, S)


def _cisco_stub(m, line, ctx, ospf: OspfIR):
    area_id = parse_area(m[1])
    if area_id is None:
        ctx.unconverted(line, REASON_BAD_VALUE, ospf.notes)
        return
    _set_stub(ospf, area_id, line, ctx)


def _silent(vendor: Vendor):
    def fn(m, line, ctx, ospf: OspfIR):
        ref = interface_names.resolve(m[1], vendor)
        if ref is None:
            ctx.unconverted(line, REASON_UNKNOWN_IF, ospf.notes)
            return
        if ref not in ospf.silent_interfaces:
            ospf.silent_interfaces.append(ref)
        ctx.rule(line, S)

    return fn


def _silent_all(m, line, ctx, ospf: OspfIR):
    ospf.silent_all = True
    ospf.field_lines["silent_all"] = line.no
    ctx.rule(line, S)


def _non_silent(vendor: Vendor):
    def fn(m, line, ctx, ospf: OspfIR):
        ref = interface_names.resolve(m[1], vendor)
        if ref is None:
            ctx.unconverted(line, REASON_UNKNOWN_IF, ospf.notes)
            return
        if ref not in ospf.non_silent_interfaces:
            ospf.non_silent_interfaces.append(ref)
            ospf.field_lines[f"non_silent {ref.if_type}{ref.number}"] = line.no
        ctx.rule(line, S)

    return fn


def _default_originate(m, line, ctx, ospf: OspfIR):
    ospf.default_originate = True
    ospf.field_lines["default_originate"] = line.no
    ctx.rule(line, S)


def _no_rule(m, line, ctx, target):
    ctx.unconverted(line, REASON_NO_RULE, target.notes)


def _start_process(block: Block, ctx: ParseContext, pid: int) -> Optional[OspfIR]:
    """Return the OSPF process IR, or None (block marked unconverted) for a second process."""
    if ctx.ir.ospf is not None and ctx.ir.ospf.process_id != pid:
        ctx.unconverted_block(block, REASON_MULTI_PROCESS, ctx.ir.notes)
        return None
    if ctx.ir.ospf is None:
        ctx.ir.ospf = OspfIR(process_id=pid)
    ctx.ir.ospf.source_lines.append(block.header.no)
    return ctx.ir.ospf


# ----------------------------------------------------------------------------- OSPF: Cisco

_CISCO_OSPF = re.compile(r"^router\s+ospf\s+(\d+)$", re.IGNORECASE)
_CISCO_OSPF_RULES = compile_rules(
    [
        (r"^router-id\s+(\S+)$", _router_id),
        (r"^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)$", _cisco_network),
        (r"^area\s+(\S+)\s+stub$", _cisco_stub),
        (r"^area\s+\S+\s+stub\s+no-summary$", _unsupported("ตัวเลือก no-summary")),
        (r"^area\s+\S+\s+nssa\b", _unsupported("NSSA")),
        (r"^area\s+\S+\s+virtual-link\b", _unsupported("Virtual Link")),
        (r"^area\s+\S+\s+range\b", _unsupported("ABR Summarization")),
        (r"^area\s+\S+\s+authentication\b", _unsupported("การยืนยันตัวตน OSPF (Authentication)")),
        (r"^passive-interface\s+default$", _silent_all),
        (rf"^no\s+passive-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _non_silent(Vendor.CISCO_IOS_XE)),
        (rf"^passive-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _silent(Vendor.CISCO_IOS_XE)),
        (r"^default-information\s+originate$", _default_originate),
        (r"^timers\b", _unsupported("คำสั่งปรับจังหวะเวลา OSPF (Timers)")),
    ]
) + CISCO_REDISTRIBUTE_RULES + CISCO_EXIT_RULES


def cisco_ospf(block: Block, ctx: ParseContext) -> bool:
    m = _CISCO_OSPF.match(block.header.body)
    if not m:
        return False
    ospf = _start_process(block, ctx, int(m[1]))
    if ospf is not None:
        ctx.rule(block.header, S)
        apply_child_rules(block, ctx, _CISCO_OSPF_RULES, ospf, ospf.notes)
    return True


# ----------------------------------------------------------------------------- OSPF: Huawei

_HUAWEI_OSPF = re.compile(r"^ospf\s+(\d+)(?:\s+router-id\s+(\S+))?$", re.IGNORECASE)
_HUAWEI_AREA = re.compile(r"^area\s+(\S+)$", re.IGNORECASE)
_HUAWEI_OSPF_RULES = compile_rules(
    [
        (r"^silent-interface\s+all$", _silent_all),
        (rf"^undo\s+silent-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _non_silent(Vendor.HUAWEI_VRP)),
        (rf"^silent-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _silent(Vendor.HUAWEI_VRP)),
        (r"^default-route-advertise$", _default_originate),
        (r"^(timer|spf-schedule-interval|lsa-arrival-interval|lsa-originate-interval)\b",
         _unsupported("คำสั่งปรับจังหวะเวลา OSPF (Timers)")),
    ]
) + HUAWEI_REDISTRIBUTE_RULES + HUAWEI_EXIT_RULES


class _AreaTarget:
    """Binds an area id to the process so flat child rules can address it."""

    def __init__(self, ospf: OspfIR, area_id: int):
        self.ospf, self.area_id, self.notes = ospf, area_id, ospf.notes


def _huawei_network(m, line, ctx, t: _AreaTarget):
    _add_network(t.ospf, t.area_id, m[1], m[2], line, ctx)


def _huawei_stub(m, line, ctx, t: _AreaTarget):
    _set_stub(t.ospf, t.area_id, line, ctx)


_HUAWEI_AREA_RULES = compile_rules(
    [
        (r"^network\s+(\S+)\s+(\S+)$", _huawei_network),
        (r"^stub$", _huawei_stub),
        (r"^stub\s+no-summary$", _unsupported("ตัวเลือก no-summary")),
        (r"^nssa\b", _unsupported("NSSA")),
        (r"^vlink-peer\b", _unsupported("Virtual Link")),
        (r"^abr-summary\b", _unsupported("ABR Summarization")),
        (r"^authentication-mode\b", _unsupported("การยืนยันตัวตน OSPF (Authentication)")),
    ]
) + HUAWEI_EXIT_RULES  # `quit` from the area view


def huawei_ospf(block: Block, ctx: ParseContext) -> bool:
    m = _HUAWEI_OSPF.match(block.header.body)
    if not m:
        return False
    ospf = _start_process(block, ctx, int(m[1]))
    if ospf is None:
        return True
    if m[2] is not None:
        rid = _ip(m[2])
        if rid is None:
            ctx.unconverted_block(block, REASON_BAD_VALUE, ctx.ir.notes)
            return True
        ospf.router_id = rid
        ospf.field_lines["router_id"] = block.header.no
    ctx.rule(block.header, S)
    for child in block.children:
        am = _HUAWEI_AREA.match(child.header.body)
        area_id = parse_area(am[1]) if am else None
        if am and area_id is not None:
            # The area exists in the IR once it holds a network or stub flag (same as Cisco,
            # where areas have no block of their own).
            ctx.rule(child.header, S)
            apply_child_rules(child, ctx, _HUAWEI_AREA_RULES, _AreaTarget(ospf, area_id), ospf.notes)
        else:
            apply_line_rules(child, ctx, _HUAWEI_OSPF_RULES, ospf, ospf.notes)
    return True


# ----------------------------------------------------------------------------- interface-level OSPF


def _if_int(attr: str):
    def fn(m, line, ctx, iface):
        setattr(iface, attr, int(m[1]))
        iface.field_lines[attr] = line.no
        ctx.rule(line, D)

    return fn


def _if_p2p(m, line, ctx, iface):
    iface.ospf_network_p2p = True
    iface.field_lines["ospf_network_p2p"] = line.no
    ctx.rule(line, D)


CISCO_OSPF_INTERFACE_RULES = compile_rules(
    [
        (r"^ip\s+ospf\s+cost\s+(\d+)$", _if_int("ospf_cost")),
        (r"^ip\s+ospf\s+priority\s+(\d+)$", _if_int("ospf_priority")),
        (r"^ip\s+ospf\s+network\s+point-to-point$", _if_p2p),
        (r"^ip\s+ospf\s+(hello-interval|dead-interval|retransmit-interval|transmit-delay)\b",
         _unsupported("คำสั่งปรับจังหวะเวลา OSPF (Timers)")),
        (r"^ip\s+ospf\s+authentication\b", _unsupported("การยืนยันตัวตน OSPF (Authentication)")),
    ]
)

HUAWEI_OSPF_INTERFACE_RULES = compile_rules(
    [
        (r"^ospf\s+cost\s+(\d+)$", _if_int("ospf_cost")),
        (r"^ospf\s+dr-priority\s+(\d+)$", _if_int("ospf_priority")),
        (r"^ospf\s+network-type\s+p2p$", _if_p2p),
        (r"^ospf\s+timer\b", _unsupported("คำสั่งปรับจังหวะเวลา OSPF (Timers)")),
        (r"^ospf\s+authentication-mode\b", _unsupported("การยืนยันตัวตน OSPF (Authentication)")),
    ]
)

CISCO_HANDLERS: list[BlockHandler] = [cisco_static_route, cisco_ospf]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_static_route, huawei_ospf]
