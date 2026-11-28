"""Tier 1 — Interface & Serial rules (proposal §2.3.1 item 1.3.3).

  interface <Type><number>      type name mapped (D); number kept verbatim (§2.3.2 item 4)
  description <text>            <-> description <text>              (D)
  ip address <ip> <mask>        <-> ip address <ip> <mask|len>      (D; T when a prefix length
                                                                     is normalised to a mask)
  shutdown / no shutdown        <-> shutdown / undo shutdown        (D; unset if omitted)
  encapsulation ppp|hdlc        <-> link-protocol ppp|hdlc          (D; renderer warns on HDLC)
  no ip address                  -> "ไม่ต้องใช้คำสั่งนี้" (target default is no address)
  exit                          <-> quit                            (D, view exit; base.view_exit)
  interface range Gi0/1 - 4     <-> port-group group-member GigabitEthernet0/1 to GigabitEthernet0/4
                                                                    (T; numbers verbatim)

Link aggregation (S):
  interface Port-channel<id>    <-> interface Eth-Trunk<id>          (type name only, number kept)
  channel-group <id> mode active (member) <-> eth-trunk <id> (member) + mode lacp-static (in Eth-Trunk<id>)
  channel-group <id> mode on     (member) <-> eth-trunk <id> (member; Huawei default manual mode)
  channel-protocol lacp          -> "ไม่ต้องใช้คำสั่งนี้" (mode lacp-static already selects LACP)
  PAgP (desirable/auto) and LACP passive -> not supported.
  A member without an `interface Port-channel<id>` block in the source still yields
  `interface Eth-Trunk<id>` (translation of the channel-group line, like Cisco's implicit
  creation); the Huawei renderer always writes Eth-Trunk<id> before its members.

First-hop redundancy (HSRP -> VRRP, with a protocol-change warning in the renderer):
  standby <g> ip <ip>                 <-> vrrp vrid <g> virtual-ip <ip>
  standby <g> priority <n>            <-> vrrp vrid <g> priority <n>
  standby <g> preempt                  -> "ไม่ต้องใช้คำสั่งนี้" (Huawei VRRP preempts by default)
  standby <g> track <if> <dec>        <-> vrrp vrid <g> track interface <if> reduced <dec>
  standby <g> track <obj> decrement <dec> + global `track <obj> interface <if> line-protocol`
                                       -> vrrp vrid <g> track interface <if> reduced <dec>
  The global `track` object has no Huawei command of its own (never a standalone `bfd track`):
  it is folded into the VRRP line; an object no converted HSRP line uses stays "แปลงไม่ได้".

The interface block also accepts switchport rules (tier1_vlan), interface-level OSPF
rules (tier1_routing), RIP authentication (tier2_services, not supported) and ACL binding
(tier3_bgp_acl). Tunnel/ATM interfaces are out of scope; Clock Rate / Frame Relay are
"not supported" (§2.3.2 item 3) — all kept as unconverted comments.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Interface
from typing import Optional

from app.core.ir import InterfaceIR, InterfaceRef, SyntaxCategory, Vendor, VrrpGroupIR, VrrpTrackIR
from app.core.rules import interface_names
from app.core.rules.base import (
    CISCO_EXIT_RULES,
    HUAWEI_EXIT_RULES,
    REASON_NO_RULE,
    REASON_UNKNOWN_IF,
    Block,
    BlockHandler,
    ChildRule,
    Line,
    ParseContext,
    apply_child_rules,
    compile_rules,
    parse_ipv4,
    reason_intentional,
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
from app.core.rules.tier2_services import CISCO_RIP_INTERFACE_RULES, HUAWEI_RIP_INTERFACE_RULES
from app.core.rules.tier3_bgp_acl import CISCO_ACL_INTERFACE_RULES, HUAWEI_ACL_INTERFACE_RULES

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL

REASON_UNKNOWN_IF_TYPE = "ยังไม่มีกฎรองรับ Interface ประเภทนี้"
REASON_NO_IP = "อุปกรณ์ปลายทางไม่มี IP address บน Interface อยู่แล้วเป็นค่าเริ่มต้น"
REASON_CHANNEL_PROTOCOL = "Huawei mode lacp-static ใน interface Eth-Trunk กำหนดให้ใช้ LACP อยู่แล้ว"
REASON_CHANNEL_MODE_CONFLICT = (
    "พอร์ตสมาชิกของ Port-channel เดียวกันตั้ง mode ไม่ตรงกัน (active กับ on) — "
    "Eth-Trunk ของ Huawei มีได้โหมดเดียว กรุณาตรวจสอบต้นทาง"
)
REASON_CHANNEL_ON_VIRTUAL = "channel-group / eth-trunk ใช้ได้เฉพาะพอร์ตจริงเท่านั้น"
REASON_LACP_NOT_TRUNK = "mode lacp-static ใช้ได้เฉพาะใน interface Eth-Trunk"
FEATURE_PAGP = "EtherChannel แบบ PAgP หรือ LACP passive (รองรับเฉพาะ mode active และ mode on)"
REASON_VRRP_PREEMPT = "VRRP ของ Huawei ทำ preempt เป็นค่าเริ่มต้นอยู่แล้ว"
REASON_TRACK_UNUSED = reason_intentional(
    "track object นี้ไม่ได้ถูกใช้โดยคำสั่ง standby ที่แปลงได้ — Huawei ไม่มีคำสั่ง track แยก "
    "(ห้ามแปลงเป็น bfd track ที่ system-view) จึงรวมไว้ในคำสั่ง vrrp vrid ... track interface เท่านั้น"
)
REASON_TRACK_UNKNOWN = reason_intentional(
    "ไม่พบ track object แบบ interface line-protocol ที่คำสั่งนี้อ้างถึง — ระบบไม่เดาว่าต้อง track อะไร"
)
MAX_VRID = 255
MAX_VRRP_PRIORITY = 254
MAX_VRRP_REDUCED = 255

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

# ----------------------------------------------------------------------------- link aggregation


def _trunk(ctx: ParseContext, group: int, line: Line) -> InterfaceIR:
    """The Eth-Trunk / Port-channel interface a member binds to (created from the member line
    when the source has no `interface Port-channel<id>` block)."""
    ref = InterfaceRef(if_type="eth-trunk", number=str(group))
    for iface in ctx.ir.interfaces:
        if iface.ref == ref and iface.range_end is None:
            return iface
    iface = InterfaceIR(if_type="eth-trunk", number=str(group), is_virtual=True, source_lines=[line.no])
    ctx.ir.interfaces.append(iface)
    ctx.data.setdefault("implicit_trunks", set()).add(id(iface))
    return iface


def _bind_member(iface: InterfaceIR, group: int, lacp: Optional[bool], line: Line, ctx: ParseContext) -> None:
    if iface.is_virtual:
        ctx.unconverted(line, REASON_CHANNEL_ON_VIRTUAL, iface.notes)
        return
    modes: dict[int, bool] = ctx.data.setdefault("channel_modes", {})
    if lacp is not None and modes.get(group, lacp) != lacp:
        ctx.unconverted(line, REASON_CHANNEL_MODE_CONFLICT, iface.notes)
        return
    trunk = _trunk(ctx, group, line)
    if lacp is not None:
        modes[group] = lacp
        if lacp:
            trunk.lacp_static = True
            trunk.field_lines.setdefault("lacp_static", line.no)
    iface.channel_group = group
    iface.field_lines["channel_group"] = line.no
    ctx.rule(line, S)


def _cisco_channel_group(m, line, ctx, iface):
    group, mode = int(m[1]), m[2].lower()
    if group < 1:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return
    if mode not in ("active", "on"):
        ctx.unconverted(line, reason_not_supported(FEATURE_PAGP), iface.notes)
        return
    _bind_member(iface, group, mode == "active", line, ctx)


def _huawei_eth_trunk(m, line, ctx, iface):
    _bind_member(iface, int(m[1]), None, line, ctx)


def _huawei_lacp_static(m, line, ctx, iface):
    if iface.if_type != "eth-trunk":
        ctx.unconverted(line, REASON_LACP_NOT_TRUNK, iface.notes)
        return
    _set(iface, "lacp_static", True, line, ctx, S)


def _not_needed(reason: str):
    def fn(m, line, ctx, iface):
        ctx.not_needed(line, reason, iface.notes)

    return fn


_CISCO_LAG = compile_rules(
    [
        (r"^channel-group\s+(\d+)\s+mode\s+(active|passive|on|desirable|auto)\b.*$", _cisco_channel_group),
        (r"^channel-protocol\s+lacp$", _not_needed(REASON_CHANNEL_PROTOCOL)),
        (r"^channel-protocol\s+pagp$", _unsupported(FEATURE_PAGP)),
    ]
)
_HUAWEI_LAG = compile_rules(
    [
        (r"^eth-trunk\s+(\d+)$", _huawei_eth_trunk),
        (r"^mode\s+lacp-static$", _huawei_lacp_static),
    ]
)


# ----------------------------------------------------------------------------- HSRP / VRRP


def _group(iface: InterfaceIR, vrid: int, protocol: str) -> VrrpGroupIR:
    for g in iface.vrrp_groups:
        if g.vrid == vrid:
            return g
    g = VrrpGroupIR(vrid=vrid, protocol=protocol)
    iface.vrrp_groups.append(g)
    return g


def _protocol(ctx: ParseContext) -> str:
    return "hsrp" if ctx.vendor is Vendor.CISCO_IOS_XE else "vrrp"


def _valid_vrid(m, line, ctx, iface) -> Optional[int]:
    vrid = int(m[1])
    if not 1 <= vrid <= MAX_VRID:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return None
    return vrid


def _vrrp_ip(m, line, ctx, iface):
    vrid = _valid_vrid(m, line, ctx, iface)
    if vrid is None:
        return
    address = parse_ipv4(m[2])
    if address is None:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return
    g = _group(iface, vrid, _protocol(ctx))
    g.virtual_ip = address
    g.field_lines["virtual_ip"] = line.no
    ctx.rule(line, T)


def _vrrp_priority(m, line, ctx, iface):
    vrid = _valid_vrid(m, line, ctx, iface)
    if vrid is None:
        return
    priority = int(m[2])
    if not 1 <= priority <= MAX_VRRP_PRIORITY:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return
    g = _group(iface, vrid, _protocol(ctx))
    g.priority = priority
    g.field_lines["priority"] = line.no
    ctx.rule(line, T)


def _add_track(iface: InterfaceIR, vrid: int, ref: InterfaceRef, decrement: int, line: Line, ctx: ParseContext,
               track_object: Optional[int] = None) -> None:
    g = _group(iface, vrid, _protocol(ctx))
    g.tracks.append(VrrpTrackIR(interface=ref, decrement=decrement, track_object=track_object, source_line=line.no))


def _vrrp_track_interface(m, line, ctx, iface):
    vrid = _valid_vrid(m, line, ctx, iface)
    if vrid is None:
        return
    ref = interface_names.resolve(m[2], ctx.vendor)
    if ref is None:
        ctx.unconverted(line, REASON_UNKNOWN_IF, iface.notes)
        return
    decrement = int(m[3])
    if not 1 <= decrement <= MAX_VRRP_REDUCED:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return
    _add_track(iface, vrid, ref, decrement, line, ctx)
    ctx.rule(line, T)


def _hsrp_track_object(m, line, ctx, iface):
    """`standby <g> track <obj> decrement <dec>`: resolved against the global track objects
    once the whole file is parsed (objects may be defined anywhere)."""
    vrid = _valid_vrid(m, line, ctx, iface)
    if vrid is None:
        return
    decrement = int(m[3])
    if not 1 <= decrement <= MAX_VRRP_REDUCED:
        ctx.unconverted(line, REASON_BAD_VALUE, iface.notes)
        return
    ctx.rule(line, S)
    ctx.data.setdefault("track_refs", []).append((line, iface, vrid, int(m[2]), decrement))
    ctx.add_finalizer(_resolve_track_objects)


def _resolve_track_objects(ctx: ParseContext) -> None:
    objects: dict[int, tuple[InterfaceRef, Line]] = ctx.data.get("track_objects", {})
    used: set[int] = set()
    for line, iface, vrid, obj, decrement in ctx.data.get("track_refs", []):
        if obj in objects:
            _add_track(iface, vrid, objects[obj][0], decrement, line, ctx, track_object=obj)
            group = _group(iface, vrid, _protocol(ctx))
            group.tracks.sort(key=lambda t: t.source_line or 0)  # keep source order
            used.add(obj)
        else:
            ctx.demote(line.no, REASON_TRACK_UNKNOWN, iface.notes)
    for obj, (_, line) in objects.items():
        if obj not in used:
            ctx.demote(line.no, REASON_TRACK_UNUSED, ctx.ir.notes)


_CISCO_FHRP = compile_rules(
    [
        (r"^standby\s+(\d+)\s+ip\s+(\S+)$", _vrrp_ip),
        (r"^standby\s+(\d+)\s+priority\s+(\d+)$", _vrrp_priority),
        (r"^standby\s+\d+\s+preempt$", _not_needed(REASON_VRRP_PREEMPT)),
        (r"^standby\s+(\d+)\s+track\s+(\d+)\s+decrement\s+(\d+)$", _hsrp_track_object),
        (rf"^standby\s+(\d+)\s+track\s+({interface_names.IF_NAME_PATTERN})\s+(\d+)$", _vrrp_track_interface),
    ]
)
_HUAWEI_FHRP = compile_rules(
    [
        (r"^vrrp\s+vrid\s+(\d+)\s+virtual-ip\s+(\S+)$", _vrrp_ip),
        (r"^vrrp\s+vrid\s+(\d+)\s+priority\s+(\d+)$", _vrrp_priority),
        (rf"^vrrp\s+vrid\s+(\d+)\s+track\s+interface\s+({interface_names.IF_NAME_PATTERN})\s+reduced\s+(\d+)$",
         _vrrp_track_interface),
    ]
)

_CISCO_TRACK = re.compile(
    rf"^track\s+(\d+)\s+interface\s+({interface_names.IF_NAME_PATTERN})\s+line-protocol$", re.IGNORECASE
)


def cisco_track(block: Block, ctx: ParseContext) -> bool:
    """Global `track <obj> interface <if> line-protocol` (folded into the VRRP track line)."""
    m = _CISCO_TRACK.match(block.header.body)
    if not m:
        return False
    ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
    ref = interface_names.resolve(m[2], Vendor.CISCO_IOS_XE)
    if ref is None:
        ctx.unconverted(block.header, REASON_UNKNOWN_IF, ctx.ir.notes)
        return True
    ctx.data.setdefault("track_objects", {})[int(m[1])] = (ref, block.header)
    ctx.rule(block.header, S)
    ctx.add_finalizer(_resolve_track_objects)
    return True


CISCO_INTERFACE_RULES: list[ChildRule] = (
    _CISCO_BASE + CISCO_EXIT_RULES + CISCO_SWITCHPORT_RULES + CISCO_OSPF_INTERFACE_RULES
    + CISCO_RIP_INTERFACE_RULES + CISCO_ACL_INTERFACE_RULES + _CISCO_LAG + _CISCO_FHRP
)
HUAWEI_INTERFACE_RULES: list[ChildRule] = (
    _HUAWEI_BASE + HUAWEI_EXIT_RULES + HUAWEI_SWITCHPORT_RULES + HUAWEI_OSPF_INTERFACE_RULES
    + HUAWEI_RIP_INTERFACE_RULES + HUAWEI_ACL_INTERFACE_RULES + _HUAWEI_LAG + _HUAWEI_FHRP
)


def _interface(ctx: ParseContext, ref: InterfaceRef, line: Line, range_end: Optional[str] = None) -> InterfaceIR:
    for iface in ctx.ir.interfaces:
        if iface.ref == ref and iface.range_end == range_end:
            break
    else:
        iface = InterfaceIR(
            if_type=ref.if_type,
            number=ref.number,
            range_end=range_end,
            is_virtual=interface_names.is_virtual(ref.if_type),
        )
        ctx.ir.interfaces.append(iface)
    implicit = ctx.data.get("implicit_trunks", set())
    if id(iface) in implicit:  # created earlier from a member's channel-group line
        implicit.discard(id(iface))
        iface.source_lines.insert(0, line.no)
    else:
        iface.source_lines.append(line.no)
    return iface


# ----------------------------------------------------------------------------- port ranges
#
#   interface range GigabitEthernet0/1 - 4
#       <-> port-group group-member GigabitEthernet0/1 to GigabitEthernet0/4      (T)
#
# Port numbers are kept verbatim at both ends (§2.3.2 item 4) — only the type name changes.
# Physical ports only, one contiguous range; comma lists / macros stay "แปลงไม่ได้".

REASON_BAD_RANGE = (
    "ช่วงพอร์ตไม่ถูกต้อง — ต้องเป็นพอร์ตจริงประเภทเดียวกัน ต่างกันเฉพาะตัวเลขสุดท้าย และเรียงจากน้อยไปมาก"
)
_CISCO_RANGE = re.compile(
    rf"^interface\s+range\s+({interface_names.IF_NAME_PATTERN})\s*-\s*(\d+)$", re.IGNORECASE
)
_HUAWEI_RANGE = re.compile(
    rf"^port-group\s+group-member\s+({interface_names.IF_NAME_PATTERN})\s+to\s+({interface_names.IF_NAME_PATTERN})$",
    re.IGNORECASE,
)


def _cisco_range_end(m: re.Match, start: InterfaceRef) -> Optional[str]:
    parts = interface_names.split_last(start.number)
    return f"{parts[0]}{int(m[2])}" if parts else None


def _huawei_range_end(m: re.Match, start: InterfaceRef) -> Optional[str]:
    end = interface_names.resolve(m[2], Vendor.HUAWEI_VRP)
    return end.number if end is not None and end.if_type == start.if_type else None


def _range_handler(vendor: Vendor, pattern: re.Pattern, end_of, rules: list[ChildRule]) -> BlockHandler:
    def handler(block: Block, ctx: ParseContext) -> bool:
        m = pattern.match(block.header.body)
        if not m:
            return False
        start = interface_names.resolve(m[1], vendor)
        end = end_of(m, start) if start is not None else None
        if (
            start is None
            or end is None
            or interface_names.is_virtual(start.if_type)
            or interface_names.range_numbers(start.number, end) is None
        ):
            ctx.unconverted_block(block, REASON_BAD_RANGE, ctx.ir.notes)
            return True
        iface = _interface(ctx, start, block.header, range_end=end)
        ctx.rule(block.header, T)
        apply_child_rules(block, ctx, rules, iface, iface.notes)
        return True

    handler.__name__ = f"{'cisco' if vendor is Vendor.CISCO_IOS_XE else 'huawei'}_port_range"
    return handler


cisco_port_range = _range_handler(Vendor.CISCO_IOS_XE, _CISCO_RANGE, _cisco_range_end, CISCO_INTERFACE_RULES)
huawei_port_range = _range_handler(Vendor.HUAWEI_VRP, _HUAWEI_RANGE, _huawei_range_end, HUAWEI_INTERFACE_RULES)


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

CISCO_HANDLERS: list[BlockHandler] = [cisco_port_range, cisco_interface, cisco_track]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_port_range, huawei_interface]
