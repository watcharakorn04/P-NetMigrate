"""Tier 2 — RIPv2, Redistribution, Default gateway, NTP, Syslog, VTY/SSH (proposal §2.3.1 1.3.4–1.3.6).

RIPv2, single process (D inside the block; header T because Huawei adds a process id):
  router rip                    <-> rip [<pid>]          (Cisco has no id -> process 1)
   version 2                    <-> version 2
   no auto-summary / auto-summary <-> undo summary / summary
   network <classful>           <-> network <classful>
   passive-interface <if>       <-> silent-interface <if>
   default-information originate <-> default-route originate
  Not supported -> "แปลงไม่ได้": RIPv1, authentication, timers, >1 process (§2.3.2 item 7).

Redistribution (T) into OSPF / RIP / BGP — only with an explicit metric (§2.3.2 items 5, 7):
  redistribute static|connected|ospf <p>|rip [subnets] metric <m> [metric-type 1|2]
      <-> import-route static|direct|ospf <p>|rip <p> cost <m> [type 1|2]   (OSPF / RIP)
      <-> import-route ... med <m>                                          (BGP)
  No metric -> "แปลงไม่ได้" (default metrics differ). Route-map / route-policy -> out of scope.

Default gateway (T, C->H only): ip default-gateway <ip> -> ip route-static 0.0.0.0 0.0.0.0 <ip> + warning.
NTP (D):    ntp server <ip>                 <-> ntp-service unicast-server <ip>
Syslog (D): logging host <ip> / logging <ip> <-> info-center loghost <ip>

VTY / SSH (D):
  line vty <a> [<b>]            <-> user-interface vty <a> <b>
   login local                  <-> authentication-mode aaa
   transport input ssh|telnet|ssh telnet|all <-> protocol inbound ssh|telnet|all
   logging synchronous           -> "ไม่ต้องใช้คำสั่งนี้" (VRP default; see tier1_system)
  Huawei needs `stelnet server enable` for SSH: the renderer writes it as a comment advisory
  ("# แนะนำให้เปิดใช้งาน SSH Server ...") — never as a command, because the Huawei BGP
  activation block is the only command the system may auto-generate (proposal §2.3.2 item 5).
  User accounts / passwords are never translated — secret_stripper removes them first; a
  password-based `login` / `authentication-mode password` stays "แปลงไม่ได้".
  line con 0                    <-> user-interface con 0   (same child rules as VTY)
   login local                  <-> authentication-mode aaa   (never `authentication-mode local`)

SSH server (D/T, global; never adds `stelnet server enable`):
  ip ssh version 2                  <-> ssh server compatible-ssh1x disable
  ip ssh time-out <s>               <-> ssh server timeout <s>                 (never `ssh client timeout`)
  ip ssh authentication-retries <n> <-> ssh server authentication-retries <n>  (never `ssh server retry`)

Clock (T): clock timezone <tz> <h> [<m>] <-> clock timezone <tz> add|minus HH:MM:SS
           e.g. `clock timezone ICT 7 0` <-> `clock timezone ICT add 07:00:00`

DHCP snooping (D global / S per VLAN):
  ip dhcp snooping              <-> dhcp snooping enable   (+ comment advisory: `dhcp enable` first)
  ip dhcp snooping vlan 10,20   <-> vlan 10 / dhcp snooping enable / quit   (one block per VLAN;
                                    never the global `dhcp snooping enable vlan ...`)
  (Huawei) dhcp enable           -> "ไม่ต้องใช้คำสั่งนี้" (Cisco runs the DHCP service by default)

Global BPDU protection (D): spanning-tree portfast [edge] bpduguard default <-> stp bpdu-protection
  (interface-level `spanning-tree bpduguard enable` is "ไม่ต้องใช้คำสั่งนี้", see tier1_vlan)

Global STP (system view, with a semantics warning in the renderer):
  spanning-tree mode rapid-pvst     <-> stp mode rstp            (T; other modes -> no rule)
  spanning-tree portfast default    <-> stp edged-port default   (D)
"""

from __future__ import annotations

import re
from typing import Optional

from app.core.ir import (
    BgpIR,
    ClockTimezoneIR,
    DhcpSnoopingIR,
    OspfIR,
    RedistributeIR,
    RipIR,
    ServerIR,
    SshServerIR,
    SyntaxCategory,
    Vendor,
    VtyIR,
)
from app.core.rules import interface_names
from app.core.rules.tier1_system import CISCO_NOT_NEEDED_ANYWHERE
from app.core.rules.tier1_vlan import parse_cisco_vlan_list
from app.core.rules.base import (
    CISCO_EXIT_RULES,
    HUAWEI_EXIT_RULES,
    REASON_BAD_VALUE,
    REASON_NO_RULE,
    REASON_UNKNOWN_IF,
    Block,
    BlockHandler,
    ChildRule,
    ParseContext,
    apply_child_rules,
    not_needed_rule,
    classful_prefix_len,
    compile_rules,
    parse_ipv4,
    reason_intentional,
    reason_not_supported,
    unconverted_rule,
    unsupported_rule,
)

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL

REASON_REDIST_NO_METRIC = reason_intentional(
    "ต้นทางไม่ได้ระบุค่าตัววัด (metric) — ค่าเริ่มต้นตอนดึงเส้นทางจากโปรโตคอลอื่นของสองยี่ห้อไม่เท่ากัน "
    "ระบบไม่เดาค่าให้ กรุณาระบุ metric ในคำสั่งต้นทางแล้วแปลงใหม่"
)
REASON_REDIST_SOURCE = reason_not_supported(
    "การดึงเส้นทางจากโปรโตคอลนี้ (รองรับเฉพาะ static, connected/direct, OSPF, RIP)"
)
REASON_RIP_MULTI = reason_intentional("RIP มากกว่าหนึ่ง Process (Multi-Process)")
REASON_SERVER_NOT_IPV4 = "รองรับเฉพาะเซิร์ฟเวอร์ที่ระบุเป็น IPv4 address"
REASON_PASSWORD_LOGIN = reason_intentional(
    "การยืนยันตัวตนด้วยรหัสผ่านของ line — ระบบไม่แปลงรหัสผ่าน กรุณาตั้งค่าการยืนยันตัวตนเองบนอุปกรณ์ปลายทาง"
)
REASON_NO_LOGIN = reason_intentional("VTY ที่ไม่มีการยืนยันตัวตนไม่ปลอดภัย กรุณาตั้งค่าเองบนอุปกรณ์ปลายทาง")
REASON_STELNET = (
    "Cisco ไม่มีคำสั่งเปิดบริการ SSH แยก — SSH จะทำงานเมื่อมี RSA key (crypto key generate rsa) "
    "ซึ่งต้องสร้างเองบนอุปกรณ์ปลายทาง"
)
REASON_TELNET_SERVER = "Cisco เปิดบริการ Telnet บน VTY อยู่แล้ว ควบคุมด้วย transport input"
REASON_DHCP_SERVICE = "Cisco เปิดบริการ DHCP (service dhcp) เป็นค่าเริ่มต้นอยู่แล้ว"

FEATURE_RIP_AUTH = "การยืนยันตัวตน RIP (Authentication)"
FEATURE_RIP_TIMERS = "คำสั่งปรับจังหวะเวลา RIP (Timers)"
FEATURE_VTY_ACL = "การนำ ACL ไปใช้กับ Policy อื่น (ACL บน VTY)"


# ----------------------------------------------------------------------------- redistribution

_METRIC_RANGE = {"ospf": (0, 16777214), "rip": (0, 15), "bgp": (0, 4294967295)}


def _target_protocol(target) -> str:
    if isinstance(target, OspfIR):
        return "ospf"
    if isinstance(target, RipIR):
        return "rip"
    if isinstance(target, BgpIR):
        return "bgp"
    raise TypeError(f"redistribution into {type(target).__name__} is not modelled")


def _source_protocol(tokens: list[str], vendor: Vendor) -> tuple[Optional[str], Optional[int], int]:
    """(neutral protocol, process id, tokens consumed); protocol None if unsupported."""
    word = tokens[0].lower()
    has_pid = len(tokens) > 1 and tokens[1].isdigit()
    if word == "static":
        return "static", None, 1
    if word == ("connected" if vendor is Vendor.CISCO_IOS_XE else "direct"):
        return "connected", None, 1
    if word == "ospf":
        if vendor is Vendor.CISCO_IOS_XE and not has_pid:
            return None, None, 0
        return "ospf", int(tokens[1]) if has_pid else 1, 2 if has_pid else 1
    if word == "rip":
        if vendor is Vendor.CISCO_IOS_XE:
            return "rip", 1, 1
        return "rip", int(tokens[1]) if has_pid else 1, 2 if has_pid else 1
    return None, None, 0


def _redistribute(vendor: Vendor):
    is_cisco = vendor is Vendor.CISCO_IOS_XE

    def fn(m, line, ctx, target):
        into = _target_protocol(target)
        tokens = m[1].split()
        protocol, pid, i = _source_protocol(tokens, vendor)
        if protocol is None:
            ctx.unconverted(line, REASON_REDIST_SOURCE, target.notes)
            return
        metric_kw = "metric" if is_cisco else ("med" if into == "bgp" else "cost")
        type_kw = "metric-type" if is_cisco else "type"
        metric: Optional[int] = None
        metric_type: Optional[int] = None
        while i < len(tokens):
            word, arg = tokens[i].lower(), tokens[i + 1] if i + 1 < len(tokens) else ""
            if is_cisco and word == "subnets" and into == "ospf":
                i += 1  # IOS-XE always imports subnets; Huawei import-route has no classful mode
            elif word == metric_kw and arg.isdigit():
                metric, i = int(arg), i + 2
            elif word == type_kw and into == "ospf" and arg in ("1", "2"):
                metric_type, i = int(arg), i + 2
            else:
                ctx.unconverted(line, REASON_NO_RULE, target.notes)
                return
        if metric is None:
            ctx.unconverted(line, REASON_REDIST_NO_METRIC, target.notes)
            return
        lo, hi = _METRIC_RANGE[into]
        if not lo <= metric <= hi:
            ctx.unconverted(line, REASON_BAD_VALUE, target.notes)
            return
        target.redistribute.append(
            RedistributeIR(protocol=protocol, process_id=pid, metric=metric, metric_type=metric_type, source_line=line.no)
        )
        ctx.rule(line, T)

    return fn


CISCO_REDISTRIBUTE_RULES: list[ChildRule] = compile_rules([(r"^redistribute\s+(.+)$", _redistribute(Vendor.CISCO_IOS_XE))])
HUAWEI_REDISTRIBUTE_RULES: list[ChildRule] = compile_rules([(r"^import-route\s+(.+)$", _redistribute(Vendor.HUAWEI_VRP))])


# ----------------------------------------------------------------------------- RIP


def _set(target, attr: str, value, line, ctx, category=D) -> None:
    setattr(target, attr, value)
    target.field_lines[attr] = line.no
    ctx.rule(line, category)


def _rip_version(m, line, ctx, rip: RipIR):
    _set(rip, "version", 2, line, ctx)


def _rip_summary(value: bool):
    def fn(m, line, ctx, rip: RipIR):
        _set(rip, "auto_summary", value, line, ctx)

    return fn


def _rip_network(m, line, ctx, rip: RipIR):
    address = parse_ipv4(m[1])
    if address is None or classful_prefix_len(address) is None:
        ctx.unconverted(line, REASON_BAD_VALUE, rip.notes)
        return
    if address not in rip.networks:
        rip.networks.append(address)
        rip.field_lines[f"network {address}"] = line.no
    ctx.rule(line, D)


def _rip_silent(vendor: Vendor):
    def fn(m, line, ctx, rip: RipIR):
        ref = interface_names.resolve(m[1], vendor)
        if ref is None:
            ctx.unconverted(line, REASON_UNKNOWN_IF, rip.notes)
            return
        if ref not in rip.silent_interfaces:
            rip.silent_interfaces.append(ref)
            rip.field_lines[f"silent {ref.if_type}{ref.number}"] = line.no
        ctx.rule(line, D)

    return fn


def _rip_default_originate(m, line, ctx, rip: RipIR):
    _set(rip, "default_originate", True, line, ctx)


_no_rule = unconverted_rule(REASON_NO_RULE)

_CISCO_RIP_RULES = compile_rules(
    [
        (r"^version\s+2$", _rip_version),
        (r"^version\s+1$", unsupported_rule("RIPv1 (ระบบรองรับเฉพาะ RIPv2)")),
        (r"^no\s+auto-summary$", _rip_summary(False)),
        (r"^auto-summary$", _rip_summary(True)),
        (r"^network\s+(\S+)$", _rip_network),
        (r"^passive-interface\s+default$", _no_rule),
        (rf"^passive-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _rip_silent(Vendor.CISCO_IOS_XE)),
        (r"^default-information\s+originate$", _rip_default_originate),
        (r"^timers\b", unsupported_rule(FEATURE_RIP_TIMERS)),
    ]
) + CISCO_REDISTRIBUTE_RULES + CISCO_EXIT_RULES

_HUAWEI_RIP_RULES = compile_rules(
    [
        (r"^version\s+2$", _rip_version),
        (r"^version\s+1$", unsupported_rule("RIPv1 (ระบบรองรับเฉพาะ RIPv2)")),
        (r"^undo\s+summary$", _rip_summary(False)),
        (r"^summary$", _rip_summary(True)),
        (r"^network\s+(\S+)$", _rip_network),
        (r"^silent-interface\s+all$", _no_rule),
        (rf"^silent-interface\s+({interface_names.IF_NAME_PATTERN}|\S+)$", _rip_silent(Vendor.HUAWEI_VRP)),
        (r"^default-route\s+originate$", _rip_default_originate),
        (r"^timers\s+rip\b", unsupported_rule(FEATURE_RIP_TIMERS)),
    ]
) + HUAWEI_REDISTRIBUTE_RULES + HUAWEI_EXIT_RULES


def _rip_handler(vendor: Vendor, header_re: str, rules: list[ChildRule]) -> BlockHandler:
    header = re.compile(header_re, re.IGNORECASE)

    def handler(block: Block, ctx: ParseContext) -> bool:
        m = header.match(block.header.body)
        if not m:
            return False
        pid = int(m[1]) if m.lastindex and m[1] else 1
        if ctx.ir.rip is not None and ctx.ir.rip.process_id != pid:
            ctx.unconverted_block(block, REASON_RIP_MULTI, ctx.ir.notes)
            return True
        if ctx.ir.rip is None:
            ctx.ir.rip = RipIR(process_id=pid)
        rip = ctx.ir.rip
        rip.source_lines.append(block.header.no)
        ctx.rule(block.header, T)
        apply_child_rules(block, ctx, rules, rip, rip.notes)
        return True

    handler.__name__ = f"{'cisco' if vendor is Vendor.CISCO_IOS_XE else 'huawei'}_rip"
    return handler


cisco_rip = _rip_handler(Vendor.CISCO_IOS_XE, r"^router\s+rip$", _CISCO_RIP_RULES)
huawei_rip = _rip_handler(Vendor.HUAWEI_VRP, r"^rip(?:\s+(\d+))?$", _HUAWEI_RIP_RULES)

# Interface-level RIP: authentication is "not supported" (key material is stripped earlier).
CISCO_RIP_INTERFACE_RULES: list[ChildRule] = compile_rules(
    [(r"^ip\s+rip\s+authentication\b", unsupported_rule(FEATURE_RIP_AUTH))]
)
HUAWEI_RIP_INTERFACE_RULES: list[ChildRule] = compile_rules(
    [(r"^rip\s+authentication-mode\b", unsupported_rule(FEATURE_RIP_AUTH))]
)


# ----------------------------------------------------------------------------- default gateway / NTP / syslog


def _single_line_handler(name: str, pattern: str, apply) -> BlockHandler:
    regex = re.compile(pattern, re.IGNORECASE)

    def handler(block: Block, ctx: ParseContext) -> bool:
        m = regex.match(block.header.body)
        if not m:
            return False
        ctx.unconverted_children(block, REASON_NO_RULE, ctx.ir.notes)
        apply(m, block, ctx)
        return True

    handler.__name__ = name
    return handler


def _default_gateway(m, block: Block, ctx: ParseContext) -> None:
    gateway = parse_ipv4(m[1])
    if gateway is None:
        ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
        return
    ctx.ir.default_gateway = gateway
    ctx.ir.field_lines["default_gateway"] = block.header.no
    ctx.rule(block.header, T)


def _server(attr: str):
    def apply(m, block: Block, ctx: ParseContext) -> None:
        address = parse_ipv4(m[m.lastindex])  # the alternative group that matched
        if address is None:
            ctx.unconverted(block.header, REASON_SERVER_NOT_IPV4, ctx.ir.notes)
            return
        getattr(ctx.ir, attr).append(ServerIR(address=address, source_line=block.header.no))
        ctx.rule(block.header, D)

    return apply


cisco_default_gateway = _single_line_handler("cisco_default_gateway", r"^ip\s+default-gateway\s+(\S+)$", _default_gateway)
cisco_ntp = _single_line_handler("cisco_ntp", r"^ntp\s+server\s+(\S+)$", _server("ntp_servers"))
huawei_ntp = _single_line_handler("huawei_ntp", r"^ntp-service\s+unicast-server\s+(\S+)$", _server("ntp_servers"))
cisco_syslog = _single_line_handler(
    "cisco_syslog", r"^logging\s+(?:host\s+(\S+)|(\d+\.\d+\.\d+\.\d+))$", _server("syslog_hosts")
)
huawei_syslog = _single_line_handler("huawei_syslog", r"^info-center\s+loghost\s+(\S+)$", _server("syslog_hosts"))


# ----------------------------------------------------------------------------- clock timezone

MAX_TZ_MINUTES = 23 * 60 + 59


def _store_timezone(ctx: ParseContext, block: Block, name: str, minutes: int) -> None:
    if abs(minutes) > MAX_TZ_MINUTES:
        ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
        return
    ctx.ir.clock_timezone = ClockTimezoneIR(name=name, offset_minutes=minutes, source_line=block.header.no)
    ctx.rule(block.header, T)


def _cisco_timezone(m, block: Block, ctx: ParseContext) -> None:
    hours, minutes = int(m[2]), int(m[3] or 0)
    if minutes > 59:
        ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
        return
    sign = -1 if m[2].startswith("-") else 1
    _store_timezone(ctx, block, m[1], sign * (abs(hours) * 60 + minutes))


def _huawei_timezone(m, block: Block, ctx: ParseContext) -> None:
    hours, minutes, seconds = int(m[3]), int(m[4]), int(m[5] or 0)
    if minutes > 59 or seconds != 0:  # Cisco offsets have no seconds
        ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
        return
    sign = -1 if m[2].lower() == "minus" else 1
    _store_timezone(ctx, block, m[1], sign * (hours * 60 + minutes))


cisco_clock = _single_line_handler(
    "cisco_clock", r"^clock\s+timezone\s+(\S+)\s+([+-]?\d{1,2})(?:\s+(\d{1,2}))?$", _cisco_timezone
)
huawei_clock = _single_line_handler(
    "huawei_clock", r"^clock\s+timezone\s+(\S+)\s+(add|minus)\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$", _huawei_timezone
)


def format_huawei_timezone(offset_minutes: int) -> str:
    """+420 -> 'add 07:00:00'; -330 -> 'minus 05:30:00'."""
    sign = "minus" if offset_minutes < 0 else "add"
    hours, minutes = divmod(abs(offset_minutes), 60)
    return f"{sign} {hours:02d}:{minutes:02d}:00"


def format_cisco_timezone(offset_minutes: int) -> str:
    """+420 -> '7 0'; -330 -> '-5 30'."""
    hours, minutes = divmod(abs(offset_minutes), 60)
    return f"{'-' if offset_minutes < 0 else ''}{hours} {minutes}"


# ----------------------------------------------------------------------------- SSH server

MAX_SSH_TIMEOUT = 120
MAX_SSH_RETRIES = 5


def _ssh(ctx: ParseContext) -> SshServerIR:
    if ctx.ir.ssh_server is None:
        ctx.ir.ssh_server = SshServerIR()
    return ctx.ir.ssh_server


def _ssh_version2(m, block: Block, ctx: ParseContext) -> None:
    ssh = _ssh(ctx)
    ssh.version2_only = True
    ssh.field_lines["version2_only"] = block.header.no
    ctx.rule(block.header, T)


def _ssh_number(attr: str, high: int):
    def apply(m, block: Block, ctx: ParseContext) -> None:
        value = int(m[1])
        if not 1 <= value <= high:
            ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
            return
        ssh = _ssh(ctx)
        setattr(ssh, attr, value)
        ssh.field_lines[attr] = block.header.no
        ctx.rule(block.header, D)

    return apply


cisco_ssh_version = _single_line_handler("cisco_ssh_version", r"^ip\s+ssh\s+version\s+2$", _ssh_version2)
cisco_ssh_timeout = _single_line_handler(
    "cisco_ssh_timeout", r"^ip\s+ssh\s+time-out\s+(\d+)$", _ssh_number("timeout", MAX_SSH_TIMEOUT)
)
cisco_ssh_retries = _single_line_handler(
    "cisco_ssh_retries", r"^ip\s+ssh\s+authentication-retries\s+(\d+)$", _ssh_number("auth_retries", MAX_SSH_RETRIES)
)
huawei_ssh_version = _single_line_handler(
    "huawei_ssh_version",
    r"^(?:ssh\s+server\s+compatible-ssh1x\s+disable|undo\s+ssh\s+server\s+compatible-ssh1x(?:\s+enable)?)$",
    _ssh_version2,
)
huawei_ssh_timeout = _single_line_handler(
    "huawei_ssh_timeout", r"^ssh\s+server\s+timeout\s+(\d+)$", _ssh_number("timeout", MAX_SSH_TIMEOUT)
)
huawei_ssh_retries = _single_line_handler(
    "huawei_ssh_retries",
    r"^ssh\s+server\s+authentication-retries\s+(\d+)$",
    _ssh_number("auth_retries", MAX_SSH_RETRIES),
)


# ----------------------------------------------------------------------------- DHCP snooping


def _snooping(ctx: ParseContext) -> DhcpSnoopingIR:
    if ctx.ir.dhcp_snooping is None:
        ctx.ir.dhcp_snooping = DhcpSnoopingIR()
    return ctx.ir.dhcp_snooping


def _snooping_global(m, block: Block, ctx: ParseContext) -> None:
    snooping = _snooping(ctx)
    snooping.enabled = True
    snooping.field_lines["enabled"] = block.header.no
    ctx.rule(block.header, D)


def _cisco_snooping_vlans(m, block: Block, ctx: ParseContext) -> None:
    ids = parse_cisco_vlan_list(m[1])
    if ids is None:
        ctx.unconverted(block.header, REASON_BAD_VALUE, ctx.ir.notes)
        return
    snooping = _snooping(ctx)
    snooping.vlans = sorted({*snooping.vlans, *ids})
    snooping.field_lines.setdefault("vlans", block.header.no)
    ctx.rule(block.header, S)


cisco_dhcp_snooping = _single_line_handler("cisco_dhcp_snooping", r"^ip\s+dhcp\s+snooping$", _snooping_global)
cisco_dhcp_snooping_vlan = _single_line_handler(
    "cisco_dhcp_snooping_vlan", r"^ip\s+dhcp\s+snooping\s+vlan\s+([\d,\-\s]+)$", _cisco_snooping_vlans
)
huawei_dhcp_snooping = _single_line_handler("huawei_dhcp_snooping", r"^dhcp\s+snooping\s+enable$", _snooping_global)


# ----------------------------------------------------------------------------- global STP BPDU protection


def _bpdu_protection(m, block: Block, ctx: ParseContext) -> None:
    ctx.ir.stp_bpdu_protection = True
    ctx.ir.field_lines["stp_bpdu_protection"] = block.header.no
    ctx.rule(block.header, D)


cisco_bpdu_protection = _single_line_handler(
    "cisco_bpdu_protection", r"^spanning-tree\s+portfast\s+(?:edge\s+)?bpduguard\s+default$", _bpdu_protection
)
huawei_bpdu_protection = _single_line_handler("huawei_bpdu_protection", r"^stp\s+bpdu-protection$", _bpdu_protection)


# ----------------------------------------------------------------------------- global STP mode / edge default


def _stp_mode_rstp(m, block: Block, ctx: ParseContext) -> None:
    ctx.ir.stp_mode = "rstp"
    ctx.ir.field_lines["stp_mode"] = block.header.no
    ctx.rule(block.header, T)


def _stp_edge_default(m, block: Block, ctx: ParseContext) -> None:
    ctx.ir.stp_edge_default = True
    ctx.ir.field_lines["stp_edge_default"] = block.header.no
    ctx.rule(block.header, D)


cisco_stp_mode = _single_line_handler("cisco_stp_mode", r"^spanning-tree\s+mode\s+rapid-pvst$", _stp_mode_rstp)
huawei_stp_mode = _single_line_handler("huawei_stp_mode", r"^stp\s+mode\s+rstp$", _stp_mode_rstp)
cisco_stp_edge_default = _single_line_handler(
    "cisco_stp_edge_default", r"^spanning-tree\s+portfast\s+(?:edge\s+)?default$", _stp_edge_default
)
huawei_stp_edge_default = _single_line_handler(
    "huawei_stp_edge_default", r"^stp\s+edged-port\s+default$", _stp_edge_default
)


# ----------------------------------------------------------------------------- VTY / SSH

_TRANSPORT_WORDS = {"ssh": {"ssh"}, "telnet": {"telnet"}, "all": {"ssh", "telnet"}}


def _vty_login_local(m, line, ctx, vty: VtyIR):
    _set(vty, "login_local", True, line, ctx)


def _vty_transport(m, line, ctx, vty: VtyIR):
    words = m[1].lower().split()
    if not words or any(w not in _TRANSPORT_WORDS for w in words) or ("all" in words and len(words) > 1):
        ctx.unconverted(line, REASON_NO_RULE, vty.notes)
        return
    protocols: set[str] = set()
    for w in words:
        protocols |= _TRANSPORT_WORDS[w]
    _set(vty, "transport", sorted(protocols), line, ctx)


_CISCO_VTY_RULES = compile_rules(
    [
        (r"^login\s+local$", _vty_login_local),
        (r"^login$", unconverted_rule(REASON_PASSWORD_LOGIN)),
        (r"^no\s+login$", unconverted_rule(REASON_NO_LOGIN)),
        (r"^transport\s+input\s+(.+)$", _vty_transport),
        (r"^access-class\s+\S+\s+(in|out)\b", unsupported_rule(FEATURE_VTY_ACL)),
    ]
) + [(pattern, not_needed_rule(reason)) for pattern, reason in CISCO_NOT_NEEDED_ANYWHERE] + CISCO_EXIT_RULES

_HUAWEI_VTY_RULES = compile_rules(
    [
        (r"^authentication-mode\s+aaa$", _vty_login_local),
        (r"^authentication-mode\s+password$", unconverted_rule(REASON_PASSWORD_LOGIN)),
        (r"^authentication-mode\s+none$", unconverted_rule(REASON_NO_LOGIN)),
        (r"^protocol\s+inbound\s+(ssh|telnet|all)$", _vty_transport),
        (r"^acl\s+\S+\s+(inbound|outbound)$", unsupported_rule(FEATURE_VTY_ACL)),
    ]
) + HUAWEI_EXIT_RULES


def _vty_handler(vendor: Vendor, header_re: str, rules: list[ChildRule], kind: str = "vty") -> BlockHandler:
    header = re.compile(header_re, re.IGNORECASE)

    def handler(block: Block, ctx: ParseContext) -> bool:
        m = header.match(block.header.body)
        if not m:
            return False
        first = int(m[1])
        last = int(m[2]) if m[2] else first
        if last < first:
            ctx.unconverted_block(block, REASON_BAD_VALUE, ctx.ir.notes)
            return True
        vty = VtyIR(kind=kind, first=first, last=last, source_lines=[block.header.no])
        ctx.ir.vty_lines.append(vty)
        ctx.rule(block.header, D)
        apply_child_rules(block, ctx, rules, vty, vty.notes)
        return True

    handler.__name__ = f"{'cisco' if vendor is Vendor.CISCO_IOS_XE else 'huawei'}_{kind}"
    return handler


cisco_vty = _vty_handler(Vendor.CISCO_IOS_XE, r"^line\s+vty\s+(\d+)(?:\s+(\d+))?$", _CISCO_VTY_RULES)
huawei_vty = _vty_handler(Vendor.HUAWEI_VRP, r"^user-interface\s+vty\s+(\d+)(?:\s+(\d+))?$", _HUAWEI_VTY_RULES)
cisco_console = _vty_handler(
    Vendor.CISCO_IOS_XE, r"^line\s+con(?:sole)?\s+(0)()$", _CISCO_VTY_RULES, kind="console"
)
huawei_console = _vty_handler(
    Vendor.HUAWEI_VRP, r"^user-interface\s+con(?:sole)?\s+(0)()$", _HUAWEI_VTY_RULES, kind="console"
)


def _huawei_service_switch(name: str, pattern: str, reason: str) -> BlockHandler:
    """Huawei global service switches with no Cisco command: "ไม่ต้องใช้คำสั่งนี้" + reason."""

    def apply(m, block: Block, ctx: ParseContext) -> None:
        ctx.not_needed(block.header, reason, ctx.ir.notes)

    return _single_line_handler(name, pattern, apply)


huawei_stelnet = _huawei_service_switch("huawei_stelnet", r"^stelnet\s+server\s+enable$", REASON_STELNET)
huawei_telnet = _huawei_service_switch("huawei_telnet", r"^telnet\s+server\s+enable$", REASON_TELNET_SERVER)
huawei_dhcp_service = _huawei_service_switch("huawei_dhcp_service", r"^dhcp\s+enable$", REASON_DHCP_SERVICE)

# Handlers for the RIP block before the generic single-line ones (no pattern overlap today).
CISCO_HANDLERS: list[BlockHandler] = [
    cisco_rip, cisco_default_gateway, cisco_ntp, cisco_syslog, cisco_vty, cisco_console,
    cisco_clock, cisco_ssh_version, cisco_ssh_timeout, cisco_ssh_retries,
    cisco_dhcp_snooping, cisco_dhcp_snooping_vlan, cisco_bpdu_protection,
    cisco_stp_mode, cisco_stp_edge_default,
]
HUAWEI_HANDLERS: list[BlockHandler] = [
    huawei_rip, huawei_ntp, huawei_syslog, huawei_vty, huawei_console, huawei_stelnet, huawei_telnet,
    huawei_clock, huawei_ssh_version, huawei_ssh_timeout, huawei_ssh_retries,
    huawei_dhcp_service, huawei_dhcp_snooping, huawei_bpdu_protection,
    huawei_stp_mode, huawei_stp_edge_default,
]
