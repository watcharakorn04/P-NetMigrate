"""Tier 3 — single-AS IPv4 BGP and IPv4 ACLs (proposal §2.3.1 items 1.3.4–1.3.5).

Both features fail SILENTLY on a device (it accepts the config and keeps running), so this
module refuses to emit anything that might change behaviour without saying so.

BGP (S — Huawei nests IPv4 unicast settings under `ipv4-family unicast`):
  router bgp <as>                      <-> bgp <as>
   bgp router-id <id>                  <-> router-id <id>
   neighbor <ip> remote-as <as>        <-> peer <ip> as-number <as>
   neighbor <ip> description <t>       <-> peer <ip> description <t>
   network <ip> [mask <m>]             <-> ipv4-family unicast / network <ip> <m>
   redistribute ... metric <m>         <-> ipv4-family unicast / import-route ... med <m>
   (implicit activation)               <-> ipv4-family unicast / peer <ip> enable
  Cisco activates neighbors automatically; Huawei does not. The Huawei renderer ALWAYS writes
  `ipv4-family unicast` + `peer <ip> enable`, labelled "ระบบสร้างขึ้นเอง" (§2.3.2 item 3).
  Not supported -> "แปลงไม่ได้": peer group, route reflector, confederation, route filtering,
  other address families, a second AS.

ACL (T):
  access-list <n> ... / ip access-list standard|extended <n|name>
      <-> acl number <n'> / acl name <name> basic|advance
  Numbers are mapped by TYPE, never copied (table below). A mapped number is labelled
  "ระบบสร้างขึ้นเอง" with a collision warning. Rule ids are renumbered 5, 10, ... keeping
  order (§2.3.2 item 8).
   permit|deny [ip|tcp|udp|icmp] <src> [port] [<dst> [port]]
      <-> rule <id> permit|deny [proto] [source <a> <w>] [source-port ..] [destination ..] [destination-port ..]
  Binding: ip access-group <acl> in|out <-> traffic-filter inbound|outbound acl [name] <acl>
  If any matching entry of an ACL cannot be converted, the WHOLE ACL and its bindings stay
  "แปลงไม่ได้": dropping one entry would silently change what the ACL filters.

  ACL number mapping — the neutral `ordinal` is the offset inside the Huawei range:
    | kind     | Cisco      | Huawei     | ordinal  |
    | basic    | 1–99       | 2000–2098  | 0–98     |
    | basic    | 1300–1999  | 2100–2799  | 100–799  |
    | advanced | 100–199    | 3000–3099  | 0–99     |
    | advanced | 2000–2699  | 3100–3799  | 100–799  |
  Huawei 2800–2999 / 3800–3999 have no Cisco number (§2.3.2 item 3). Cisco basic 1–99 has 99
  numbers but Huawei 2000–2099 has 100, so Huawei 2099 has no Cisco number either; aligning
  on 2000 (the most common Huawei basic ACL) keeps every other row of the table exact.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network
from typing import Optional

from app.core.ir import (
    ACL_ANY,
    AclAddressIR,
    AclEntryIR,
    AclIR,
    AclPortIR,
    AclRefIR,
    BgpIR,
    BgpNeighborIR,
    BgpNetworkIR,
    SyntaxCategory,
    Vendor,
)
from app.core.rules.base import (
    CISCO_EXIT_RULES,
    HUAWEI_EXIT_RULES,
    exit_word,
    view_exit,
    REASON_BAD_VALUE,
    REASON_NO_RULE,
    Block,
    BlockHandler,
    ChildRule,
    Line,
    LineKind,
    ParseContext,
    apply_child_rules,
    apply_line_rules,
    auto_ai_eligible,
    classful_prefix_len,
    compile_rules,
    not_needed_rule,
    out_of_scope_feature,
    parse_ipv4,
    parse_mask,
    reason_intentional,
    reason_not_supported,
    reason_out_of_scope,
    unsupported_rule,
)
from app.core.rules.tier2_services import CISCO_REDISTRIBUTE_RULES, HUAWEI_REDISTRIBUTE_RULES

S, T = SyntaxCategory.STRUCTURAL, SyntaxCategory.TRANSFORM

# ============================================================================= BGP

FEATURE_PEER_GROUP = "Peer Group"
FEATURE_RR = "Route Reflector"
FEATURE_CONFED = "Confederation"
FEATURE_FILTER = "การกรองเส้นทาง BGP (Route Filtering)"
FEATURE_OTHER_AF = "Address Family อื่นนอกจาก IPv4 Unicast"
REASON_BGP_MULTI_AS = reason_not_supported("BGP มากกว่าหนึ่ง AS (ระบบรองรับ AS เดียว)")
REASON_BGP_SYNC = "ปลายทางปิด synchronization ของ BGP เป็นค่าเริ่มต้นอยู่แล้ว"
REASON_BGP_AUTO_SUMMARY = "Huawei ปิด auto-summary ของ BGP เป็นค่าเริ่มต้นอยู่แล้ว"

MAX_ASN = 4294967295


def _asn(text: str) -> Optional[int]:
    return int(text) if text.isdigit() and 1 <= int(text) <= MAX_ASN else None


def _bgp_router_id(m, line, ctx, bgp: BgpIR):
    rid = parse_ipv4(m[1])
    if rid is None:
        ctx.unconverted(line, REASON_BAD_VALUE, bgp.notes)
        return
    bgp.router_id = rid
    bgp.field_lines["router_id"] = line.no
    ctx.rule(line, S)


_PEER_GROUP_REASON = reason_not_supported(FEATURE_PEER_GROUP)


def _neighbor_remote_as(m, line, ctx, bgp: BgpIR):
    address = parse_ipv4(m[1])
    if address is None:  # a peer-group name in place of an address
        ctx.unconverted(line, _PEER_GROUP_REASON, bgp.notes)
        return
    asn = _asn(m[2])
    if asn is None:
        ctx.unconverted(line, REASON_BAD_VALUE, bgp.notes)
        return
    neighbor = bgp.neighbor(address)
    if neighbor is None:
        bgp.neighbors.append(BgpNeighborIR(address=address, remote_as=asn, source_line=line.no))
    else:
        neighbor.remote_as = asn
    ctx.rule(line, S)


def _neighbor_description(m, line, ctx, bgp: BgpIR):
    address = parse_ipv4(m[1])
    neighbor = bgp.neighbor(address) if address is not None else None
    if neighbor is None:
        ctx.unconverted(line, REASON_NO_RULE, bgp.notes)
        return
    neighbor.description = m[2]
    neighbor.field_lines["description"] = line.no
    ctx.rule(line, S)


def _activate(m, line, ctx, bgp: BgpIR):
    address = parse_ipv4(m[1])
    if address is None:
        ctx.unconverted(line, _PEER_GROUP_REASON, bgp.notes)
        return
    ctx.data.setdefault("bgp_activated", set()).add(address)
    ctx.rule(line, S)


def _no_default_ipv4(m, line, ctx, bgp: BgpIR):
    ctx.data["bgp_no_default_ipv4"] = True
    ctx.rule(line, S)


def _bgp_network(allow_prefix_len: bool):
    def fn(m, line, ctx, bgp: BgpIR):
        address = parse_ipv4(m[1])
        plen = None
        if address is not None:
            plen = parse_mask(m[2], allow_prefix_len) if m[2] else classful_prefix_len(address)
        if plen is None:
            ctx.unconverted(line, REASON_BAD_VALUE, bgp.notes)
            return
        prefix = IPv4Network(f"{address}/{plen}", strict=False)
        if all(n.prefix != prefix for n in bgp.networks):
            bgp.networks.append(BgpNetworkIR(prefix=prefix, source_line=line.no))
        ctx.rule(line, S)

    return fn


def _structural_ok(m, line, ctx, bgp: BgpIR):
    ctx.rule(line, S)


_CISCO_BGP_RULES = compile_rules(
    [
        (r"^bgp\s+router-id\s+(\S+)$", _bgp_router_id),
        (r"^neighbor\s+(\S+)\s+remote-as\s+(\S+)$", _neighbor_remote_as),
        (r"^neighbor\s+(\S+)\s+description\s+(.+)$", _neighbor_description),
        (r"^neighbor\s+(\S+)\s+activate$", _activate),
        (r"^neighbor\s+\S+\s+peer-group\b", unsupported_rule(FEATURE_PEER_GROUP)),
        (r"^neighbor\s+\S+\s+route-reflector-client$", unsupported_rule(FEATURE_RR)),
        (r"^bgp\s+cluster-id\b", unsupported_rule(FEATURE_RR)),
        (r"^bgp\s+confederation\b", unsupported_rule(FEATURE_CONFED)),
        (r"^neighbor\s+\S+\s+(prefix-list|distribute-list|filter-list)\b", unsupported_rule(FEATURE_FILTER)),
        (r"^distribute-list\b", unsupported_rule(FEATURE_FILTER)),
        (r"^network\s+(\S+)(?:\s+mask\s+(\S+))?$", _bgp_network(False)),
        (r"^no\s+bgp\s+default\s+ipv4-unicast$", _no_default_ipv4),
        (r"^no\s+synchronization$", not_needed_rule(REASON_BGP_SYNC)),
        (r"^no\s+auto-summary$", not_needed_rule(REASON_BGP_AUTO_SUMMARY)),
        (r"^exit-address-family$", _structural_ok),
    ]
) + CISCO_REDISTRIBUTE_RULES + CISCO_EXIT_RULES

_HUAWEI_BGP_RULES = compile_rules(
    [
        (r"^router-id\s+(\S+)$", _bgp_router_id),
        (r"^peer\s+(\S+)\s+as-number\s+(\S+)$", _neighbor_remote_as),
        (r"^peer\s+(\S+)\s+description\s+(.+)$", _neighbor_description),
        (r"^peer\s+(\S+)\s+enable$", _activate),
        (r"^group\s+\S+", unsupported_rule(FEATURE_PEER_GROUP)),
        (r"^peer\s+\S+\s+group\b", unsupported_rule(FEATURE_PEER_GROUP)),
        (r"^peer\s+\S+\s+reflect-client$", unsupported_rule(FEATURE_RR)),
        (r"^reflector\s+cluster-id\b", unsupported_rule(FEATURE_RR)),
        (r"^confederation\b", unsupported_rule(FEATURE_CONFED)),
        (r"^peer\s+\S+\s+(ip-prefix|filter-policy|as-path-filter|acl)\b", unsupported_rule(FEATURE_FILTER)),
        (r"^filter-policy\b", unsupported_rule(FEATURE_FILTER)),
        (r"^network\s+(\S+)(?:\s+(\S+))?$", _bgp_network(True)),
        (r"^undo\s+synchronization$", not_needed_rule(REASON_BGP_SYNC)),
    ]
) + HUAWEI_REDISTRIBUTE_RULES + HUAWEI_EXIT_RULES

_CISCO_IPV4_AF = re.compile(r"^address-family\s+ipv4(\s+unicast)?$", re.IGNORECASE)
_CISCO_OTHER_AF = re.compile(r"^address-family\b", re.IGNORECASE)
_HUAWEI_IPV4_AF = re.compile(r"^ipv4-family\s+unicast$", re.IGNORECASE)
_HUAWEI_OTHER_AF = re.compile(r"^(\S+-family|evpn)\b", re.IGNORECASE)


def _finalize_bgp(ctx: ParseContext) -> None:
    """Resolve IPv4-unicast activation once the whole BGP block is known."""
    bgp = ctx.ir.bgp
    if bgp is None:
        return
    activated = ctx.data.get("bgp_activated", set())
    implicit = ctx.vendor is Vendor.CISCO_IOS_XE and not ctx.data.get("bgp_no_default_ipv4", False)
    for neighbor in bgp.neighbors:
        neighbor.enabled = implicit or neighbor.address in activated


def _bgp_handler(vendor: Vendor, header_re: str, rules: list[ChildRule], ipv4_af: re.Pattern, other_af: re.Pattern):
    header = re.compile(header_re, re.IGNORECASE)
    other_af_reason = reason_not_supported(FEATURE_OTHER_AF)

    def handler(block: Block, ctx: ParseContext) -> bool:
        m = header.match(block.header.body)
        if not m:
            return False
        asn = _asn(m[1])
        if asn is None:
            ctx.unconverted_block(block, REASON_BAD_VALUE, ctx.ir.notes)
            return True
        if ctx.ir.bgp is not None and ctx.ir.bgp.asn != asn:
            ctx.unconverted_block(block, REASON_BGP_MULTI_AS, ctx.ir.notes)
            return True
        if ctx.ir.bgp is None:
            ctx.ir.bgp = BgpIR(asn=asn)
        bgp = ctx.ir.bgp
        bgp.source_lines.append(block.header.no)
        ctx.add_finalizer(_finalize_bgp)
        ctx.rule(block.header, S)
        for child in block.children:
            body = child.header.body
            feature = out_of_scope_feature(body)
            if feature:
                ctx.unconverted_block(child, reason_out_of_scope(feature), bgp.notes)
            elif ipv4_af.match(body):
                ctx.rule(child.header, S)
                apply_child_rules(child, ctx, rules, bgp, bgp.notes)
            elif other_af.match(body):
                ctx.unconverted_block(child, other_af_reason, bgp.notes)
            else:
                apply_line_rules(child, ctx, rules, bgp, bgp.notes)
        return True

    handler.__name__ = f"{'cisco' if vendor is Vendor.CISCO_IOS_XE else 'huawei'}_bgp"
    return handler


cisco_bgp = _bgp_handler(Vendor.CISCO_IOS_XE, r"^router\s+bgp\s+(\S+)$", _CISCO_BGP_RULES, _CISCO_IPV4_AF, _CISCO_OTHER_AF)
huawei_bgp = _bgp_handler(Vendor.HUAWEI_VRP, r"^bgp\s+(\S+)$", _HUAWEI_BGP_RULES, _HUAWEI_IPV4_AF, _HUAWEI_OTHER_AF)


# ============================================================================= ACL numbers

BASIC, ADVANCED = "basic", "advanced"
_HUAWEI_BASE = {BASIC: 2000, ADVANCED: 3000}
# (cisco_lo, cisco_hi, ordinal_lo) per kind — rows of the proposal's table
_CISCO_ROWS = {BASIC: ((1, 99, 0), (1300, 1999, 100)), ADVANCED: ((100, 199, 0), (2000, 2699, 100))}

FEATURE_L2_ACL = "ACL ชั้นที่ 2 หรือ ACL ที่ไม่ใช่ IPv4 (Layer 2 / non-IPv4 ACL)"
FEATURE_USER_DEFINED = "User-Defined ACL / User ACL"
FEATURE_TIME_RANGE = "Time Range"
FEATURE_MATCH_AUTO = "match-order auto (ลำดับการตรวจกฎอัตโนมัติ)"
REASON_ACL_RANGE_GAP = reason_intentional(
    "ช่วงหมายเลข ACL นี้ของ Huawei ไม่มีช่วงหมายเลขที่ตรงกันฝั่ง Cisco "
    "(Huawei 2800–2999, 3800–3999 และ 2099 อยู่นอกช่วงของ Cisco ซึ่งแคบกว่า) — เป็นข้อกำหนดของผู้ผลิต"
)
REASON_ACL_PARTIAL = reason_intentional(
    "ACL นี้มีบางกฎที่แปลงไม่ได้ จึงไม่แปลงทั้งชุด เพราะการตัดกฎบางข้อออกจะทำให้ผลการกรองเปลี่ยนโดยไม่มีอะไรเตือน"
)
REASON_ACL_BINDING_DROPPED = reason_intentional(
    "ACL ที่ผูกไว้ไม่ได้ถูกแปลง จึงไม่แปลงคำสั่งผูกนี้ เพื่อไม่ให้ผูกกับ ACL ที่ไม่มีอยู่หรือไม่ครบ"
)
REASON_ACL_REMARK = "หมายเหตุของ ACL ไม่มีคำสั่งที่ตรงกันโดยตรง จึงเก็บไว้เป็น Comment (ไม่มีผลต่อการกรอง)"
REASON_ACL_STEP = "ระบบไล่หมายเลขกฎใหม่ให้อยู่แล้ว และ Cisco ไม่มีคำสั่ง step"
REASON_ACL_KIND_CONFLICT = "ชื่อ ACL นี้ถูกใช้กับ ACL คนละชนิด (basic/advanced)"


def cisco_number_to_ordinal(number: int) -> Optional[tuple[str, int]]:
    for kind, rows in _CISCO_ROWS.items():
        for lo, hi, ord_lo in rows:
            if lo <= number <= hi:
                return kind, ord_lo + number - lo
    return None


def cisco_number(kind: str, ordinal: int) -> Optional[int]:
    """Cisco ACL number for a neutral ordinal; None when Cisco has no number for it."""
    for lo, hi, ord_lo in _CISCO_ROWS[kind]:
        if ord_lo <= ordinal <= ord_lo + hi - lo:
            return lo + ordinal - ord_lo
    return None


def huawei_number(kind: str, ordinal: int) -> int:
    return _HUAWEI_BASE[kind] + ordinal


def huawei_number_to_ordinal(number: int) -> Optional[tuple[str, int]]:
    for kind, base in _HUAWEI_BASE.items():
        if base <= number < base + 1000:
            return kind, number - base
    return None


# Cisco numbers outside the IPv4 standard/extended ranges (200-299, 700-799, 1100-1199, ...).
REASON_CISCO_NON_IP_ACL = reason_not_supported(FEATURE_L2_ACL)


def _huawei_number_problem(number: int) -> Optional[str]:
    """Reason a Huawei ACL number cannot be converted to Cisco; None if it can."""
    mapped = huawei_number_to_ordinal(number)
    if mapped is not None:
        return None if cisco_number(*mapped) is not None else REASON_ACL_RANGE_GAP
    if 4000 <= number <= 4999:
        return reason_not_supported(FEATURE_L2_ACL)
    if number >= 5000:
        return reason_not_supported(FEATURE_USER_DEFINED)
    return REASON_BAD_VALUE


# ============================================================================= ACL entries

TCP_PORT_NAMES = {
    "bgp": 179, "chargen": 19, "cmd": 514, "daytime": 13, "discard": 9, "domain": 53, "echo": 7,
    "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113,
    "irc": 194, "klogin": 543, "kshell": 544, "login": 513, "lpd": 515, "nntp": 119, "pop2": 109,
    "pop3": 110, "smtp": 25, "sunrpc": 111, "tacacs": 49, "talk": 517, "telnet": 23, "time": 37,
    "uucp": 540, "whois": 43, "www": 80,
}
UDP_PORT_NAMES = {
    "biff": 512, "bootpc": 68, "bootps": 67, "discard": 9, "dns": 53, "domain": 53, "echo": 7,
    "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139,
    "netbios-ssn": 139, "ntp": 123, "rip": 520, "snmp": 161, "snmptrap": 162, "sunrpc": 111,
    "syslog": 514, "tacacs": 49, "talk": 517, "tftp": 69, "time": 37, "who": 513, "xdmcp": 177,
}
_PORT_NAMES = {"tcp": TCP_PORT_NAMES, "udp": UDP_PORT_NAMES}
_PORT_OPS = {"eq": 1, "gt": 1, "lt": 1, "range": 2}
_PROTOCOLS = ("ip", "tcp", "udp", "icmp")


class _EntryError(Exception):
    def __init__(self, reason: str = REASON_NO_RULE):
        self.reason = reason


class _Tokens:
    def __init__(self, text: str):
        self.items = text.split()
        self.i = 0

    def peek(self, offset: int = 0) -> Optional[str]:
        j = self.i + offset
        return self.items[j].lower() if j < len(self.items) else None

    def take(self) -> str:
        if self.i >= len(self.items):
            raise _EntryError()
        self.i += 1
        return self.items[self.i - 1]

    def done(self) -> bool:
        return self.i >= len(self.items)

    def rest_reason(self) -> str:
        rest = [t.lower() for t in self.items[self.i :]]
        return reason_not_supported(FEATURE_TIME_RANGE) if "time-range" in rest else REASON_NO_RULE


def _ip_or_fail(text: str) -> IPv4Address:
    ip = parse_ipv4(text)
    if ip is None:
        raise _EntryError(REASON_BAD_VALUE)
    return ip


def _port_value(text: str, protocol: str) -> int:
    if text.isdigit():
        if int(text) > 65535:
            raise _EntryError(REASON_BAD_VALUE)
        return int(text)
    value = _PORT_NAMES[protocol].get(text.lower())
    if value is None:
        raise _EntryError(f"ไม่รู้จักชื่อพอร์ต {text} — กรุณาใช้หมายเลขพอร์ต")
    return value


def _parse_port(tok: _Tokens, protocol: Optional[str]) -> Optional[AclPortIR]:
    op = tok.peek()
    if op not in _PORT_OPS and op != "neq":
        return None
    if protocol not in _PORT_NAMES:
        raise _EntryError()
    if op == "neq":
        raise _EntryError()  # Huawei has no "not equal" port operator
    tok.take()
    ports = [_port_value(tok.take(), protocol) for _ in range(_PORT_OPS[op])]
    if op == "range" and ports[0] > ports[1]:
        raise _EntryError(REASON_BAD_VALUE)
    return AclPortIR(operator=op, ports=ports)


def _cisco_address(tok: _Tokens, implicit_host: bool) -> AclAddressIR:
    word = tok.peek()
    if word is None:
        raise _EntryError()
    if word == "any":
        tok.take()
        return ACL_ANY
    if word == "host":
        tok.take()
        return AclAddressIR(address=_ip_or_fail(tok.take()), wildcard=IPv4Address("0.0.0.0"))
    address = _ip_or_fail(tok.take())
    nxt = tok.peek()
    if implicit_host and (nxt is None or parse_ipv4(nxt) is None):
        return AclAddressIR(address=address, wildcard=IPv4Address("0.0.0.0"))
    return AclAddressIR(address=address, wildcard=_ip_or_fail(tok.take()))


def parse_cisco_entry(text: str, kind: str) -> AclEntryIR:
    """'permit tcp any host 1.1.1.1 eq 80' -> AclEntryIR. Raises _EntryError."""
    tok = _Tokens(text)
    action = tok.take().lower()
    if action not in ("permit", "deny"):
        raise _EntryError()
    if kind == BASIC:
        entry = AclEntryIR(action=action, source=_cisco_address(tok, implicit_host=True))
    else:
        protocol = tok.take().lower()
        if protocol not in _PROTOCOLS:
            raise _EntryError()
        source = _cisco_address(tok, implicit_host=False)
        source_port = _parse_port(tok, protocol)
        destination = _cisco_address(tok, implicit_host=False)
        destination_port = _parse_port(tok, protocol)
        entry = AclEntryIR(
            action=action, protocol=protocol, source=source, source_port=source_port,
            destination=destination, destination_port=destination_port,
        )
    if not tok.done():
        raise _EntryError(tok.rest_reason())
    return entry


def _huawei_address(tok: _Tokens) -> AclAddressIR:
    if tok.peek() == "any":
        tok.take()
        return ACL_ANY
    address = _ip_or_fail(tok.take())
    wildcard_text = tok.take()
    wildcard = IPv4Address("0.0.0.0") if wildcard_text == "0" else _ip_or_fail(wildcard_text)
    return AclAddressIR(address=address, wildcard=wildcard)


def parse_huawei_rule(text: str, kind: str) -> tuple[Optional[int], AclEntryIR]:
    """'[<id>] permit tcp source ... destination-port eq 80' -> (id, entry). Raises _EntryError."""
    tok = _Tokens(text)
    rule_id = int(tok.take()) if (tok.peek() or "").isdigit() else None
    action = tok.take().lower()
    if action not in ("permit", "deny"):
        raise _EntryError()
    protocol = None
    if kind == ADVANCED:
        protocol = tok.take().lower()
        if protocol not in _PROTOCOLS:
            raise _EntryError()
    fields: dict = {}
    allowed = {"source"} if kind == BASIC else {"source", "destination", "source-port", "destination-port"}
    while not tok.done():
        word = tok.peek()
        if word not in allowed or word in fields:
            raise _EntryError(tok.rest_reason())
        tok.take()
        if word in ("source", "destination"):
            fields[word] = _huawei_address(tok)
        else:
            port = _parse_port(tok, protocol)
            if port is None:
                raise _EntryError()
            fields[word] = port
    entry = AclEntryIR(
        action=action,
        protocol=protocol,
        source=fields.get("source", ACL_ANY),
        source_port=fields.get("source-port"),
        destination=fields.get("destination", ACL_ANY) if kind == ADVANCED else None,
        destination_port=fields.get("destination-port"),
    )
    return rule_id, entry


# ----------------------------------------------------------------------------- entry formatting (renderers)


def _cisco_addr(a: AclAddressIR) -> str:
    if a.is_any:
        return "any"
    if a.is_host:
        return f"host {a.address}"
    return f"{a.address} {a.wildcard}"


def _port_text(p: Optional[AclPortIR]) -> list[str]:
    return [p.operator, *map(str, p.ports)] if p else []


def format_cisco_entry(e: AclEntryIR) -> str:
    parts = [e.action]
    if e.protocol:
        parts.append(e.protocol)
    parts += [_cisco_addr(e.source), *_port_text(e.source_port)]
    if e.destination is not None:
        parts += [_cisco_addr(e.destination), *_port_text(e.destination_port)]
    return " ".join(parts)


def _huawei_addr(keyword: str, a: AclAddressIR) -> list[str]:
    if a.is_any:
        return []
    return [keyword, str(a.address), "0" if a.is_host else str(a.wildcard)]


def format_huawei_rule(e: AclEntryIR) -> str:
    parts = [e.action]
    if e.protocol:
        parts.append(e.protocol)
    parts += _huawei_addr("source", e.source)
    if e.source_port:
        parts += ["source-port", *_port_text(e.source_port)]
    if e.destination is not None:
        parts += _huawei_addr("destination", e.destination)
    if e.destination_port:
        parts += ["destination-port", *_port_text(e.destination_port)]
    return " ".join(parts)


# ----------------------------------------------------------------------------- ACL IR helpers


def _get_acl(ctx: ParseContext, kind: str, ordinal: Optional[int], name: Optional[str], line: Line) -> Optional[AclIR]:
    acl = AclIR(kind=kind, ordinal=ordinal, name=name)
    existing = ctx.ir.acl(acl.key)
    if existing is not None:
        if existing.kind != kind:
            return None
        acl = existing
    else:
        ctx.ir.acls.append(acl)
    acl.source_lines.append(line.no)
    ctx.add_finalizer(_finalize_acls)
    return acl


def _track_block(ctx: ParseContext, acl: AclIR, block: Block) -> None:
    """Remember every source line of the ACL block(s), so a rejected ACL can lock all of them."""
    lines: dict = ctx.data.setdefault("acl_block_lines", {})
    lines.setdefault(acl.key, set()).update(l.no for l in block.lines())


def _mark_partial(ctx: ParseContext, acl: AclIR) -> None:
    ctx.data.setdefault("acl_partial", set()).add(acl.key)


def _next_sequence(acl: AclIR, step: int) -> int:
    return max((e.sequence for e in acl.entries), default=0) + step


def _add_entry(ctx: ParseContext, acl: AclIR, line: Line, parse, text: str, explicit_seq: Optional[int], step: int):
    try:
        result = parse(text, acl.kind)
    except _EntryError as err:
        ctx.unconverted(line, err.reason, acl.notes)
        _mark_partial(ctx, acl)
        return
    seq, entry = result if isinstance(result, tuple) else (explicit_seq, result)
    entry.sequence = seq if seq is not None else _next_sequence(acl, step)
    entry.source_line = line.no
    acl.entries.append(entry)
    ctx.rule(line, T)


def _finalize_acls(ctx: ParseContext) -> None:
    """Order entries; unconvert any ACL with a failed entry, plus the bindings that use it."""
    partial = ctx.data.get("acl_partial", set())
    dropped = set()
    for acl in list(ctx.ir.acls):
        acl.entries.sort(key=lambda e: e.sequence)
        if acl.key not in partial:
            continue
        lines = set(acl.source_lines) | {e.source_line for e in acl.entries}
        lines |= ctx.data.get("acl_block_lines", {}).get(acl.key, set())
        for no in sorted(lines):
            status = ctx.status.get(no)
            if status is None:
                continue
            if status.kind is LineKind.RULE:
                ctx.demote(no, REASON_ACL_PARTIAL, ctx.ir.notes)
            elif status.kind is LineKind.UNCONVERTED and auto_ai_eligible(status.reason):
                # Block-skip boundary: the failing entry itself (e.g. `deny ip any any log`) and
                # every other line of a rejected ACL are locked too, so hybrid never sends a
                # fragment of the ACL to AI (a stray `rule deny ...` would land in system-view).
                status.reason = f"{REASON_ACL_PARTIAL} ({status.reason})"
                for note in acl.notes:
                    if note.source_line == no:
                        note.reason = status.reason
        ctx.ir.notes.extend(acl.notes)
        ctx.ir.acls.remove(acl)
        dropped.add(acl.key)
    if not dropped:
        return
    for iface in ctx.ir.interfaces:
        for attr in ("acl_in", "acl_out"):
            ref = getattr(iface, attr)
            if ref is not None and ref.key in dropped:
                setattr(iface, attr, None)
                ctx.demote(iface.field_lines.pop(attr), REASON_ACL_BINDING_DROPPED, iface.notes)
        iface.notes.sort(key=lambda n: n.source_line)


# ----------------------------------------------------------------------------- ACL: Cisco

_CISCO_NUMBERED = re.compile(r"^access-list\s+(\d+)\s+(.+)$", re.IGNORECASE)
_CISCO_NAMED = re.compile(r"^ip\s+access-list\s+(standard|extended)\s+(\S+)$", re.IGNORECASE)
_CISCO_SEQ_ENTRY = re.compile(r"^(?:(\d+)\s+)?(permit|deny)\b\s*(.*)$", re.IGNORECASE)
_REMARK = re.compile(r"^(?:\d+\s+)?remark\b", re.IGNORECASE)
_CISCO_KIND = {"standard": BASIC, "extended": ADVANCED}


def cisco_acl_numbered(block: Block, ctx: ParseContext) -> bool:
    m = _CISCO_NUMBERED.match(block.header.body)
    if not m:
        return False
    line = block.header
    mapped = cisco_number_to_ordinal(int(m[1]))
    if mapped is None:
        ctx.unconverted_block(block, REASON_CISCO_NON_IP_ACL, ctx.ir.notes)
        return True
    acl = _get_acl(ctx, mapped[0], mapped[1], None, line)
    if acl is None:
        ctx.unconverted_block(block, REASON_ACL_KIND_CONFLICT, ctx.ir.notes)
        return True
    _track_block(ctx, acl, block)
    ctx.unconverted_children(block, REASON_NO_RULE, acl.notes)
    if _REMARK.match(m[2]):
        ctx.unconverted(line, REASON_ACL_REMARK, acl.notes)
    else:
        _add_entry(ctx, acl, line, parse_cisco_entry, m[2], None, 10)
    return True


def cisco_acl_named(block: Block, ctx: ParseContext) -> bool:
    m = _CISCO_NAMED.match(block.header.body)
    if not m:
        return False
    kind, ident = _CISCO_KIND[m[1].lower()], m[2]
    ordinal, name = None, ident
    if ident.isdigit():
        mapped = cisco_number_to_ordinal(int(ident))
        if mapped is None or mapped[0] != kind:
            ctx.unconverted_block(block, REASON_BAD_VALUE, ctx.ir.notes)
            return True
        ordinal, name = mapped[1], None
    acl = _get_acl(ctx, kind, ordinal, name, block.header)
    if acl is None:
        ctx.unconverted_block(block, REASON_ACL_KIND_CONFLICT, ctx.ir.notes)
        return True
    _track_block(ctx, acl, block)
    ctx.rule(block.header, T)
    for child in block.children:
        body = child.header.body
        for grandchild in child.children:
            ctx.unconverted_block(grandchild, REASON_NO_RULE, acl.notes)
        if body.lower() == exit_word(ctx.vendor):
            view_exit(None, child.header, ctx, acl)
            continue
        if _REMARK.match(body):
            ctx.unconverted(child.header, REASON_ACL_REMARK, acl.notes)
            continue
        em = _CISCO_SEQ_ENTRY.match(body)
        if em is None:
            ctx.unconverted(child.header, REASON_NO_RULE, acl.notes)
            _mark_partial(ctx, acl)
            continue
        seq = int(em[1]) if em[1] else None
        _add_entry(ctx, acl, child.header, parse_cisco_entry, f"{em[2]} {em[3]}", seq, 10)
    return True


def _unsupported_block(name: str, pattern: str, reason: str) -> BlockHandler:
    regex = re.compile(pattern, re.IGNORECASE)

    def handler(block: Block, ctx: ParseContext) -> bool:
        if not regex.match(block.header.body):
            return False
        ctx.unconverted_block(block, reason, ctx.ir.notes)
        return True

    handler.__name__ = name
    return handler


cisco_mac_acl = _unsupported_block("cisco_mac_acl", r"^mac\s+access-list\b", reason_not_supported(FEATURE_L2_ACL))
cisco_time_range = _unsupported_block("cisco_time_range", r"^time-range\b", reason_not_supported(FEATURE_TIME_RANGE))


# ----------------------------------------------------------------------------- ACL: Huawei

_HUAWEI_NUMBERED = re.compile(r"^acl\s+(?:number\s+)?(\d+)(?:\s+match-order\s+(config|auto))?$", re.IGNORECASE)
_HUAWEI_NAMED = re.compile(r"^acl\s+name\s+(\S+)\s+(basic|advance|link|user)(?:\s+match-order\s+(config|auto))?$", re.IGNORECASE)
_HUAWEI_RULE = re.compile(r"^rule\s+(.+)$", re.IGNORECASE)
_HUAWEI_KIND = {"basic": BASIC, "advance": ADVANCED}


def _huawei_acl_body(block: Block, ctx: ParseContext, acl: AclIR) -> None:
    ctx.rule(block.header, T)
    for child in block.children:
        body = child.header.body
        for grandchild in child.children:
            ctx.unconverted_block(grandchild, REASON_NO_RULE, acl.notes)
        if body.lower() == exit_word(ctx.vendor):
            view_exit(None, child.header, ctx, acl)
        elif re.match(r"^step\s+\d+$", body, re.IGNORECASE):
            ctx.not_needed(child.header, REASON_ACL_STEP, acl.notes)
        elif re.match(r"^description\b", body, re.IGNORECASE):
            ctx.unconverted(child.header, REASON_ACL_REMARK, acl.notes)
        elif rm := _HUAWEI_RULE.match(body):
            _add_entry(ctx, acl, child.header, parse_huawei_rule, rm[1], None, 5)
        else:
            ctx.unconverted(child.header, REASON_NO_RULE, acl.notes)
            _mark_partial(ctx, acl)


def huawei_acl(block: Block, ctx: ParseContext) -> bool:
    body = block.header.body
    if m := _HUAWEI_NUMBERED.match(body):
        number, order = int(m[1]), m[2]
        problem = _huawei_number_problem(number)
        mapped = huawei_number_to_ordinal(number)
        kind, ordinal, name = (mapped[0], mapped[1], None) if mapped else (None, None, None)
    elif m := _HUAWEI_NAMED.match(body):
        flavour, order = m[2].lower(), m[3]
        problem = {
            "link": reason_not_supported(FEATURE_L2_ACL),
            "user": reason_not_supported(FEATURE_USER_DEFINED),
        }.get(flavour)
        kind, ordinal, name = _HUAWEI_KIND.get(flavour), None, m[1]
    else:
        return False
    if problem is None and order and order.lower() == "auto":
        problem = reason_not_supported(FEATURE_MATCH_AUTO)
    if problem is not None:
        ctx.unconverted_block(block, problem, ctx.ir.notes)
        return True
    acl = _get_acl(ctx, kind, ordinal, name, block.header)
    if acl is None:
        ctx.unconverted_block(block, REASON_ACL_KIND_CONFLICT, ctx.ir.notes)
        return True
    _track_block(ctx, acl, block)
    _huawei_acl_body(block, ctx, acl)
    return True


huawei_time_range = _unsupported_block("huawei_time_range", r"^time-range\b", reason_not_supported(FEATURE_TIME_RANGE))


# ----------------------------------------------------------------------------- interface binding


def _bind(iface, direction: str, ref: AclRefIR, line: Line, ctx: ParseContext) -> None:
    attr = "acl_in" if direction.lower() in ("in", "inbound") else "acl_out"
    setattr(iface, attr, ref)
    iface.field_lines[attr] = line.no
    ctx.rule(line, T)


def _cisco_access_group(m, line, ctx, iface):
    ident, direction = m[1], m[2]
    if ident.isdigit():
        mapped = cisco_number_to_ordinal(int(ident))
        if mapped is None:
            ctx.unconverted(line, REASON_CISCO_NON_IP_ACL, iface.notes)
            return
        ref = AclRefIR(kind=mapped[0], ordinal=mapped[1])
    else:
        ref = AclRefIR(name=ident)
    _bind(iface, direction, ref, line, ctx)


def _huawei_traffic_filter(m, line, ctx, iface):
    direction, name, number = m[1], m[2], m[3]
    if name:
        ref = AclRefIR(name=name)
    else:
        problem = _huawei_number_problem(int(number))
        if problem is not None:
            ctx.unconverted(line, problem, iface.notes)
            return
        kind, ordinal = huawei_number_to_ordinal(int(number))
        ref = AclRefIR(kind=kind, ordinal=ordinal)
    _bind(iface, direction, ref, line, ctx)


CISCO_ACL_INTERFACE_RULES: list[ChildRule] = compile_rules(
    [(r"^ip\s+access-group\s+(\S+)\s+(in|out)$", _cisco_access_group)]
)
HUAWEI_ACL_INTERFACE_RULES: list[ChildRule] = compile_rules(
    [(r"^traffic-filter\s+(inbound|outbound)\s+acl\s+(?:name\s+(\S+)|(\d+))$", _huawei_traffic_filter)]
)

CISCO_HANDLERS: list[BlockHandler] = [cisco_bgp, cisco_acl_numbered, cisco_acl_named, cisco_mac_acl, cisco_time_range]
HUAWEI_HANDLERS: list[BlockHandler] = [huawei_bgp, huawei_acl, huawei_time_range]
