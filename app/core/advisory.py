"""Configuration advisory (proposal §2.3.1 module 7.3–7.6).

Three cumulative levels, rendered for Cisco IOS-XE AND Huawei VRP side by side:
  1 Basic        — VLANs, port modes, IP addressing, routing, remote management (SSH)
  2 Intermediate — QoS: classify/mark, trust boundary, queueing, rate limit on inter-device links
  3 Advanced     — security: port-security MAC limit, root guard, DHCP snooping, inter-subnet
                   ACL, shut unused ports, hardened management access

Level 1 re-uses the real renderers on the device's own IR (so the values are exact). Levels 2
and 3 are templates prepared in advance (7.5) filled with the device's real VLAN ids and port
names. Every suggestion is only a proposal (7.6): it is never sent to a device by the system,
and no template contains a credential. Port numbers are never translated (§2.3.2 item 4).
"""

from __future__ import annotations

from ipaddress import IPv4Network
from typing import Optional

from app.core.hardware import PortState, port_state
from app.core.ir import DeviceConfigIR, InterfaceIR, Vendor
from app.core.renderers import render_config
from app.core.rules.interface_names import display_name

LEVELS = (1, 2, 3)
C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP
HEADER = {
    1: ("ระดับ 1 พื้นฐาน — ทำให้เครือข่ายใช้งานได้", "Level 1 Basic — make the network work"),
    2: ("ระดับ 2 ปานกลาง — คุณภาพการใช้งาน (QoS)", "Level 2 Intermediate — quality of service"),
    3: ("ระดับ 3 ขั้นสูง — ความปลอดภัย", "Level 3 Advanced — security"),
}
REVIEW_NOTE = "ข้อเสนอแนะจากแม่แบบ ต้องตรวจสอบกับคู่มือผู้ผลิตก่อนใช้ — ระบบไม่ส่งไปตั้งค่าบนอุปกรณ์ให้เอง"


def _c(vendor: Vendor, text: str) -> str:
    return f"{vendor.comment_marker} {text}"


def _wild(net: IPv4Network) -> str:
    return str(net.hostmask)


def _names(ifaces: list[InterfaceIR], vendor: Vendor) -> list[str]:
    return [display_name(i.ref, vendor) for i in ifaces]


class _Facts:
    def __init__(self, ir: DeviceConfigIR, uplinks: set[str], vendor_of_names: Vendor):
        phys = [i for i in ir.interfaces if not i.is_virtual]
        self.ir = ir
        self.access = [i for i in phys if i.port_mode == "access"]
        # uplinks: names (in the source vendor) the topology identified as inter-device, plus trunks
        self.uplinks = [i for i in phys
                        if display_name(i.ref, vendor_of_names) in uplinks or i.port_mode == "trunk"]
        self.unused = [i for i in phys if port_state(i) is PortState.UNUSED]
        self.vlans = [v.vlan_id for v in ir.vlans] or sorted({i.access_vlan for i in self.access if i.access_vlan})
        self.user_subnets = [i.ipv4.network for i in ir.interfaces
                             if i.if_type == "vlanif" and i.ipv4 is not None and i.ipv4.network.prefixlen < 31]
        nets = [i.ipv4.network for i in ir.interfaces if i.ipv4 is not None and i.ipv4.network.prefixlen < 32]
        self.mgmt: Optional[IPv4Network] = (self.user_subnets or nets or [None])[0]


def _baseline(ir: DeviceConfigIR, vendor: Vendor) -> list[str]:
    interfaces = [i.model_copy(update={"acl_in": None, "acl_out": None, "notes": []}) for i in ir.interfaces]
    base = ir.model_copy(update={
        "interfaces": interfaces, "acls": [], "ntp_servers": [], "syslog_hosts": [], "notes": [], "comments": [],
        "warnings": [],
    })
    lines = [l.text for l in render_config(base, vendor)
             if not l.is_comment and l.text.strip() not in ("end", "return")]
    if vendor is H:
        lines += ["stelnet server enable", "user-interface vty 0 4", " authentication-mode aaa", " protocol inbound ssh"]
    else:
        lines += ["ip ssh version 2", "line vty 0 4", " login local", " transport input ssh"]
    lines.append(_c(vendor, "บัญชีผู้ใช้สำหรับ SSH ให้ผู้ดูแลระบบสร้างเองบนอุปกรณ์ (ระบบไม่สร้างรหัสผ่าน)"))
    return lines


def _qos(f: _Facts, vendor: Vendor) -> list[str]:
    acc, up = _names(f.access, vendor), _names(f.uplinks, vendor)
    if vendor is C:
        out = [
            "class-map match-any NM-VOICE", " match dscp ef",
            "class-map match-any NM-SIGNALING", " match dscp cs3",
            "policy-map NM-ACCESS-MARK", " class NM-VOICE", "  set dscp ef", " class class-default", "  set dscp default",
            "policy-map NM-UPLINK-QUEUE", " class NM-VOICE", "  priority level 1 percent 20",
            " class NM-SIGNALING", "  bandwidth remaining percent 10", " class class-default", "  fair-queue",
            "policy-map NM-UPLINK-POLICE", " class class-default", "  police cir 100000000",
        ]
        for p in acc:
            out += [f"interface {p}", " service-policy input NM-ACCESS-MARK"]
        for p in up:
            out += [f"interface {p}", " service-policy output NM-UPLINK-QUEUE", " service-policy input NM-UPLINK-POLICE"]
        out.append(_c(vendor, "พอร์ตเชื่อมระหว่างอุปกรณ์เชื่อถือ DSCP ที่ส่งมา (IOS-XE เชื่อถือ DSCP เป็นค่าเริ่มต้น)"))
        return out
    out = [
        "traffic classifier NM-VOICE operator or", " if-match dscp ef",
        "traffic behavior NM-VOICE", " remark dscp ef",
        "traffic classifier NM-OTHER operator or", " if-match any",
        "traffic behavior NM-OTHER", " remark dscp default",
        "traffic policy NM-ACCESS-MARK", " classifier NM-VOICE behavior NM-VOICE", " classifier NM-OTHER behavior NM-OTHER",
    ]
    for p in acc:
        out += [f"interface {p}", " traffic-policy NM-ACCESS-MARK inbound"]
    for p in up:
        out += [f"interface {p}", " trust dscp", " qos lr outbound cir 100000"]
    if up:
        out.append(_c(vendor, "จัดลำดับคิว: ตั้งคิว EF (DSCP 46) เป็น Priority Queue ตามคำสั่ง QoS ของรุ่นอุปกรณ์ (แต่ละรุ่นต่างกัน)"))
    return out


def _security(f: _Facts, vendor: Vendor) -> list[str]:
    acc, up, unused = _names(f.access, vendor), _names(f.uplinks, vendor), _names(f.unused, vendor)
    vlans = " ".join(str(v) for v in f.vlans)
    out: list[str] = []
    if vendor is C:
        if f.vlans:
            out += ["ip dhcp snooping", f"ip dhcp snooping vlan {','.join(str(v) for v in f.vlans)}"]
        for p in acc:
            out += [f"interface {p}", " switchport port-security", " switchport port-security maximum 2",
                    " switchport port-security violation restrict", " spanning-tree guard root"]
        for p in up:
            out += [f"interface {p}", " ip dhcp snooping trust"]
        for p in unused:
            out += [f"interface {p}", " shutdown"]
        if len(f.user_subnets) > 1:
            out.append("ip access-list extended NM-INTER-SUBNET")
            seq = 10
            for a in f.user_subnets:
                for b in f.user_subnets:
                    if a != b:
                        out.append(f" {seq} deny ip {a.network_address} {_wild(a)} {b.network_address} {_wild(b)}")
                        seq += 10
            out.append(f" {seq} permit ip any any")
            out.append(_c(vendor, "นำ NM-INTER-SUBNET ไปผูกที่ interface Vlan ตามนโยบายจริง (ip access-group NM-INTER-SUBNET in)"))
        if f.mgmt:
            out += ["ip access-list standard NM-MGMT", f" permit {f.mgmt.network_address} {_wild(f.mgmt)}",
                    "line vty 0 4", " access-class NM-MGMT in", " transport input ssh", " exec-timeout 10 0",
                    "ip ssh version 2"]
        return out
    if f.vlans:
        out += ["dhcp enable", "dhcp snooping enable", f"dhcp snooping enable vlan {vlans}"]
    for p in acc:
        out += [f"interface {p}", " port-security enable", " port-security max-mac-num 2",
                " port-security protect-action restrict", " stp root-protection"]
    for p in up:
        out += [f"interface {p}", " dhcp snooping trusted"]
    for p in unused:
        out += [f"interface {p}", " shutdown"]
    if len(f.user_subnets) > 1:
        out.append("acl name NM-INTER-SUBNET advance")
        rule = 5
        for a in f.user_subnets:
            for b in f.user_subnets:
                if a != b:
                    out.append(f" rule {rule} deny ip source {a.network_address} {_wild(a)} "
                               f"destination {b.network_address} {_wild(b)}")
                    rule += 5
        out.append(f" rule {rule} permit ip")
        out.append(_c(vendor, "นำ NM-INTER-SUBNET ไปผูกที่ interface Vlanif ตามนโยบายจริง (traffic-filter inbound acl name NM-INTER-SUBNET)"))
    if f.mgmt:
        out += ["acl number 2010", f" rule 5 permit source {f.mgmt.network_address} {_wild(f.mgmt)}",
                "user-interface vty 0 4", " acl 2010 inbound", " protocol inbound ssh", " idle-timeout 10 0",
                "stelnet server enable"]
    return out


def advise_sections(ir: DeviceConfigIR, uplink_ports: set[str]) -> dict[int, dict[str, list[str]]]:
    """Each level's OWN lines (not cumulative), per vendor: {1: {"cisco_ios_xe": [...], ...}, ...}."""
    facts = _Facts(ir, uplink_ports, ir.source_vendor)
    out: dict[int, dict[str, list[str]]] = {}
    for lv in LEVELS:
        out[lv] = {}
        for vendor in (C, H):
            th, en = HEADER[lv]
            body = _baseline(ir, vendor) if lv == 1 else _qos(facts, vendor) if lv == 2 else _security(facts, vendor)
            out[lv][vendor.value] = [_c(vendor, "=" * 60), _c(vendor, f"{th} / {en}")] + body
    return out


def advise(ir: DeviceConfigIR, uplink_ports: set[str], level: int) -> dict[str, list[str]]:
    """Cumulative suggestions up to `level` (7.3: a higher level includes all lower levels)."""
    if level not in LEVELS:
        raise ValueError("level must be 1, 2 or 3")
    sections = advise_sections(ir, uplink_ports)
    out: dict[str, list[str]] = {}
    for vendor in (C, H):
        lines = [_c(vendor, f"NetMigrate — {REVIEW_NOTE}")]
        for lv in range(1, level + 1):
            lines += sections[lv][vendor.value]
        out[vendor.value] = lines
    return out
