"""Topology analysis (proposal §2.3.1 module 7.1 / 7.2).

Rules find WHAT IS PROVABLE from the configurations alone:
  * subnets and which device/port sits in each one (shared subnet => inter-device L3 link);
  * BGP sessions (neighbor address == another device's interface address);
  * the routing protocol running across each link (OSPF network / RIP classful network
    statements covering both ends);
  * links named in interface descriptions ("Uplink-to-CORE1" when CORE1 is a device);
  * VLAN reach (which devices define / carry each VLAN);
  * port roles: inter-device link, end-user access port, routed stub port, unused.

Device roles are given by a rule heuristic, flagged as such. The AI (7.2) is only asked —
on demand, with this IR-derived summary which never contains credentials — to describe
roles, links the rules could not resolve, and to phrase the explanation.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Optional

from app.core.engine import sanitize_and_parse
from app.core.hardware import PortState, port_state
from app.core.ir import DeviceConfigIR, InterfaceIR, Vendor
from app.core.rules.interface_names import display_name
from app.core.vendor_detect import detect_vendor


@dataclass
class TopologyInput:
    name: str
    text: str
    vendor: Optional[Vendor] = None


ROLE_TEXT = {
    "edge_router": ("เราเตอร์ขอบเครือข่าย (มี BGP)", "Edge router (runs BGP)"),
    "router": ("เราเตอร์ (พอร์ตแบบ Routed + โปรโตคอลจัดเส้นทาง)", "Router (routed ports + routing protocol)"),
    "l3_switch": ("สวิตช์ชั้นที่ 3 / Distribution (มี VLAN + Vlanif + จัดเส้นทาง)", "Layer-3 / distribution switch"),
    "access_switch": ("สวิตช์ Access (พอร์ตต่อเครื่องผู้ใช้)", "Access switch (end-user ports)"),
    "unknown": ("ระบุบทบาทด้วยกฎไม่ได้", "Role not determinable by rules"),
}
PORT_ROLE_TEXT = {
    "uplink": ("พอร์ตเชื่อมระหว่างอุปกรณ์", "Inter-device link"),
    "access": ("พอร์ตต่อเครื่องผู้ใช้", "End-user access port"),
    "routed": ("พอร์ต Routed (ปลายทางนอกชุดไฟล์)", "Routed port (peer outside this file set)"),
    "trunk": ("พอร์ต Trunk (ยังไม่ทราบอุปกรณ์ปลายสาย)", "Trunk (peer not identified)"),
    "unused": ("ไม่ได้ใช้งาน", "Unused"),
}


def _classful(addr: IPv4Address) -> IPv4Network:
    first = int(addr) >> 24
    prefix = 8 if first < 128 else 16 if first < 192 else 24
    return ip_network(f"{addr}/{prefix}", strict=False)  # type: ignore[return-value]


def _ospf_covers(ir: DeviceConfigIR, ip: IPv4Address) -> bool:
    if not ir.ospf:
        return False
    for area in ir.ospf.areas:
        for n in area.networks:
            mask = ~int(n.wildcard) & 0xFFFFFFFF
            if int(ip) & mask == int(n.address) & mask:
                return True
    return False


def _rip_covers(ir: DeviceConfigIR, ip: IPv4Address) -> bool:
    return bool(ir.rip) and any(ip in _classful(n) for n in ir.rip.networks)  # type: ignore[union-attr]


def _protocols(ir: DeviceConfigIR) -> list[str]:
    out = []
    if ir.ospf:
        out.append("OSPF")
    if ir.rip:
        out.append("RIP")
    if ir.bgp:
        out.append("BGP")
    if ir.static_routes or ir.default_gateway:
        out.append("Static")
    return out


def _device_role(ir: DeviceConfigIR) -> str:
    phys = [i for i in ir.interfaces if not i.is_virtual]
    access = [i for i in phys if i.port_mode == "access"]
    routed = [i for i in phys if i.ipv4 is not None]
    vlanifs = [i for i in ir.interfaces if i.if_type == "vlanif" and i.ipv4 is not None]
    routing = bool(ir.ospf or ir.rip or ir.bgp or ir.static_routes)
    if ir.bgp:
        return "edge_router"
    if access and (vlanifs or (routing and routed)):
        return "l3_switch"
    if routed and not access:
        return "router"
    if access or ir.vlans:
        return "access_switch"
    return "unknown"


def analyze(inputs: list[TopologyInput]) -> dict:
    devices: list[dict] = []
    irs: list[DeviceConfigIR] = []
    errors: list[dict] = []
    for item in inputs:
        vendor = item.vendor or detect_vendor(item.text)
        if vendor is None:
            errors.append({"name": item.name, "reason": "vendor"})
            continue
        other = Vendor.HUAWEI_VRP if vendor is Vendor.CISCO_IOS_XE else Vendor.CISCO_IOS_XE
        _, parsed = sanitize_and_parse(item.text, vendor, other)  # secrets stripped first
        ir = parsed.ir
        name = ir.hostname or item.name.rsplit(".", 1)[0]
        irs.append(ir)
        devices.append({"id": len(devices), "name": name, "file": item.name, "vendor": vendor.value})

    # subnet -> members
    subnets: dict[IPv4Network, list[dict]] = {}
    for dev, ir in zip(devices, irs):
        for iface in ir.interfaces:
            if iface.ipv4 is None or iface.ipv4.network.prefixlen >= 32:
                continue
            subnets.setdefault(iface.ipv4.network, []).append(
                {"device": dev["id"], "port": display_name(iface.ref, Vendor(dev["vendor"])), "ip": str(iface.ipv4.ip),
                 "_iface": iface, "_ir": ir})

    links: list[dict] = []
    linked_ports: set[tuple[int, str]] = set()
    for net, members in subnets.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = members[i], members[j]
                if a["device"] == b["device"]:
                    continue
                protos = []
                ia, ib = IPv4Address(a["ip"]), IPv4Address(b["ip"])
                if _ospf_covers(a["_ir"], ia) and _ospf_covers(b["_ir"], ib):
                    protos.append("OSPF")
                if _rip_covers(a["_ir"], ia) and _rip_covers(b["_ir"], ib):
                    protos.append("RIP")
                links.append({"a": a["device"], "a_port": a["port"], "b": b["device"], "b_port": b["port"],
                              "kind": "l3", "subnet": str(net), "protocols": protos, "source": "rule"})
                linked_ports |= {(a["device"], a["port"]), (b["device"], b["port"])}

    # BGP sessions
    ip_owner = {m["ip"]: m["device"] for ms in subnets.values() for m in ms}
    for dev, ir in zip(devices, irs):
        if not ir.bgp:
            continue
        for n in ir.bgp.neighbors:
            peer = ip_owner.get(str(n.address))
            if peer is None or peer == dev["id"]:
                continue
            existing = next((l for l in links if {l["a"], l["b"]} == {dev["id"], peer} and l["kind"] == "l3"), None)
            if existing is not None:
                if "BGP" not in existing["protocols"]:
                    existing["protocols"].append("BGP")
            elif not any(l["kind"] == "bgp" and {l["a"], l["b"]} == {dev["id"], peer} for l in links):
                links.append({"a": dev["id"], "a_port": None, "b": peer, "b_port": None, "kind": "bgp",
                              "subnet": None, "protocols": ["BGP"], "source": "rule"})

    # Links named in descriptions
    by_name = {d["name"].lower(): d["id"] for d in devices}
    for dev, ir in zip(devices, irs):
        for iface in ir.interfaces:
            desc = (iface.description or "").lower()
            if not desc or iface.is_virtual:
                continue
            port = display_name(iface.ref, Vendor(dev["vendor"]))
            if (dev["id"], port) in linked_ports:
                continue
            for other_name, other_id in by_name.items():
                if other_id != dev["id"] and len(other_name) >= 3 and other_name in desc:
                    if not any({l["a"], l["b"]} == {dev["id"], other_id} for l in links):
                        links.append({"a": dev["id"], "a_port": port, "b": other_id, "b_port": None,
                                      "kind": "description", "subnet": None, "protocols": [], "source": "rule"})
                    linked_ports.add((dev["id"], port))
                    break

    # Per-device details and port roles
    unresolved: list[dict] = []
    vlan_map: dict[int, dict] = {}
    for dev, ir in zip(devices, irs):
        vendor = Vendor(dev["vendor"])
        ports = []
        for iface in ir.interfaces:
            if iface.is_virtual:
                continue
            name = display_name(iface.ref, vendor)
            role = _port_role(iface, (dev["id"], name) in linked_ports)
            if role == "trunk":
                unresolved.append({"device": dev["name"], "port": name,
                                   "vlans": iface.trunk_allowed_vlans or [], "description": iface.description})
            ports.append({
                "name": name, "role": role, "mode": iface.port_mode,
                "ip": str(iface.ipv4) if iface.ipv4 else None,
                "access_vlan": iface.access_vlan, "trunk_vlans": iface.trunk_allowed_vlans,
                "edge": bool(iface.stp_edge), "shutdown": bool(iface.shutdown),
                "description": iface.description,
            })
            for vid in ([iface.access_vlan] if iface.access_vlan else []) + (iface.trunk_allowed_vlans or []):
                vlan_map.setdefault(vid, {"id": vid, "name": None, "devices": set()})["devices"].add(dev["id"])
        for v in ir.vlans:
            entry = vlan_map.setdefault(v.vlan_id, {"id": v.vlan_id, "name": None, "devices": set()})
            entry["devices"].add(dev["id"])
            entry["name"] = entry["name"] or v.name
        role = _device_role(ir)
        dev.update({
            "role": role, "role_source": "rule",
            "protocols": _protocols(ir),
            "vlans": [v.vlan_id for v in ir.vlans],
            "ports": ports,
            "virtual": [{"name": display_name(i.ref, vendor), "ip": str(i.ipv4) if i.ipv4 else None}
                        for i in ir.interfaces if i.is_virtual],
            "counts": {r: sum(1 for p in ports if p["role"] == r) for r in PORT_ROLE_TEXT},
        })

    return {
        "devices": devices,
        "links": links,
        "subnets": [
            {"network": str(net), "shared": len({m["device"] for m in ms}) > 1,
             "members": [{k: v for k, v in m.items() if not k.startswith("_")} for m in ms]}
            for net, ms in sorted(subnets.items(), key=lambda kv: (int(kv[0].network_address), kv[0].prefixlen))
        ],
        "vlans": [{"id": v["id"], "name": v["name"], "devices": sorted(v["devices"])}
                  for v in sorted(vlan_map.values(), key=lambda x: x["id"])],
        "unresolved": unresolved,
        "errors": errors,
        "_irs": irs,  # stripped by the API layer; used by the advisory generator
    }


def _port_role(iface: InterfaceIR, linked: bool) -> str:
    if linked:
        return "uplink"
    if iface.port_mode == "trunk":
        return "trunk"
    if iface.port_mode == "access":
        return "access"
    if iface.ipv4 is not None:
        return "routed"
    return "unused" if port_state(iface) is PortState.UNUSED else "routed"


def ai_summary(result: dict) -> dict:
    """The (credential-free, IR-derived) view sent to AI for role/explanation (7.2)."""
    return {
        "devices": [{k: d[k] for k in ("name", "vendor", "role", "protocols", "vlans", "ports", "virtual")}
                    for d in result["devices"]],
        "links": result["links"],
        "vlans": result["vlans"],
        "unresolved_trunks": result["unresolved"],
    }
