"""Cisco IOS-XE renderer: IR -> Cisco text lines with provenance labels."""

from __future__ import annotations

from app.core.ir import DeviceConfigIR, RenderedLine, SyntaxCategory, Vendor
from app.core.renderers.common import (
    WARN_STATIC_DEFAULT_PREFERENCE,
    LineWriter,
    hdlc_warning,
    interface_warnings,
    trunk_warning,
)
from app.core.rules.interface_names import display_name
from app.core.rules.tier1_vlan import format_cisco_vlan_list

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL
C = Vendor.CISCO_IOS_XE


def render(ir: DeviceConfigIR) -> list[RenderedLine]:
    w = LineWriter(C)
    for c in ir.comments:
        w.comment(c)
    w.separator()

    if ir.hostname:
        w.cmd(f"hostname {ir.hostname}", D, ir.field_lines.get("hostname"))
    if ir.domain_name:
        w.cmd(f"ip domain name {ir.domain_name}", D, ir.field_lines.get("domain_name"))
    w.separator()

    for vlan in ir.vlans:
        w.cmd(f"vlan {vlan.vlan_id}", D, vlan.source_lines[0] if vlan.source_lines else None)
        if vlan.name:
            warn = (
                f"VLAN {vlan.vlan_id}: ชื่อมีช่องว่าง ซึ่ง Cisco อาจไม่รับ กรุณาตรวจสอบ"
                if any(ch.isspace() for ch in vlan.name)
                else None
            )
            w.cmd(f" name {vlan.name}", D, vlan.field_lines.get("name"), warn)
        w.notes(vlan.notes)
        w.separator()

    for iface in ir.interfaces:
        name = display_name(iface.ref, C)
        fl = iface.field_lines
        w.cmd(f"interface {name}", D, iface.source_lines[0], interface_warnings(iface, name))
        if iface.description:
            w.cmd(f" description {iface.description}", D, fl.get("description"))
        if iface.link_protocol:
            warn = hdlc_warning(name) if iface.link_protocol == "hdlc" else None
            w.cmd(f" encapsulation {iface.link_protocol}", D, fl.get("link_protocol"), warn)
        if iface.port_mode:
            w.cmd(f" switchport mode {iface.port_mode}", D, fl.get("port_mode"), trunk_warning(iface, name))
        if iface.access_vlan is not None:
            w.cmd(f" switchport access vlan {iface.access_vlan}", D, fl.get("access_vlan"))
        if iface.trunk_allowed_vlans:
            vlans = format_cisco_vlan_list(iface.trunk_allowed_vlans)
            w.cmd(f" switchport trunk allowed vlan {vlans}", T, fl.get("trunk_allowed_vlans"))
        if iface.ipv4:
            w.cmd(f" ip address {iface.ipv4.ip} {iface.ipv4.netmask}", D, fl.get("ipv4"))
        if iface.ospf_network_p2p:
            w.cmd(" ip ospf network point-to-point", D, fl.get("ospf_network_p2p"))
        if iface.ospf_cost is not None:
            w.cmd(f" ip ospf cost {iface.ospf_cost}", D, fl.get("ospf_cost"))
        if iface.ospf_priority is not None:
            w.cmd(f" ip ospf priority {iface.ospf_priority}", D, fl.get("ospf_priority"))
        if iface.stp_edge:
            w.cmd(" spanning-tree portfast", D, fl.get("stp_edge"))
        if iface.shutdown is not None:
            w.cmd(" shutdown" if iface.shutdown else " no shutdown", D, fl.get("shutdown"))
        w.notes(iface.notes)
        w.separator()

    if ospf := ir.ospf:
        src, fl = ospf.source_lines[0] if ospf.source_lines else None, ospf.field_lines
        w.cmd(f"router ospf {ospf.process_id}", S, src)
        if ospf.router_id:
            w.cmd(f" router-id {ospf.router_id}", S, fl.get("router_id"))
        for ref in ospf.silent_interfaces:
            w.cmd(f" passive-interface {display_name(ref, C)}", S, src)
        for area in ospf.areas:
            for net in area.networks:
                w.cmd(f" network {net.address} {net.wildcard} area {area.area_id}", S, net.source_line)
        for area in ospf.areas:
            if area.stub:
                w.cmd(f" area {area.area_id} stub", S, area.field_lines.get("stub"))
        if ospf.default_originate:
            w.cmd(" default-information originate", S, fl.get("default_originate"))
        w.notes(ospf.notes)
        w.separator()

    for route in ir.static_routes:
        parts = ["ip route", str(route.destination.network_address), str(route.destination.netmask)]
        if route.exit_interface:
            parts.append(display_name(route.exit_interface, C))
        if route.next_hop:
            parts.append(str(route.next_hop))
        if route.preference is not None:
            parts.append(str(route.preference))
        warn = WARN_STATIC_DEFAULT_PREFERENCE if route.preference is None else None
        w.cmd(" ".join(parts), T, route.source_lines[0] if route.source_lines else None, warn)
    if ir.static_routes:
        w.separator()

    if ir.notes:
        w.notes(ir.notes)
        w.separator()
    w.cmd("end", D)
    return w.lines
