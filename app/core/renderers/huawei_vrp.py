"""Huawei VRP renderer: IR -> Huawei text lines with provenance labels."""

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
from app.core.rules.tier1_vlan import format_huawei_vlan_list

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL
H = Vendor.HUAWEI_VRP


def render(ir: DeviceConfigIR) -> list[RenderedLine]:
    w = LineWriter(H)
    for c in ir.comments:
        w.comment(c)
    w.separator()

    if ir.hostname:
        w.cmd(f"sysname {ir.hostname}", D, ir.field_lines.get("hostname"))
    if ir.domain_name:
        w.cmd(f"dns domain {ir.domain_name}", D, ir.field_lines.get("domain_name"))
    w.separator()

    for vlan in ir.vlans:
        w.cmd(f"vlan {vlan.vlan_id}", D, vlan.source_lines[0] if vlan.source_lines else None)
        if vlan.name:
            w.cmd(f" description {vlan.name}", D, vlan.field_lines.get("name"))
        w.notes(vlan.notes)
        w.separator()

    for iface in ir.interfaces:
        name = display_name(iface.ref, H)
        fl = iface.field_lines
        w.cmd(f"interface {name}", D, iface.source_lines[0], interface_warnings(iface, name))
        if iface.description:
            w.cmd(f" description {iface.description}", D, fl.get("description"))
        if iface.link_protocol:
            warn = hdlc_warning(name) if iface.link_protocol == "hdlc" else None
            w.cmd(f" link-protocol {iface.link_protocol}", D, fl.get("link_protocol"), warn)
        if iface.port_mode:
            w.cmd(f" port link-type {iface.port_mode}", D, fl.get("port_mode"), trunk_warning(iface, name))
        if iface.access_vlan is not None:
            w.cmd(f" port default vlan {iface.access_vlan}", D, fl.get("access_vlan"))
        if iface.trunk_allowed_vlans:
            vlans = format_huawei_vlan_list(iface.trunk_allowed_vlans)
            w.cmd(f" port trunk allow-pass vlan {vlans}", T, fl.get("trunk_allowed_vlans"))
        if iface.stp_edge:
            w.cmd(" stp edged-port enable", D, fl.get("stp_edge"))
        if iface.ipv4:
            w.cmd(f" ip address {iface.ipv4.ip} {iface.ipv4.netmask}", D, fl.get("ipv4"))
        if iface.ospf_network_p2p:
            w.cmd(" ospf network-type p2p", D, fl.get("ospf_network_p2p"))
        if iface.ospf_cost is not None:
            w.cmd(f" ospf cost {iface.ospf_cost}", D, fl.get("ospf_cost"))
        if iface.ospf_priority is not None:
            w.cmd(f" ospf dr-priority {iface.ospf_priority}", D, fl.get("ospf_priority"))
        if iface.shutdown is not None:
            w.cmd(" shutdown" if iface.shutdown else " undo shutdown", D, fl.get("shutdown"))
        w.notes(iface.notes)
        w.separator()

    if ospf := ir.ospf:
        src, fl = ospf.source_lines[0] if ospf.source_lines else None, ospf.field_lines
        header = f"ospf {ospf.process_id}" + (f" router-id {ospf.router_id}" if ospf.router_id else "")
        w.cmd(header, S, src)
        for ref in ospf.silent_interfaces:
            w.cmd(f" silent-interface {display_name(ref, H)}", S, src)
        if ospf.default_originate:
            w.cmd(" default-route-advertise", S, fl.get("default_originate"))
        for area in ospf.areas:
            w.cmd(f" area {area.dotted}", S, src)
            if area.stub:
                w.cmd("  stub", S, area.field_lines.get("stub"))
            for net in area.networks:
                w.cmd(f"  network {net.address} {net.wildcard}", S, net.source_line)
        w.notes(ospf.notes)
        w.separator()

    for route in ir.static_routes:
        parts = ["ip route-static", str(route.destination.network_address), str(route.destination.netmask)]
        if route.exit_interface:
            parts.append(display_name(route.exit_interface, H))
        if route.next_hop:
            parts.append(str(route.next_hop))
        if route.preference is not None:
            parts += ["preference", str(route.preference)]
        warn = WARN_STATIC_DEFAULT_PREFERENCE if route.preference is None else None
        w.cmd(" ".join(parts), T, route.source_lines[0] if route.source_lines else None, warn)
    if ir.static_routes:
        w.separator()

    if ir.notes:
        w.notes(ir.notes)
        w.separator()
    w.cmd("return", D)
    return w.lines
