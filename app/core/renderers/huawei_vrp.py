"""Huawei VRP renderer: IR -> Huawei text lines with provenance labels."""

from __future__ import annotations

import re

from app.core.ir import AclRefIR, DeviceConfigIR, InterfaceIR, Provenance, RenderedLine, SyntaxCategory, Vendor
from app.core.renderers.common import (
    WARN_ACL_NUMBER_ASSIGNED,
    WARN_BGP_PEER_ENABLE,
    WARN_DEFAULT_GATEWAY,
    WARN_HUAWEI_ACL_NAME,
    WARN_HUAWEI_VTY_RANGE,
    WARN_RIP_NO_VERSION,
    WARN_STATIC_DEFAULT_PREFERENCE,
    WARN_STELNET,
    LineWriter,
    acl_default_action_warning,
    hdlc_warning,
    huawei_import_route,
    interface_warnings,
    trunk_warning,
)
from app.core.rules.interface_names import display_name
from app.core.rules.tier1_vlan import format_huawei_vlan_list
from app.core.rules.tier3_bgp_acl import BASIC, format_huawei_rule, huawei_number

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL
H = Vendor.HUAWEI_VRP
SYSTEM = Provenance.SYSTEM
_VALID_ACL_NAME = re.compile(r"^[A-Za-z]\S{0,31}$")
HUAWEI_VTY_SAFE_MAX = 4


def _first(lines: list[int]):
    return lines[0] if lines else None


def _acl_ref_text(ref: AclRefIR) -> str:
    return f"name {ref.name}" if ref.name else str(huawei_number(ref.kind, ref.ordinal))


def _render_acls(w: LineWriter, ir: DeviceConfigIR) -> None:
    for acl in ir.acls:
        src = _first(acl.source_lines)
        if acl.name:
            flavour = "basic" if acl.kind == BASIC else "advance"
            warn = None if _VALID_ACL_NAME.match(acl.name) else WARN_HUAWEI_ACL_NAME
            w.cmd(f"acl name {acl.name} {flavour}", T, src, warn)
        else:
            w.cmd(f"acl number {huawei_number(acl.kind, acl.ordinal)}", T, src, WARN_ACL_NUMBER_ASSIGNED, SYSTEM)
        for i, entry in enumerate(acl.entries, start=1):
            w.cmd(f" rule {5 * i} {format_huawei_rule(entry)}", T, entry.source_line)
        w.notes(acl.notes)
        w.separator()


def _render_interface(w: LineWriter, ir: DeviceConfigIR, iface: InterfaceIR) -> None:
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
    for attr, direction in (("acl_in", "inbound"), ("acl_out", "outbound")):
        ref = getattr(iface, attr)
        if ref is not None:
            warn = acl_default_action_warning(ir.acl(ref.key), H)
            w.cmd(f" traffic-filter {direction} acl {_acl_ref_text(ref)}", T, fl.get(attr), warn)
    if iface.shutdown is not None:
        w.cmd(" shutdown" if iface.shutdown else " undo shutdown", D, fl.get("shutdown"))
    w.notes(iface.notes)
    w.separator()


def _render_ospf(w: LineWriter, ir: DeviceConfigIR) -> None:
    ospf = ir.ospf
    src, fl = _first(ospf.source_lines), ospf.field_lines
    header = f"ospf {ospf.process_id}" + (f" router-id {ospf.router_id}" if ospf.router_id else "")
    w.cmd(header, S, src)
    for ref in ospf.silent_interfaces:
        w.cmd(f" silent-interface {display_name(ref, H)}", S, src)
    if ospf.default_originate:
        w.cmd(" default-route-advertise", S, fl.get("default_originate"))
    for r in ospf.redistribute:
        w.cmd(f" {huawei_import_route(r, 'ospf')}", T, r.source_line)
    for area in ospf.areas:
        w.cmd(f" area {area.dotted}", S, src)
        if area.stub:
            w.cmd("  stub", S, area.field_lines.get("stub"))
        for net in area.networks:
            w.cmd(f"  network {net.address} {net.wildcard}", S, net.source_line)
    w.notes(ospf.notes)
    w.separator()


def _render_rip(w: LineWriter, ir: DeviceConfigIR) -> None:
    rip = ir.rip
    src, fl = _first(rip.source_lines), rip.field_lines
    w.cmd(f"rip {rip.process_id}", T, src, WARN_RIP_NO_VERSION if rip.version is None else None)
    if rip.version is not None:
        w.cmd(f" version {rip.version}", D, fl.get("version"))
    if rip.auto_summary is not None:
        w.cmd(" summary" if rip.auto_summary else " undo summary", D, fl.get("auto_summary"))
    for ref in rip.silent_interfaces:
        w.cmd(f" silent-interface {display_name(ref, H)}", D, fl.get(f"silent {ref.if_type}{ref.number}"))
    for net in rip.networks:
        w.cmd(f" network {net}", D, fl.get(f"network {net}"))
    if rip.default_originate:
        w.cmd(" default-route originate", D, fl.get("default_originate"))
    for r in rip.redistribute:
        w.cmd(f" {huawei_import_route(r, 'rip')}", T, r.source_line)
    w.notes(rip.notes)
    w.separator()


def _render_bgp(w: LineWriter, ir: DeviceConfigIR) -> None:
    bgp = ir.bgp
    src = _first(bgp.source_lines)
    w.cmd(f"bgp {bgp.asn}", S, src)
    if bgp.router_id:
        w.cmd(f" router-id {bgp.router_id}", S, bgp.field_lines.get("router_id"))
    for n in bgp.neighbors:
        w.cmd(f" peer {n.address} as-number {n.remote_as}", S, n.source_line)
        if n.description:
            w.cmd(f" peer {n.address} description {n.description}", S, n.field_lines.get("description"))
    # Proposal §2.3.2 item 3: Huawei peers exchange no IPv4 routes until enabled here.
    w.cmd(" ipv4-family unicast", S, src, WARN_BGP_PEER_ENABLE, SYSTEM)
    for net in bgp.networks:
        w.cmd(f"  network {net.prefix.network_address} {net.prefix.netmask}", S, net.source_line)
    for r in bgp.redistribute:
        w.cmd(f"  {huawei_import_route(r, 'bgp')}", T, r.source_line)
    for n in bgp.neighbors:
        if n.enabled:
            w.cmd(f"  peer {n.address} enable", S, n.source_line, WARN_BGP_PEER_ENABLE, SYSTEM)
    w.notes(bgp.notes)
    w.separator()


def _render_vty(w: LineWriter, ir: DeviceConfigIR) -> None:
    ssh_lines = [v for v in ir.vty_lines if v.transport and "ssh" in v.transport]
    if ssh_lines:
        w.cmd("stelnet server enable", D, ssh_lines[0].field_lines.get("transport"), WARN_STELNET, SYSTEM)
    for vty in ir.vty_lines:
        fl = vty.field_lines
        warn = WARN_HUAWEI_VTY_RANGE if vty.last > HUAWEI_VTY_SAFE_MAX else None
        w.cmd(f"user-interface vty {vty.first} {vty.last}", D, _first(vty.source_lines), warn)
        if vty.login_local:
            w.cmd(" authentication-mode aaa", D, fl.get("login_local"))
        if vty.transport:
            protocol = "all" if len(vty.transport) > 1 else vty.transport[0]
            w.cmd(f" protocol inbound {protocol}", D, fl.get("transport"))
        w.notes(vty.notes)
        w.separator()


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
        w.cmd(f"vlan {vlan.vlan_id}", D, _first(vlan.source_lines))
        if vlan.name:
            w.cmd(f" description {vlan.name}", D, vlan.field_lines.get("name"))
        w.notes(vlan.notes)
        w.separator()

    _render_acls(w, ir)  # before interfaces: traffic-filter references them

    for iface in ir.interfaces:
        _render_interface(w, ir, iface)

    if ir.ospf:
        _render_ospf(w, ir)
    if ir.rip:
        _render_rip(w, ir)
    if ir.bgp:
        _render_bgp(w, ir)

    for route in ir.static_routes:
        parts = ["ip route-static", str(route.destination.network_address), str(route.destination.netmask)]
        if route.exit_interface:
            parts.append(display_name(route.exit_interface, H))
        if route.next_hop:
            parts.append(str(route.next_hop))
        if route.preference is not None:
            parts += ["preference", str(route.preference)]
        warn = WARN_STATIC_DEFAULT_PREFERENCE if route.preference is None else None
        w.cmd(" ".join(parts), T, _first(route.source_lines), warn)
    if ir.default_gateway:
        w.cmd(
            f"ip route-static 0.0.0.0 0.0.0.0 {ir.default_gateway}",
            T,
            ir.field_lines.get("default_gateway"),
            WARN_DEFAULT_GATEWAY,
        )
    if ir.static_routes or ir.default_gateway:
        w.separator()

    for server in ir.ntp_servers:
        w.cmd(f"ntp-service unicast-server {server.address}", D, server.source_line)
    for host in ir.syslog_hosts:
        w.cmd(f"info-center loghost {host.address}", D, host.source_line)
    if ir.ntp_servers or ir.syslog_hosts:
        w.separator()

    _render_vty(w, ir)

    if ir.notes:
        w.notes(ir.notes)
        w.separator()
    w.cmd("return", D)
    return w.lines
