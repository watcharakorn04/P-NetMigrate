"""Cisco IOS-XE renderer: IR -> Cisco text lines with provenance labels."""

from __future__ import annotations

from app.core.ir import AclRefIR, DeviceConfigIR, InterfaceIR, InterfaceRef, Provenance, RenderedLine, SyntaxCategory, Vendor
from app.core.renderers.common import (
    WARN_WRITE_MEMORY,
    WARN_STP_EDGE_DEFAULT,
    WARN_STP_RSTP,
    WARN_CISCO_VRRP,
    WARN_TRACK_OBJECT_ASSIGNED,
    interface_header,
    WARN_ACL_NUMBER_ASSIGNED,
    WARN_CISCO_SSH,
    WARN_RIP_NO_VERSION,
    WARN_STATIC_DEFAULT_PREFERENCE,
    LineWriter,
    acl_default_action_warning,
    cisco_redistribute,
    hdlc_warning,
    interface_warnings,
    render_banner,
    rip_pid_warning,
    trunk_warning,
)
from app.core.rules.interface_names import display_name
from app.core.rules.tier1_vlan import format_cisco_vlan_list
from app.core.rules.tier2_services import format_cisco_timezone
from app.core.rules.tier3_bgp_acl import BASIC, cisco_number, format_cisco_entry

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL
C = Vendor.CISCO_IOS_XE
SYSTEM = Provenance.SYSTEM


def _first(lines: list[int]):
    return lines[0] if lines else None


def _acl_ref_text(ref: AclRefIR) -> str:
    # Parsers reject Huawei numbers without a Cisco equivalent, so cisco_number() is never None here.
    return ref.name if ref.name else str(cisco_number(ref.kind, ref.ordinal))


def _render_acls(w: LineWriter, ir: DeviceConfigIR) -> None:
    for acl in ir.acls:
        src = _first(acl.source_lines)
        flavour = "standard" if acl.kind == BASIC else "extended"
        if acl.name:
            w.cmd(f"ip access-list {flavour} {acl.name}", T, src)
        else:
            number = cisco_number(acl.kind, acl.ordinal)
            w.cmd(f"ip access-list {flavour} {number}", T, src, WARN_ACL_NUMBER_ASSIGNED, SYSTEM)
        for entry in acl.entries:
            w.cmd(f" {format_cisco_entry(entry)}", T, entry.source_line)
        w.notes(acl.notes)
        if "exit" in acl.field_lines:
            w.exit_view(acl.field_lines["exit"])
        w.separator()


def _trunk_is_lacp(ir: DeviceConfigIR, group: int) -> bool:
    return any(i.if_type == "eth-trunk" and i.number == str(group) and i.lacp_static for i in ir.interfaces)


def _track_objects(ir: DeviceConfigIR) -> dict[tuple[str, str], tuple[int, bool]]:
    """Tracked interface -> (track object number, assigned by the system?).

    Cisco HSRP/VRRP tracks a global `track <obj> interface <if> line-protocol` object. A number
    from the Cisco source is reused; otherwise (Huawei source) the system assigns the lowest free one.
    """
    out: dict[tuple[str, str], tuple[int, bool]] = {}
    tracks = [t for i in ir.interfaces for g in i.vrrp_groups for t in g.tracks]
    for t in tracks:
        if t.track_object is not None:
            out.setdefault((t.interface.if_type, t.interface.number), (t.track_object, False))
    used = {n for n, _ in out.values()}
    next_free = 1
    for t in tracks:
        key = (t.interface.if_type, t.interface.number)
        if key in out:
            continue
        while next_free in used:
            next_free += 1
        out[key] = (next_free, True)
        used.add(next_free)
    return out


def _render_track_objects(w: LineWriter, ir: DeviceConfigIR) -> dict[tuple[str, str], tuple[int, bool]]:
    objects = _track_objects(ir)
    sources = {(t.interface.if_type, t.interface.number): t.source_line
               for i in ir.interfaces for g in i.vrrp_groups for t in g.tracks}
    for (if_type, number), (obj, assigned) in sorted(objects.items(), key=lambda kv: kv[1][0]):
        name = display_name(InterfaceRef(if_type=if_type, number=number), C)
        if assigned:
            w.cmd(f"track {obj} interface {name} line-protocol", S, sources[(if_type, number)],
                  WARN_TRACK_OBJECT_ASSIGNED, SYSTEM)
        else:
            w.cmd(f"track {obj} interface {name} line-protocol", S, sources[(if_type, number)])
    if objects:
        w.separator()
    return objects


def _render_fhrp(w: LineWriter, iface: InterfaceIR, objects: dict[tuple[str, str], tuple[int, bool]]) -> None:
    for g in iface.vrrp_groups:
        word = "standby" if g.protocol == "hsrp" else "vrrp"
        lines: list[tuple[str, object]] = []
        if g.virtual_ip is not None:
            lines.append((f" {word} {g.vrid} ip {g.virtual_ip}", g.field_lines.get("virtual_ip")))
        if g.priority is not None:
            lines.append((f" {word} {g.vrid} priority {g.priority}", g.field_lines.get("priority")))
        for t in g.tracks:
            obj = objects[(t.interface.if_type, t.interface.number)][0]
            lines.append((f" {word} {g.vrid} track {obj} decrement {t.decrement}", t.source_line))
        for i, (text, src) in enumerate(lines):
            w.cmd(text, T, src, WARN_CISCO_VRRP if word == "vrrp" and i == 0 else None)


def _render_interface(w: LineWriter, ir: DeviceConfigIR, iface: InterfaceIR, objects=None) -> None:
    name = display_name(iface.ref, C)
    fl = iface.field_lines
    w.cmd(interface_header(iface, C), D, iface.source_lines[0], interface_warnings(iface, name))
    if iface.description:
        w.cmd(f" description {iface.description}", D, fl.get("description"))
    if iface.channel_group is not None:
        mode = "active" if _trunk_is_lacp(ir, iface.channel_group) else "on"
        w.cmd(f" channel-group {iface.channel_group} mode {mode}", S, fl.get("channel_group"))
    if iface.link_protocol:
        warn = hdlc_warning(name) if iface.link_protocol == "hdlc" else None
        w.cmd(f" encapsulation {iface.link_protocol}", D, fl.get("link_protocol"), warn)
    if iface.port_mode:
        w.cmd(f" switchport mode {iface.port_mode}", D, fl.get("port_mode"), trunk_warning(iface, name))
    if iface.access_vlan is not None:
        w.cmd(f" switchport access vlan {iface.access_vlan}", D, fl.get("access_vlan"))
    if iface.voice_vlan is not None:
        w.cmd(f" switchport voice vlan {iface.voice_vlan}", D, fl.get("voice_vlan"))
    if iface.trunk_allowed_vlans:
        vlans = format_cisco_vlan_list(iface.trunk_allowed_vlans)
        w.cmd(f" switchport trunk allowed vlan {vlans}", T, fl.get("trunk_allowed_vlans"))
    if iface.ipv4:
        w.cmd(f" ip address {iface.ipv4.ip} {iface.ipv4.netmask}", D, fl.get("ipv4"))
    _render_fhrp(w, iface, objects or {})
    for attr, direction in (("acl_in", "in"), ("acl_out", "out")):
        ref = getattr(iface, attr)
        if ref is not None:
            warn = acl_default_action_warning(ir.acl(ref.key), C)
            w.cmd(f" ip access-group {_acl_ref_text(ref)} {direction}", T, fl.get(attr), warn)
    if iface.ospf_network_p2p:
        w.cmd(" ip ospf network point-to-point", D, fl.get("ospf_network_p2p"))
    if iface.ospf_cost is not None:
        w.cmd(f" ip ospf cost {iface.ospf_cost}", D, fl.get("ospf_cost"))
    if iface.ospf_priority is not None:
        w.cmd(f" ip ospf priority {iface.ospf_priority}", D, fl.get("ospf_priority"))
    if iface.stp_edge:
        w.cmd(" spanning-tree portfast", D, fl.get("stp_edge"))
    if iface.port_security:
        w.cmd(" switchport port-security", D, fl.get("port_security"))
    if iface.port_security_max is not None:
        w.cmd(f" switchport port-security maximum {iface.port_security_max}", D, fl.get("port_security_max"))
    if iface.port_security_action:
        w.cmd(f" switchport port-security violation {iface.port_security_action}", T, fl.get("port_security_action"))
    if iface.port_security_sticky:
        w.cmd(" switchport port-security mac-address sticky", D, fl.get("port_security_sticky"))
    if iface.dhcp_snooping_trusted:
        w.cmd(" ip dhcp snooping trust", D, fl.get("dhcp_snooping_trusted"))
    for storm in iface.storm_control:
        level = f"{storm.max_percent}" if storm.min_percent == storm.max_percent else f"{storm.max_percent} {storm.min_percent}"
        w.cmd(f" storm-control {storm.traffic} level {level}", T, storm.source_line)
    if iface.shutdown is not None:
        w.cmd(" shutdown" if iface.shutdown else " no shutdown", D, fl.get("shutdown"))
    w.notes(iface.notes)
    if "exit" in fl:
        w.exit_view(fl["exit"])
    w.separator()


def _render_ospf(w: LineWriter, ir: DeviceConfigIR) -> None:
    ospf = ir.ospf
    src, fl = _first(ospf.source_lines), ospf.field_lines
    w.cmd(f"router ospf {ospf.process_id}", S, src)
    if ospf.router_id:
        w.cmd(f" router-id {ospf.router_id}", S, fl.get("router_id"))
    if ospf.silent_all:
        w.cmd(" passive-interface default", S, fl.get("silent_all"))
    for ref in ospf.non_silent_interfaces:
        w.cmd(f" no passive-interface {display_name(ref, C)}", S, fl.get(f"non_silent {ref.if_type}{ref.number}"))
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
    for r in ospf.redistribute:
        w.cmd(f" {cisco_redistribute(r, 'ospf')}", T, r.source_line)
    w.notes(ospf.notes)
    if "exit" in fl:
        w.exit_view(fl["exit"])
    w.separator()


def _render_rip(w: LineWriter, ir: DeviceConfigIR) -> None:
    rip = ir.rip
    src, fl = _first(rip.source_lines), rip.field_lines
    warnings = [x for x in (rip_pid_warning(rip.process_id), WARN_RIP_NO_VERSION if rip.version is None else None) if x]
    w.cmd("router rip", T, src, " | ".join(warnings) or None)
    if rip.version is not None:
        w.cmd(f" version {rip.version}", D, fl.get("version"))
    if rip.auto_summary is not None:
        w.cmd(" auto-summary" if rip.auto_summary else " no auto-summary", D, fl.get("auto_summary"))
    for ref in rip.silent_interfaces:
        w.cmd(f" passive-interface {display_name(ref, C)}", D, fl.get(f"silent {ref.if_type}{ref.number}"))
    for net in rip.networks:
        w.cmd(f" network {net}", D, fl.get(f"network {net}"))
    if rip.default_originate:
        w.cmd(" default-information originate", D, fl.get("default_originate"))
    for r in rip.redistribute:
        w.cmd(f" {cisco_redistribute(r, 'rip')}", T, r.source_line)
    w.notes(rip.notes)
    if "exit" in fl:
        w.exit_view(fl["exit"])
    w.separator()


def _render_bgp(w: LineWriter, ir: DeviceConfigIR) -> None:
    bgp = ir.bgp
    src = _first(bgp.source_lines)
    w.cmd(f"router bgp {bgp.asn}", S, src)
    if bgp.router_id:
        w.cmd(f" bgp router-id {bgp.router_id}", S, bgp.field_lines.get("router_id"))
    # Cisco activates every neighbor for IPv4 unicast unless told otherwise. If the source
    # left some peers disabled, keep them disabled (never activate what the source did not).
    selective = any(not n.enabled for n in bgp.neighbors)
    if selective:
        w.cmd(" no bgp default ipv4-unicast", S, src)
    for n in bgp.neighbors:
        w.cmd(f" neighbor {n.address} remote-as {n.remote_as}", S, n.source_line)
        if n.description:
            w.cmd(f" neighbor {n.address} description {n.description}", S, n.field_lines.get("description"))
    for net in bgp.networks:
        w.cmd(f" network {net.prefix.network_address} mask {net.prefix.netmask}", S, net.source_line)
    for r in bgp.redistribute:
        w.cmd(f" {cisco_redistribute(r, 'bgp')}", T, r.source_line)
    if selective:
        w.cmd(" address-family ipv4", S, src)
        for n in bgp.neighbors:
            if n.enabled:
                w.cmd(f"  neighbor {n.address} activate", S, n.source_line)
        w.cmd(" exit-address-family", S, src)
    w.notes(bgp.notes)
    if "exit" in bgp.field_lines:
        w.exit_view(bgp.field_lines["exit"])
    w.separator()


def _render_vty(w: LineWriter, ir: DeviceConfigIR) -> None:
    # Console first (Cisco order), then VTY.
    for vty in sorted(ir.vty_lines, key=lambda v: v.kind != "console"):
        fl = vty.field_lines
        if vty.kind == "console":
            header = f"line con {vty.first}"
        else:
            header = f"line vty {vty.first} {vty.last}" if vty.last != vty.first else f"line vty {vty.first}"
        w.cmd(header, D, _first(vty.source_lines))
        if vty.login_local:
            w.cmd(" login local", D, fl.get("login_local"))
        if vty.transport:
            warn = WARN_CISCO_SSH if "ssh" in vty.transport else None
            w.cmd(f" transport input {' '.join(vty.transport)}", D, fl.get("transport"), warn)
        w.notes(vty.notes)
        if "exit" in fl:
            w.exit_view(fl["exit"])
        w.separator()


def render(ir: DeviceConfigIR) -> list[RenderedLine]:
    w = LineWriter(C)
    for c in ir.comments:
        w.comment(c)
    w.separator()

    if "config_mode" in ir.field_lines:  # `system-view` -> always the first command
        w.cmd("configure terminal", D, ir.field_lines["config_mode"])
    if ir.hostname:
        w.cmd(f"hostname {ir.hostname}", D, ir.field_lines.get("hostname"))
    if ir.domain_name:
        w.cmd(f"ip domain name {ir.domain_name}", D, ir.field_lines.get("domain_name"))
    if ir.clock_timezone:
        tz = ir.clock_timezone
        w.cmd(f"clock timezone {tz.name} {format_cisco_timezone(tz.offset_minutes)}", T, tz.source_line)
    if ir.stp_bpdu_protection:
        w.cmd("spanning-tree portfast bpduguard default", D, ir.field_lines.get("stp_bpdu_protection"))
    if ir.stp_mode == "rstp":
        w.cmd("spanning-tree mode rapid-pvst", T, ir.field_lines.get("stp_mode"), WARN_STP_RSTP)
    if ir.stp_edge_default:
        w.cmd("spanning-tree portfast default", D, ir.field_lines.get("stp_edge_default"), WARN_STP_EDGE_DEFAULT)
    if ir.stp_root and ir.stp_root_vlans:
        vlans = format_cisco_vlan_list(ir.stp_root_vlans)
        w.cmd(f"spanning-tree vlan {vlans} root {ir.stp_root}", T, ir.field_lines.get("stp_root"))
    for banner in ir.banners:
        render_banner(w, banner)
    w.separator()

    for vlan in ir.vlans:
        w.cmd(f"vlan {vlan.vlan_id}", D, _first(vlan.source_lines))
        if vlan.name:
            warn = (
                f"VLAN {vlan.vlan_id}: ชื่อมีช่องว่าง ซึ่ง Cisco อาจไม่รับ กรุณาตรวจสอบ"
                if any(ch.isspace() for ch in vlan.name)
                else None
            )
            w.cmd(f" name {vlan.name}", D, vlan.field_lines.get("name"), warn)
        w.notes(vlan.notes)
        if "exit" in vlan.field_lines:
            w.exit_view(vlan.field_lines["exit"])
        w.separator()

    if ir.dhcp_snooping:
        snooping = ir.dhcp_snooping
        if snooping.enabled:
            w.cmd("ip dhcp snooping", D, snooping.field_lines.get("enabled"))
        if snooping.vlans:
            w.cmd(f"ip dhcp snooping vlan {format_cisco_vlan_list(snooping.vlans)}", S, snooping.field_lines.get("vlans"))
        w.separator()

    _render_acls(w, ir)

    objects = _render_track_objects(w, ir)  # global track objects before the HSRP/VRRP lines using them
    for iface in ir.interfaces:
        _render_interface(w, ir, iface, objects)

    if ir.ospf:
        _render_ospf(w, ir)
    if ir.rip:
        _render_rip(w, ir)
    if ir.bgp:
        _render_bgp(w, ir)

    for route in ir.static_routes:
        parts = ["ip route", str(route.destination.network_address), str(route.destination.netmask)]
        if route.exit_interface:
            parts.append(display_name(route.exit_interface, C))
        if route.next_hop:
            parts.append(str(route.next_hop))
        if route.preference is not None:
            parts.append(str(route.preference))
        warn = WARN_STATIC_DEFAULT_PREFERENCE if route.preference is None else None
        w.cmd(" ".join(parts), T, _first(route.source_lines), warn)
    if ir.default_gateway:
        w.cmd(f"ip default-gateway {ir.default_gateway}", D, ir.field_lines.get("default_gateway"))
    if ir.static_routes or ir.default_gateway:
        w.separator()

    for server in ir.ntp_servers:
        w.cmd(f"ntp server {server.address}", D, server.source_line)
    for host in ir.syslog_hosts:
        w.cmd(f"logging host {host.address}", D, host.source_line)
    if ir.syslog_source:
        w.cmd(f"logging source-interface {display_name(ir.syslog_source, C)}", D, ir.field_lines.get("syslog_source"))
    if ir.ntp_servers or ir.syslog_hosts or ir.syslog_source:
        w.separator()

    if ir.ssh_server:
        ssh, fl = ir.ssh_server, ir.ssh_server.field_lines
        if ssh.version2_only:
            w.cmd("ip ssh version 2", T, fl.get("version2_only"))
        if ssh.timeout is not None:
            w.cmd(f"ip ssh time-out {ssh.timeout}", D, fl.get("timeout"))
        if ssh.auth_retries is not None:
            w.cmd(f"ip ssh authentication-retries {ssh.auth_retries}", D, fl.get("auth_retries"))
        w.separator()
    _render_vty(w, ir)

    w.top_level_notes(ir.notes)
    w.cmd("end", D)
    if "save" in ir.field_lines:  # after end: write memory is a privileged EXEC command
        w.cmd("write memory", T, ir.field_lines["save"], WARN_WRITE_MEMORY)
    return w.lines
