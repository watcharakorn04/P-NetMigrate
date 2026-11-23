"""Tier-1 translation rules: System, VLAN & switchport, Interface & Serial, Static route, OSPFv2.

Covers both directions (Cisco IOS-XE <-> Huawei VRP), per-line provenance labels,
D/T/S categories, warnings, intentionally-unconverted commands and IR-level round-trip.
"""

import re
from pathlib import Path

import pytest

from app.core.engine import ConversionResult, convert
from app.core.ir import ConversionMode, Provenance, RenderedLine, SyntaxCategory, Vendor
from app.core.parsers import parse_config
from app.core.renderers import render_config

C = Vendor.CISCO_IOS_XE
H = Vendor.HUAWEI_VRP
FIXTURES = Path(__file__).parent / "fixtures"
CISCO_TIER1 = (FIXTURES / "cisco_tier1.txt").read_text(encoding="utf-8")
HUAWEI_TIER1 = (FIXTURES / "huawei_tier1.txt").read_text(encoding="utf-8")


def c2h(text: str) -> ConversionResult:
    return convert(text, C, H)


def h2c(text: str) -> ConversionResult:
    return convert(text, H, C)


def cmd(result: ConversionResult, text: str) -> RenderedLine:
    """The single non-comment output line whose stripped text equals `text`."""
    found = [l for l in result.lines if not l.is_comment and l.text.strip() == text]
    assert len(found) == 1, f"expected exactly one {text!r}, got {len(found)}:\n{result.text}"
    return found[0]


def has_cmd(result: ConversionResult, text: str) -> bool:
    return any(not l.is_comment and l.text.strip() == text for l in result.lines)


def comments_with(result: ConversionResult, needle: str) -> list[RenderedLine]:
    return [l for l in result.lines if l.is_comment and needle in l.text]


def commands(result: ConversionResult) -> list[str]:
    return [l.text for l in result.lines if not l.is_comment]


def block(result: ConversionResult, header: str) -> list[str]:
    """Command lines of the block starting at `header` (header included), up to the next top-level line."""
    out = commands(result)
    start = out.index(header)
    lines = [out[start]]
    for line in out[start + 1 :]:
        if not line.startswith(" "):
            break
        lines.append(line)
    return lines


# =========================================================================== Group 1: System


class TestSystem:
    def test_hostname_to_sysname(self):
        line = cmd(c2h("hostname R1\n"), "sysname R1")
        assert line.provenance is Provenance.RULE
        assert line.category is SyntaxCategory.DIRECT

    def test_sysname_to_hostname(self):
        line = cmd(h2c("sysname R2\n"), "hostname R2")
        assert line.provenance is Provenance.RULE
        assert line.category is SyntaxCategory.DIRECT

    @pytest.mark.parametrize("src", ["ip domain-name lab.local", "ip domain name lab.local"])
    def test_both_cisco_domain_forms(self, src):
        line = cmd(c2h(src + "\n"), "dns domain lab.local")
        assert line.category is SyntaxCategory.DIRECT

    def test_dns_domain_to_cisco(self):
        assert cmd(h2c("dns domain lab.local\n"), "ip domain name lab.local").provenance is Provenance.RULE

    def test_end_to_return(self):
        result = c2h("hostname R1\nend\n")
        assert commands(result)[-1] == "return"
        assert cmd(result, "return").category is SyntaxCategory.DIRECT

    def test_return_to_end(self):
        result = h2c("sysname R1\nreturn\n")
        assert commands(result)[-1] == "end"

    def test_end_marker_emitted_even_if_source_lacks_it(self):
        assert commands(c2h("hostname R1\n"))[-1] == "return"
        assert commands(h2c("sysname R1\n"))[-1] == "end"

    def test_comment_prefix_cisco_to_huawei(self):
        lines = comments_with(c2h("! Lab core switch\nhostname R1\n"), "Lab core switch")
        assert len(lines) == 1
        assert lines[0].text.startswith("#")
        assert not lines[0].text.startswith("#!")

    def test_comment_prefix_huawei_to_cisco(self):
        lines = comments_with(h2c("!Software Version V200\n#\nsysname R1\n"), "Software Version V200")
        assert len(lines) == 1
        assert lines[0].text.startswith("!")

    def test_output_separators_use_target_marker(self):
        result = c2h(CISCO_TIER1)
        assert not any(l.text.strip() == "!" for l in result.lines)
        assert any(l.text.strip() == "#" for l in result.lines)


# =========================================================================== Group 2: VLAN & switchport


class TestVlan:
    def test_vlan_name_to_description(self):
        result = c2h("vlan 10\n name SALES\n")
        assert block(result, "vlan 10") == ["vlan 10", " description SALES"]
        assert cmd(result, "description SALES").provenance is Provenance.RULE

    def test_vlan_description_to_name(self):
        assert block(h2c("vlan 10\n description SALES\n"), "vlan 10") == ["vlan 10", " name SALES"]

    def test_vlan_batch_expanded_into_individual_blocks(self):
        result = h2c("vlan batch 10 20 30 to 32\n")
        for vid in (10, 20, 30, 31, 32):
            line = cmd(result, f"vlan {vid}")
            assert line.provenance is Provenance.RULE
        assert not has_cmd(result, "vlan 33")

    def test_vlan_batch_category_is_transform(self):
        result = parse_config("vlan batch 10 20\n", H)
        assert result.line_status[1].category is SyntaxCategory.TRANSFORM

    def test_cisco_vlan_range_without_name_is_expanded(self):
        result = c2h("vlan 30-32\n")
        for vid in (30, 31, 32):
            assert has_cmd(result, f"vlan {vid}")

    def test_cisco_vlan_list_followed_by_name_is_unconverted(self):
        result = c2h("vlan 10,20\n name X\n")
        assert not has_cmd(result, "vlan 10")
        assert not has_cmd(result, "vlan 20")
        unconv = [l for l in result.lines if l.provenance is Provenance.UNCONVERTED]
        assert any("vlan 10,20" in l.text for l in unconv)
        assert any("name X" in l.text for l in unconv)
        assert all(l.is_comment and l.text.startswith("#") for l in unconv)

    def test_access_port_cisco_to_huawei(self):
        result = c2h("interface GigabitEthernet0/0/2\n switchport mode access\n switchport access vlan 10\n")
        assert block(result, "interface GigabitEthernet0/0/2") == [
            "interface GigabitEthernet0/0/2",
            " port link-type access",
            " port default vlan 10",
        ]

    def test_access_port_huawei_to_cisco(self):
        result = h2c("interface GigabitEthernet0/0/2\n port link-type access\n port default vlan 10\n")
        assert block(result, "interface GigabitEthernet0/0/2") == [
            "interface GigabitEthernet0/0/2",
            " switchport mode access",
            " switchport access vlan 10",
        ]

    def test_trunk_vlan_list_cisco_to_huawei(self):
        result = c2h(
            "interface GigabitEthernet0/0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20,30-35\n"
        )
        assert cmd(result, "port link-type trunk").category is SyntaxCategory.DIRECT
        line = cmd(result, "port trunk allow-pass vlan 10 20 30 to 35")
        assert line.category is SyntaxCategory.TRANSFORM
        assert line.provenance is Provenance.RULE

    def test_trunk_vlan_list_huawei_to_cisco(self):
        result = h2c("interface GigabitEthernet0/0/1\n port link-type trunk\n port trunk allow-pass vlan 10 20 30 to 35\n")
        assert cmd(result, "switchport mode trunk")
        assert cmd(result, "switchport trunk allowed vlan 10,20,30-35").category is SyntaxCategory.TRANSFORM

    def test_dot1q_encapsulation_is_not_needed_not_unconverted(self):
        result = c2h("interface GigabitEthernet0/0/1\n switchport trunk encapsulation dot1q\n switchport mode trunk\n")
        lines = comments_with(result, "switchport trunk encapsulation dot1q")
        assert len(lines) == 1
        assert lines[0].provenance is Provenance.NOT_NEEDED
        assert lines[0].provenance.value == "ไม่ต้องใช้คำสั่งนี้"
        assert lines[0].text.startswith("#")
        assert not [l for l in result.lines if l.provenance is Provenance.UNCONVERTED]

    def test_allow_pass_vlan_all_is_unconverted(self):
        result = h2c("interface GigabitEthernet0/0/1\n port link-type trunk\n port trunk allow-pass vlan all\n")
        assert not any("switchport trunk allowed vlan" in t for t in commands(result))
        lines = comments_with(result, "port trunk allow-pass vlan all")
        assert len(lines) == 1
        assert lines[0].provenance is Provenance.UNCONVERTED
        assert lines[0].text.startswith("!")

    def test_port_link_type_hybrid_is_unconverted(self):
        result = h2c("interface GigabitEthernet0/0/1\n port link-type hybrid\n")
        lines = comments_with(result, "port link-type hybrid")
        assert lines and lines[0].provenance is Provenance.UNCONVERTED
        assert not any(t.strip().startswith("switchport mode") for t in commands(result))

    @pytest.mark.parametrize(
        "src, vendor, expected",
        [
            ("interface GigabitEthernet0/0/2\n spanning-tree portfast\n", C, "stp edged-port enable"),
            ("interface GigabitEthernet0/0/2\n spanning-tree portfast edge\n", C, "stp edged-port enable"),
            ("interface GigabitEthernet0/0/2\n stp edged-port enable\n", H, "spanning-tree portfast"),
        ],
    )
    def test_stp_edge_port(self, src, vendor, expected):
        target = H if vendor is C else C
        line = cmd(convert(src, vendor, target), expected)
        assert line.category is SyntaxCategory.DIRECT

    @pytest.mark.parametrize(
        "src, vendor",
        [
            ("interface GigabitEthernet0/0/1\n switchport mode trunk\n", C),
            ("interface GigabitEthernet0/0/1\n port link-type trunk\n", H),
        ],
    )
    def test_trunk_without_explicit_vlan_list_warns(self, src, vendor):
        result = convert(src, vendor, H if vendor is C else C)
        assert any("VLAN" in w and "trunk" in w.lower() for w in result.warnings)


# =========================================================================== Group 3: Interface & Serial


class TestInterface:
    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("GigabitEthernet0/0/1", "GigabitEthernet0/0/1"),
            ("TenGigabitEthernet0/1/1", "XGigabitEthernet0/1/1"),
            ("FastEthernet0/1", "Ethernet0/1"),
            ("Loopback0", "LoopBack0"),
            ("Vlan10", "Vlanif10"),
            ("Port-channel1", "Eth-Trunk1"),
            ("Serial0/1/0", "Serial0/1/0"),
        ],
    )
    def test_type_name_mapping_both_ways_numbers_preserved(self, cisco, huawei):
        line = cmd(c2h(f"interface {cisco}\n description x\n"), f"interface {huawei}")
        assert line.provenance is Provenance.RULE
        assert line.category is SyntaxCategory.DIRECT
        assert has_cmd(h2c(f"interface {huawei}\n description x\n"), f"interface {cisco}")

    def test_cisco_abbreviated_name_expanded(self):
        assert has_cmd(c2h("interface Gi0/0/1\n description x\n"), "interface GigabitEthernet0/0/1")

    @pytest.mark.parametrize(
        "src, vendor, expected",
        [
            ("interface GigabitEthernet 0/0/1\n description x\n", C, "interface GigabitEthernet0/0/1"),
            ("interface vlan 10\n description x\n", C, "interface Vlanif10"),
            ("interface GE0/0/1\n description x\n", H, "interface GigabitEthernet0/0/1"),
            ("interface Vlanif 20\n description x\n", H, "interface Vlan20"),
        ],
    )
    def test_typed_and_alias_interface_names(self, src, vendor, expected):
        assert has_cmd(convert(src, vendor, H if vendor is C else C), expected)

    def test_unknown_interface_type_kept_as_comment(self):
        result = c2h("interface Dialer1\n description x\n")
        assert comments_with(result, "interface Dialer1")[0].provenance is Provenance.UNCONVERTED

    def test_non_zero_slot_warns_and_number_kept(self):
        result = c2h("interface GigabitEthernet1/0/3\n shutdown\n")
        line = cmd(result, "interface GigabitEthernet1/0/3")
        assert line.warning and "สล็อต" in line.warning
        assert line.warning in result.warnings

    @pytest.mark.parametrize("name", ["GigabitEthernet0/0/1", "Loopback1", "Vlan20", "Port-channel2"])
    def test_no_slot_warning_for_slot_zero_or_virtual(self, name):
        result = c2h(f"interface {name}\n description x\n")
        assert not any("สล็อต" in w for w in result.warnings)

    def test_prefix_length_rendered_as_dotted_mask(self):
        result = h2c("interface Vlanif10\n ip address 192.168.10.1 24\n")
        line = cmd(result, "ip address 192.168.10.1 255.255.255.0")
        assert line.category is SyntaxCategory.TRANSFORM

    def test_ip_address_and_description_cisco_to_huawei(self):
        result = c2h("interface GigabitEthernet0/0/0\n description Uplink to ISP\n ip address 10.0.0.1 255.255.255.252\n")
        assert cmd(result, "description Uplink to ISP")
        assert cmd(result, "ip address 10.0.0.1 255.255.255.252").category is SyntaxCategory.DIRECT

    @pytest.mark.parametrize(
        "src, vendor, expected",
        [
            (" shutdown", C, "shutdown"),
            (" no shutdown", C, "undo shutdown"),
            (" shutdown", H, "shutdown"),
            (" undo shutdown", H, "no shutdown"),
        ],
    )
    def test_shutdown_states(self, src, vendor, expected):
        result = convert(f"interface GigabitEthernet0/0/1\n{src}\n", vendor, H if vendor is C else C)
        assert cmd(result, expected).provenance is Provenance.RULE

    def test_shutdown_left_unset_when_omitted(self):
        result = c2h("interface GigabitEthernet0/0/1\n description x\n")
        assert not any("shutdown" in t for t in commands(result))
        result = h2c("interface GigabitEthernet0/0/1\n description x\n")
        assert not any("shutdown" in t for t in commands(result))

    def test_encapsulation_ppp_both_ways(self):
        assert cmd(c2h("interface Serial0/1/0\n encapsulation ppp\n"), "link-protocol ppp").category is SyntaxCategory.DIRECT
        assert has_cmd(h2c("interface Serial0/1/0\n link-protocol ppp\n"), "encapsulation ppp")

    @pytest.mark.parametrize(
        "src, vendor, expected",
        [
            ("interface Serial0/1/0\n encapsulation hdlc\n", C, "link-protocol hdlc"),
            ("interface Serial0/1/0\n link-protocol hdlc\n", H, "encapsulation hdlc"),
        ],
    )
    def test_hdlc_converted_with_mandatory_ppp_warning(self, src, vendor, expected):
        result = convert(src, vendor, H if vendor is C else C)
        line = cmd(result, expected)
        assert line.warning and "HDLC" in line.warning and "PPP" in line.warning

    def test_serial_without_link_protocol_warns_default_mismatch(self):
        result = c2h("interface Serial0/1/0\n ip address 10.1.1.1 255.255.255.252\n")
        assert any("HDLC" in w and "PPP" in w for w in result.warnings)

    def test_tunnel_interface_out_of_scope_kept_as_comment(self):
        result = c2h("interface Tunnel0\n ip address 10.9.9.1 255.255.255.0\n")
        unconv = [l for l in result.lines if l.provenance is Provenance.UNCONVERTED]
        assert any("interface Tunnel0" in l.text for l in unconv)
        assert any("ip address 10.9.9.1" in l.text for l in unconv)
        assert not any("Tunnel" in t for t in commands(result))

    def test_ipv6_line_inside_interface_kept_as_target_comment(self):
        result = c2h("interface GigabitEthernet0/0/1\n ipv6 address 2001:db8::1/64\n")
        lines = comments_with(result, "ipv6 address 2001:db8::1/64")
        assert len(lines) == 1
        assert lines[0].provenance is Provenance.UNCONVERTED
        assert lines[0].text.startswith("#")
        assert "IPv6" in (lines[0].warning or "")


# =========================================================================== Group 4: Static route


class TestStaticRoute:
    def test_distance_to_preference(self):
        line = cmd(c2h("ip route 172.16.0.0 255.255.0.0 10.1.1.2 200\n"), "ip route-static 172.16.0.0 255.255.0.0 10.1.1.2 preference 200")
        assert line.provenance is Provenance.RULE
        assert line.category is SyntaxCategory.TRANSFORM
        assert line.warning is None

    def test_preference_to_distance(self):
        assert has_cmd(h2c("ip route-static 172.16.0.0 255.255.0.0 10.1.1.1 preference 200\n"), "ip route 172.16.0.0 255.255.0.0 10.1.1.1 200")

    def test_prefix_length_route_to_dotted_mask(self):
        assert has_cmd(h2c("ip route-static 172.16.0.0 16 10.1.1.1\n"), "ip route 172.16.0.0 255.255.0.0 10.1.1.1")

    @pytest.mark.parametrize(
        "src, vendor, expected",
        [
            ("ip route 0.0.0.0 0.0.0.0 10.1.1.2\n", C, "ip route-static 0.0.0.0 0.0.0.0 10.1.1.2"),
            ("ip route-static 0.0.0.0 0.0.0.0 10.1.1.1\n", H, "ip route 0.0.0.0 0.0.0.0 10.1.1.1"),
        ],
    )
    def test_omitted_distance_kept_unset_with_ad_mismatch_warning(self, src, vendor, expected):
        result = convert(src, vendor, H if vendor is C else C)
        line = cmd(result, expected)
        assert line.warning and "AD=1" in line.warning and "60" in line.warning
        assert result.ir.static_routes[0].preference is None

    def test_exit_interface_route(self):
        assert has_cmd(c2h("ip route 10.2.0.0 255.255.0.0 Serial0/1/0\n"), "ip route-static 10.2.0.0 255.255.0.0 Serial0/1/0")

    def test_named_route_is_unconverted(self):
        result = c2h("ip route 10.0.0.0 255.0.0.0 10.1.1.2 name BACKUP\n")
        assert not any(t.startswith("ip route-static") for t in commands(result))
        lines = comments_with(result, "name BACKUP")
        assert len(lines) == 1 and lines[0].provenance is Provenance.UNCONVERTED


# =========================================================================== Group 5: OSPFv2


CISCO_OSPF = """router ospf 1
 router-id 1.1.1.1
 passive-interface Vlan10
 network 192.168.10.0 0.0.0.255 area 0
 network 10.1.1.0 0.0.0.3 area 0
 network 1.1.1.1 0.0.0.0 area 1
 area 1 stub
 default-information originate
"""

HUAWEI_OSPF = """ospf 1 router-id 1.1.1.1
 silent-interface Vlanif10
 default-route-advertise
 area 0.0.0.0
  network 192.168.10.0 0.0.0.255
  network 10.1.1.0 0.0.0.3
 area 0.0.0.1
  network 1.1.1.1 0.0.0.0
  stub
"""


class TestOspf:
    def test_cisco_to_huawei_structure(self):
        result = c2h(CISCO_OSPF)
        assert block(result, "ospf 1 router-id 1.1.1.1") == [
            "ospf 1 router-id 1.1.1.1",
            " silent-interface Vlanif10",
            " default-route-advertise",
            " area 0.0.0.0",
            "  network 192.168.10.0 0.0.0.255",
            "  network 10.1.1.0 0.0.0.3",
            " area 0.0.0.1",
            "  stub",
            "  network 1.1.1.1 0.0.0.0",
        ]

    def test_huawei_to_cisco_structure(self):
        result = h2c(HUAWEI_OSPF)
        assert block(result, "router ospf 1") == [
            "router ospf 1",
            " router-id 1.1.1.1",
            " passive-interface Vlan10",
            " network 192.168.10.0 0.0.0.255 area 0",
            " network 10.1.1.0 0.0.0.3 area 0",
            " network 1.1.1.1 0.0.0.0 area 1",
            " area 1 stub",
            " default-information originate",
        ]

    @pytest.mark.parametrize("src, vendor", [(CISCO_OSPF, C), (HUAWEI_OSPF, H)])
    def test_all_ospf_lines_structural_and_rule(self, src, vendor):
        result = convert(src, vendor, H if vendor is C else C)
        ospf = [l for l in result.lines if not l.is_comment and l.text.strip() not in ("#", "!", "end", "return")]
        assert ospf
        assert all(l.category is SyntaxCategory.STRUCTURAL for l in ospf)
        assert all(l.provenance is Provenance.RULE for l in ospf)

    def test_router_id_optional(self):
        assert has_cmd(c2h("router ospf 5\n network 10.0.0.0 0.0.0.255 area 0\n"), "ospf 5")

    def test_dotted_area_on_cisco_side(self):
        result = c2h("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0.0.0.2\n")
        assert has_cmd(result, "area 0.0.0.2")

    def test_abbreviated_passive_interface(self):
        assert has_cmd(c2h("router ospf 1\n passive-interface Gi0/0/1\n"), "silent-interface GigabitEthernet0/0/1")

    def test_spaced_silent_interface(self):
        assert has_cmd(h2c("ospf 1\n silent-interface GigabitEthernet 0/0/1\n"), "passive-interface GigabitEthernet0/0/1")

    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("ip ospf cost 10", "ospf cost 10"),
            ("ip ospf priority 100", "ospf dr-priority 100"),
            ("ip ospf network point-to-point", "ospf network-type p2p"),
        ],
    )
    def test_interface_level_parameters_both_ways(self, cisco, huawei):
        assert cmd(c2h(f"interface GigabitEthernet0/0/1\n {cisco}\n"), huawei).provenance is Provenance.RULE
        assert has_cmd(h2c(f"interface GigabitEthernet0/0/1\n {huawei}\n"), cisco)

    @pytest.mark.parametrize(
        "line",
        [
            " area 1 nssa",
            " area 1 virtual-link 2.2.2.2",
            " area 1 range 10.0.0.0 255.255.0.0",
            " area 1 stub no-summary",
            " timers throttle spf 10 100 5000",
        ],
    )
    def test_unsupported_cisco_ospf_kept_as_comment(self, line):
        result = c2h(f"router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n{line}\n")
        lines = comments_with(result, line.strip())
        assert len(lines) == 1
        assert lines[0].provenance is Provenance.UNCONVERTED
        assert lines[0].text.startswith("#")
        assert lines[0].warning
        assert has_cmd(result, "network 10.0.0.0 0.0.0.255")
        ospf_block = [b for b in result.blocks if b.header.startswith("router ospf")]
        assert ospf_block and ospf_block[0].complete is False

    @pytest.mark.parametrize("line", ["  nssa", "  vlink-peer 2.2.2.2", "  abr-summary 10.0.0.0 255.255.0.0", "  stub no-summary"])
    def test_unsupported_huawei_ospf_area_options_kept_as_comment(self, line):
        result = h2c(f"ospf 1\n area 0.0.0.1\n  network 10.0.0.0 0.0.0.255\n{line}\n")
        lines = comments_with(result, line.strip())
        assert len(lines) == 1
        assert lines[0].provenance is Provenance.UNCONVERTED
        assert lines[0].text.startswith("!")

    def test_supported_block_reports_complete(self):
        result = c2h(CISCO_OSPF)
        ospf_block = [b for b in result.blocks if b.header.startswith("router ospf")]
        assert ospf_block[0].complete is True

    def test_multi_process_second_process_unconverted(self):
        result = c2h("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n!\nrouter ospf 2\n network 10.9.0.0 0.0.0.255 area 0\n")
        assert has_cmd(result, "ospf 1")
        assert not has_cmd(result, "ospf 2")
        lines = comments_with(result, "router ospf 2")
        assert lines and lines[0].provenance is Provenance.UNCONVERTED
        assert comments_with(result, "network 10.9.0.0 0.0.0.255 area 0")


# =========================================================================== round-trip & labels


class TestRoundTrip:
    def test_cisco_huawei_cisco_preserves_ir(self):
        original = parse_config(CISCO_TIER1, C).ir
        huawei_text = c2h(CISCO_TIER1).text
        back = parse_config(huawei_text, H).ir
        assert back.intent() == original.intent()

    def test_huawei_cisco_huawei_preserves_ir(self):
        original = parse_config(HUAWEI_TIER1, H).ir
        cisco_text = h2c(HUAWEI_TIER1).text
        back = parse_config(cisco_text, C).ir
        assert back.intent() == original.intent()

    def test_intent_ignores_vendor_and_line_numbers(self):
        a = parse_config("hostname R1\n", C).ir
        b = parse_config("#\n\nsysname R1\n", H).ir
        assert a.intent() == b.intent()

    def test_render_config_direct(self):
        ir = parse_config("hostname R1\n", C).ir
        lines = render_config(ir, H)
        assert [l.text for l in lines if not l.is_comment][:1] == ["sysname R1"]


class TestFullFileAndLabels:
    @pytest.mark.parametrize("src, vendor", [(CISCO_TIER1, C), (HUAWEI_TIER1, H)])
    def test_every_line_has_exactly_one_label(self, src, vendor):
        result = convert(src, vendor, H if vendor is C else C)
        assert result.lines
        assert all(isinstance(l.provenance, Provenance) for l in result.lines)

    @pytest.mark.parametrize("src, vendor", [(CISCO_TIER1, C), (HUAWEI_TIER1, H)])
    def test_in_scope_fixture_fully_converted(self, src, vendor):
        result = convert(src, vendor, H if vendor is C else C)
        assert result.unconverted_items == []
        assert all(b.complete for b in result.blocks)

    def test_comment_lines_use_target_marker(self):
        result = c2h(CISCO_TIER1 + "interface Tunnel1\n description x\n")
        assert all(l.text.lstrip().startswith("#") for l in result.lines if l.is_comment)

    def test_annotated_text_contains_labels(self):
        result = c2h("hostname R1\nipv6 unicast-routing\n")
        assert "[มาจากกฎ] sysname R1" in result.annotated_text
        assert Provenance.UNCONVERTED.value in result.annotated_text

    def test_unconverted_items_listed_for_manual_ai_selection(self):
        result = c2h("hostname R1\nipv6 unicast-routing\n")
        assert [(i.line_no, i.command) for i in result.unconverted_items] == [(2, "ipv6 unicast-routing")]
        assert "IPv6" in result.unconverted_items[0].reason

    @pytest.mark.parametrize(
        "src, expected",
        [
            ("interface GigabitEthernet0/0/1\n description uplink-to-vrf-core\n", "description uplink-to-vrf-core"),
            ("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n neighbor 10.0.0.2 description ipv6-ready ISP\n",
             "peer 10.0.0.2 description ipv6-ready ISP"),
        ],
    )
    def test_free_text_mentioning_out_of_scope_words_is_converted(self, src, expected):
        """Regression: the free-text exemption regex once held a literal backspace and never matched."""
        result = c2h(src)
        assert cmd(result, expected).provenance is Provenance.RULE
        assert result.unconverted_items == []

    def test_unknown_command_never_silently_dropped(self):
        result = c2h("hostname R1\nservice timestamps debug datetime msec\n")
        lines = comments_with(result, "service timestamps debug datetime msec")
        assert lines and lines[0].provenance is Provenance.UNCONVERTED

    def test_same_vendor_rejected(self):
        with pytest.raises(ValueError):
            convert("hostname R1\n", C, C)


class TestModes:
    def test_rule_only_is_default_for_engine_and_needs_no_ai(self):
        result = c2h("hostname R1\n")
        assert result.effective_mode is ConversionMode.RULE_ONLY
        assert result.notices == []

    @pytest.mark.parametrize("mode", [ConversionMode.HYBRID, ConversionMode.AI_ONLY])
    def test_ai_mode_without_ai_falls_back_to_rule_only_and_tells_user(self, mode):
        result = convert("hostname R1\n", C, H, mode=mode, ai_available=False)
        assert result.requested_mode is mode
        assert result.effective_mode is ConversionMode.RULE_ONLY
        assert result.notices
        assert cmd(result, "sysname R1").provenance is Provenance.RULE


class TestEngineSecurity:
    """Zero-leak through the full pipeline (Non-Negotiable #2). Never weaken."""

    @pytest.mark.parametrize(
        "fixture, vendor, secrets",
        [
            ("cisco_with_secrets.txt", C, ["$9$CiscoEnableHashXyZ", "PlainEnablePw1", "netadmin", "OspfMd5Key77",
                                           "BgpNeighPw99", "PubCommRO", "TacacsKey55", "VtyLinePw42", "ConsoleSecret8"]),
            ("huawei_with_secrets.txt", H, ["SuperCipherQwE", "huaadmin", "$1a$LocalUserHashZz$", "OspfHuaKey33",
                                            "HuaBgpPw88", "HuaPubComm", "HuaVtyPw21"]),
        ],
    )
    def test_no_secret_in_any_output(self, fixture, vendor, secrets):
        text = (FIXTURES / fixture).read_text(encoding="utf-8")
        result = convert(text, vendor, H if vendor is C else C)
        everything = "\n".join(
            [result.text, result.annotated_text, *result.warnings]
            + [f"{i.command} {i.reason}" for i in result.unconverted_items]
            + [l.warning or "" for l in result.lines]
        )
        for secret in secrets:
            assert secret not in everything, secret
        system = [l for l in result.lines if l.provenance is Provenance.SYSTEM]
        advisories = [l for l in system if l.is_comment and "ตัดข้อมูลลับออก" in l.text]
        assert len(advisories) == result.secret_stripped_count > 0
        target_marker = (H if vendor is C else C).comment_marker
        assert all(l.text.startswith(target_marker) for l in advisories)
        # The only system-generated COMMANDS allowed are the mandatory Huawei BGP activation
        # block (proposal §2.3.2 item 5) — never anything derived from a secret.
        generated = [l.text.strip() for l in system if not l.is_comment]
        assert all(re.fullmatch(r"ipv4-family unicast|peer \S+ enable", t) for t in generated), generated
