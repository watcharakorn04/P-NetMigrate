"""Tier-3 translation rules: single-AS IPv4 BGP and IPv4 ACLs.

Tier 3 is "not done until behavioural tests exist" (CLAUDE.md §6): both features fail
silently on a device. Besides syntax checks this file verifies
  * every Huawei BGP peer is activated inside `ipv4-family unicast` (else no routes flow),
  * packets get the same permit/deny decision from the source ACL and the converted ACL,
  * ACL numbers are mapped by TYPE, never copied (proposal §2.3.2 item 3).
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Optional

import pytest

from app.core.engine import convert
from app.core.ir import AclIR, Provenance, SyntaxCategory
from app.core.parsers import parse_config
from tests.helpers import C, H, block, block_result, c2h, cmd, commands, comments_with, h2c, has_cmd

S, T = SyntaxCategory.STRUCTURAL, SyntaxCategory.TRANSFORM


def assert_unconverted(result, needle: str, reason_has: Optional[str] = None):
    lines = comments_with(result, needle)
    assert lines, f"{needle!r} not preserved as a comment:\n{result.annotated_text}"
    assert all(l.provenance is Provenance.UNCONVERTED for l in lines)
    assert all(l.text.startswith(result.target_vendor.comment_marker) for l in lines)
    if reason_has:
        assert any(reason_has in (l.warning or "") for l in lines), [l.warning for l in lines]
    return lines


# =========================================================================== BGP


CISCO_BGP = """router bgp 65001
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65002
 neighbor 10.0.0.6 remote-as 65003
 network 192.168.1.0 mask 255.255.255.0
"""


def huawei_ipv4_family(result) -> list[str]:
    out = commands(result)
    start = out.index(" ipv4-family unicast")
    lines = []
    for line in out[start + 1 :]:
        if not line.startswith("  "):
            break
        lines.append(line.strip())
    return lines


class TestBgpCiscoToHuawei:
    def test_block_structure(self):
        result = c2h(CISCO_BGP)
        assert block(result, "bgp 65001") == [
            "bgp 65001",
            " router-id 1.1.1.1",
            " peer 10.0.0.2 as-number 65002",
            " peer 10.0.0.6 as-number 65003",
            " ipv4-family unicast",
            "  network 192.168.1.0 255.255.255.0",
            "  peer 10.0.0.2 enable",
            "  peer 10.0.0.6 enable",
        ]

    def test_converted_lines_are_rule_structural(self):
        result = c2h(CISCO_BGP)
        for text in ("bgp 65001", "router-id 1.1.1.1", "peer 10.0.0.2 as-number 65002", "network 192.168.1.0 255.255.255.0"):
            line = cmd(result, text)
            assert (line.provenance, line.category) == (Provenance.RULE, S), text

    def test_ipv4_family_and_peer_enable_auto_generated_as_system(self):
        """Proposal §2.3.2 item 3: without these Huawei peers come up but exchange no routes."""
        result = c2h(CISCO_BGP)
        for text in ("ipv4-family unicast", "peer 10.0.0.2 enable", "peer 10.0.0.6 enable"):
            line = cmd(result, text)
            assert line.provenance is Provenance.SYSTEM, text
            assert line.provenance.value == "ระบบสร้างขึ้นเอง"
        assert cmd(result, "peer 10.0.0.2 enable").warning
        assert cmd(result, "peer 10.0.0.2 enable").warning in result.warnings

    def test_behaviour_every_neighbor_is_activated(self):
        neighbors = [f"10.0.{i}.2" for i in range(6)]
        text = "router bgp 65001\n" + "".join(f" neighbor {n} remote-as 6510{i}\n" for i, n in enumerate(neighbors))
        result = c2h(text)
        assert huawei_ipv4_family(result) == [f"peer {n} enable" for n in neighbors]

    def test_ipv4_family_emitted_even_without_networks(self):
        result = c2h("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n")
        assert huawei_ipv4_family(result) == ["peer 10.0.0.2 enable"]

    def test_classful_network_gets_explicit_mask(self):
        assert has_cmd(c2h("router bgp 65001\n network 10.0.0.0\n"), "network 10.0.0.0 255.0.0.0")

    def test_neighbor_description(self):
        result = c2h(CISCO_BGP + " neighbor 10.0.0.2 description ISP A\n")
        assert has_cmd(result, "peer 10.0.0.2 description ISP A")

    def test_address_family_ipv4_block_accepted(self):
        text = (
            "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n !\n address-family ipv4\n"
            "  network 192.168.1.0 mask 255.255.255.0\n  neighbor 10.0.0.2 activate\n exit-address-family\n"
        )
        result = c2h(text)
        assert huawei_ipv4_family(result) == ["network 192.168.1.0 255.255.255.0", "peer 10.0.0.2 enable"]
        assert block_result(result, "router bgp").complete is True

    def test_no_default_ipv4_unicast_only_activated_neighbors_enabled(self):
        text = (
            "router bgp 65001\n no bgp default ipv4-unicast\n neighbor 10.0.0.2 remote-as 65002\n"
            " neighbor 10.0.0.6 remote-as 65003\n address-family ipv4\n  neighbor 10.0.0.2 activate\n"
        )
        result = c2h(text)
        assert huawei_ipv4_family(result) == ["peer 10.0.0.2 enable"]
        assert has_cmd(result, "peer 10.0.0.6 as-number 65003")

    @pytest.mark.parametrize("line", [" no synchronization", " no auto-summary"])
    def test_target_default_lines_not_needed(self, line):
        result = c2h(CISCO_BGP + line + "\n")
        found = comments_with(result, line.strip())
        assert found and found[0].provenance is Provenance.NOT_NEEDED

    @pytest.mark.parametrize(
        "line, reason",
        [
            (" neighbor 10.0.0.2 peer-group CORE", "Peer Group"),
            (" neighbor CORE peer-group", "Peer Group"),
            (" neighbor 10.0.0.2 route-reflector-client", "Route Reflector"),
            (" bgp cluster-id 1.1.1.1", "Route Reflector"),
            (" bgp confederation identifier 100", "Confederation"),
            (" neighbor 10.0.0.2 prefix-list PL in", "กรองเส้นทาง"),
            (" neighbor 10.0.0.2 distribute-list 10 in", "กรองเส้นทาง"),
            (" neighbor 10.0.0.2 route-map RM in", "Route-Map"),
        ],
    )
    def test_unsupported_features_kept_as_comment(self, line, reason):
        result = c2h(CISCO_BGP + line + "\n")
        assert_unconverted(result, line.strip(), reason)
        assert block_result(result, "router bgp").complete is False
        assert has_cmd(result, "peer 10.0.0.2 as-number 65002")

    @pytest.mark.parametrize("af", ["address-family vpnv4", "address-family ipv4 multicast", "address-family ipv6"])
    def test_other_address_families_unconverted(self, af):
        result = c2h(CISCO_BGP + f" {af}\n  neighbor 10.0.0.2 activate\n exit-address-family\n")
        assert_unconverted(result, af)
        assert_unconverted(result, "neighbor 10.0.0.2 activate")

    def test_second_as_unconverted(self):
        result = c2h(CISCO_BGP + "!\nrouter bgp 65009\n neighbor 10.9.9.9 remote-as 65010\n")
        assert_unconverted(result, "router bgp 65009", "AS")
        assert not has_cmd(result, "peer 10.9.9.9 as-number 65010")

    def test_neighbor_password_stripped(self):
        result = c2h(CISCO_BGP + " neighbor 10.0.0.2 password BgpPw1\n")
        assert "BgpPw1" not in result.text + result.annotated_text
        assert block_result(result, "router bgp").complete is True


HUAWEI_BGP = """bgp 65002
 router-id 2.2.2.2
 peer 10.0.0.1 as-number 65001
 #
 ipv4-family unicast
  undo synchronization
  network 192.168.2.0 255.255.255.0
  peer 10.0.0.1 enable
"""


class TestBgpHuaweiToCisco:
    def test_block_structure(self):
        result = h2c(HUAWEI_BGP)
        assert block(result, "router bgp 65002") == [
            "router bgp 65002",
            " bgp router-id 2.2.2.2",
            " neighbor 10.0.0.1 remote-as 65001",
            " network 192.168.2.0 mask 255.255.255.0",
        ]
        assert cmd(result, "neighbor 10.0.0.1 remote-as 65001").provenance is Provenance.RULE
        assert block_result(result, "bgp 65002").complete is True

    def test_undo_synchronization_not_needed(self):
        found = comments_with(h2c(HUAWEI_BGP), "undo synchronization")
        assert found and found[0].provenance is Provenance.NOT_NEEDED

    def test_peer_not_enabled_is_not_activated_on_cisco(self):
        text = (
            "bgp 65002\n peer 10.0.0.1 as-number 65001\n peer 10.0.0.5 as-number 65005\n"
            " ipv4-family unicast\n  peer 10.0.0.1 enable\n"
        )
        result = h2c(text)
        assert block(result, "router bgp 65002") == [
            "router bgp 65002",
            " no bgp default ipv4-unicast",
            " neighbor 10.0.0.1 remote-as 65001",
            " neighbor 10.0.0.5 remote-as 65005",
            " address-family ipv4",
            "  neighbor 10.0.0.1 activate",
            " exit-address-family",
        ]

    def test_network_with_prefix_length_and_directly_under_bgp(self):
        result = h2c("bgp 65002\n network 172.16.0.0 16\n")
        assert has_cmd(result, "network 172.16.0.0 mask 255.255.0.0")

    @pytest.mark.parametrize(
        "line, reason",
        [
            (" group CORE internal", "Peer Group"),
            (" peer 10.0.0.1 group CORE", "Peer Group"),
            (" confederation id 100", "Confederation"),
            (" reflector cluster-id 1", "Route Reflector"),
        ],
    )
    def test_unsupported_bgp_level(self, line, reason):
        result = h2c(HUAWEI_BGP.replace(" #\n", line + "\n #\n"))
        assert_unconverted(result, line.strip(), reason)

    @pytest.mark.parametrize(
        "line, reason",
        [
            ("  peer 10.0.0.1 reflect-client", "Route Reflector"),
            ("  peer 10.0.0.1 ip-prefix PL import", "กรองเส้นทาง"),
            ("  filter-policy 2000 import", "กรองเส้นทาง"),
        ],
    )
    def test_unsupported_ipv4_family_level(self, line, reason):
        result = h2c(HUAWEI_BGP + line + "\n")
        assert_unconverted(result, line.strip(), reason)

    @pytest.mark.parametrize("af", ["ipv4-family vpnv4", "ipv6-family unicast", "l2vpn-family evpn"])
    def test_other_families_unconverted(self, af):
        result = h2c(HUAWEI_BGP + f" {af}\n  peer 10.0.0.1 enable\n")
        assert_unconverted(result, af)

    def test_round_trip(self):
        original = parse_config(CISCO_BGP, C).ir
        assert parse_config(c2h(CISCO_BGP).text, H).ir.intent() == original.intent()
        original = parse_config(HUAWEI_BGP, H).ir
        assert parse_config(h2c(HUAWEI_BGP).text, C).ir.intent() == original.intent()


# =========================================================================== ACL numbering


NUMBER_MAP = [
    # (cisco, huawei, kind)
    (1, 2000, "standard"),
    (10, 2009, "standard"),
    (99, 2098, "standard"),
    (1300, 2100, "standard"),
    (1999, 2799, "standard"),
    (100, 3000, "extended"),
    (199, 3099, "extended"),
    (2000, 3100, "extended"),
    (2699, 3799, "extended"),
]


def cisco_entry(kind: str) -> str:
    return "permit 10.0.0.0 0.0.0.255" if kind == "standard" else "permit ip any any"


def huawei_rule(kind: str) -> str:
    return "rule 5 permit source 10.0.0.0 0.0.0.255" if kind == "standard" else "rule 5 permit ip"


class TestAclNumbering:
    @pytest.mark.parametrize("cisco, huawei, kind", NUMBER_MAP)
    def test_cisco_number_mapped_by_type(self, cisco, huawei, kind):
        result = c2h(f"access-list {cisco} {cisco_entry(kind)}\n")
        header = cmd(result, f"acl number {huawei}")
        assert header.provenance is Provenance.SYSTEM
        assert header.category is T
        assert header.warning and "ชน" in header.warning  # collision warning
        assert has_cmd(result, huawei_rule(kind))
        assert not has_cmd(result, f"acl number {cisco}")

    @pytest.mark.parametrize("cisco, huawei, kind", NUMBER_MAP)
    def test_huawei_number_mapped_by_type(self, cisco, huawei, kind):
        result = h2c(f"acl number {huawei}\n {huawei_rule(kind)}\n")
        header = cmd(result, f"ip access-list {kind} {cisco}")
        assert header.provenance is Provenance.SYSTEM
        assert header.warning
        assert has_cmd(result, cisco_entry(kind))

    def test_cisco_2000_extended_never_becomes_huawei_basic_2000(self):
        """The overlap the proposal calls out: same number, different meaning."""
        result = c2h("access-list 2000 permit tcp any any eq 22\n")
        assert has_cmd(result, "acl number 3100")
        assert not has_cmd(result, "acl number 2000")

    def test_ip_access_list_numbered_form(self):
        result = c2h("ip access-list standard 10\n permit host 10.0.0.1\n")
        assert has_cmd(result, "acl number 2009")
        assert has_cmd(result, "rule 5 permit source 10.0.0.1 0")

    def test_huawei_short_acl_form(self):
        assert has_cmd(h2c("acl 3000\n rule 5 permit ip\n"), "ip access-list extended 100")

    @pytest.mark.parametrize("number", [2800, 2999, 3800, 3999, 2099])
    def test_huawei_ranges_without_cisco_equivalent(self, number):
        rule = "rule 5 permit source 10.0.0.0 0.0.0.255" if number < 3000 else "rule 5 permit ip"
        result = h2c(f"acl number {number}\n {rule}\n#\ninterface GigabitEthernet0/0/1\n traffic-filter inbound acl {number}\n")
        lines = assert_unconverted(result, f"acl number {number}")
        assert "Cisco" in lines[0].warning and "ช่วงหมายเลข" in lines[0].warning
        assert_unconverted(result, rule)
        assert_unconverted(result, f"traffic-filter inbound acl {number}")
        assert not any(l.startswith("ip access-list") for l in commands(result))
        assert not has_cmd(result, f"ip access-group {number} in")

    def test_cisco_numbers_outside_ip_ranges_unconverted(self):
        result = c2h("access-list 700 permit 0011.2233.4455 0000.0000.0000\n")
        assert_unconverted(result, "access-list 700", "ชั้นที่ 2")

    @pytest.mark.parametrize("number, reason", [(4000, "ชั้นที่ 2"), (5000, "User-Defined")])
    def test_huawei_l2_and_user_defined_unconverted(self, number, reason):
        result = h2c(f"acl number {number}\n rule 5 permit\n")
        assert_unconverted(result, f"acl number {number}", reason)


# =========================================================================== ACL entries


class TestAclEntries:
    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("permit ip any any", "permit ip"),
            ("deny ip host 10.0.0.1 any", "deny ip source 10.0.0.1 0"),
            ("permit ip 10.0.0.0 0.0.0.255 172.16.0.0 0.0.255.255",
             "permit ip source 10.0.0.0 0.0.0.255 destination 172.16.0.0 0.0.255.255"),
            ("permit tcp any host 10.1.1.1 eq 80", "permit tcp destination 10.1.1.1 0 destination-port eq 80"),
            ("permit tcp any host 10.1.1.1 eq www", "permit tcp destination 10.1.1.1 0 destination-port eq 80"),
            ("permit udp any any eq domain", "permit udp destination-port eq 53"),
            ("permit tcp host 10.0.0.9 gt 1023 any lt 1024",
             "permit tcp source 10.0.0.9 0 source-port gt 1023 destination-port lt 1024"),
            ("permit tcp any any range 8000 8080", "permit tcp destination-port range 8000 8080"),
            ("deny icmp any any", "deny icmp"),
        ],
    )
    def test_extended_entries(self, cisco, huawei):
        result = c2h(f"ip access-list extended X1\n {cisco}\n")
        assert has_cmd(result, "acl name X1 advance")
        line = cmd(result, f"rule 5 {huawei}")
        assert (line.provenance, line.category) == (Provenance.RULE, T)

    @pytest.mark.parametrize(
        "huawei, cisco",
        [
            ("rule 5 permit ip source any destination any", "permit ip any any"),
            ("rule 5 permit tcp source 10.0.0.0 0.0.0.255 destination-port eq www", "permit tcp 10.0.0.0 0.0.0.255 any eq 80"),
            ("rule 5 deny udp destination 10.0.0.5 0 destination-port eq snmp", "deny udp any host 10.0.0.5 eq 161"),
        ],
    )
    def test_huawei_entries_to_cisco(self, huawei, cisco):
        result = h2c(f"acl name X1 advance\n {huawei}\n")
        assert has_cmd(result, "ip access-list extended X1")
        assert has_cmd(result, cisco)

    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("permit any", "permit"),
            ("permit host 10.0.0.1", "permit source 10.0.0.1 0"),
            ("permit 10.0.0.1", "permit source 10.0.0.1 0"),
            ("deny 10.0.0.0 0.0.0.255", "deny source 10.0.0.0 0.0.0.255"),
        ],
    )
    def test_standard_entries(self, cisco, huawei):
        result = c2h(f"ip access-list standard S1\n {cisco}\n")
        assert has_cmd(result, "acl name S1 basic")
        assert has_cmd(result, f"rule 5 {huawei}")

    def test_named_acl_headers_are_rule_not_system(self):
        result = c2h("ip access-list extended WEB\n permit ip any any\n")
        line = cmd(result, "acl name WEB advance")
        assert line.provenance is Provenance.RULE
        back = h2c("acl name WEB advance\n rule 5 permit ip\n")
        assert cmd(back, "ip access-list extended WEB").provenance is Provenance.RULE

    def test_huawei_rules_resequenced_preserving_order(self):
        text = "access-list 101 permit tcp any any eq 22\naccess-list 101 permit udp any any eq 53\naccess-list 101 deny ip any any\n"
        result = c2h(text)
        assert block(result, "acl number 3001") == [
            "acl number 3001",
            " rule 5 permit tcp destination-port eq 22",
            " rule 10 permit udp destination-port eq 53",
            " rule 15 deny ip",
        ]

    def test_huawei_rule_ids_define_order(self):
        text = "acl number 3000\n rule 100 deny ip\n rule 1 permit tcp destination-port eq 22\n rule 7 permit udp\n"
        result = h2c(text)
        assert block(result, "ip access-list extended 100") == [
            "ip access-list extended 100",
            " permit tcp any any eq 22",
            " permit udp any any",
            " deny ip any any",
        ]

    def test_cisco_sequence_numbers_define_order(self):
        text = "ip access-list extended E\n 30 deny ip any any\n 10 permit tcp any any eq 22\n permit udp any any\n"
        result = c2h(text)
        assert block(result, "acl name E advance") == [
            "acl name E advance",
            " rule 5 permit tcp destination-port eq 22",
            " rule 10 deny ip",
            " rule 15 permit udp",
        ]

    def test_huawei_step_not_needed(self):
        result = h2c("acl number 3000\n step 10\n rule 10 permit ip\n")
        found = comments_with(result, "step 10")
        assert found and found[0].provenance is Provenance.NOT_NEEDED

    @pytest.mark.parametrize(
        "entry, reason",
        [
            ("permit tcp any any eq 22 time-range WORK", "Time Range"),
            ("permit tcp any any neq 22", None),
            ("permit ip any any log", None),
            ("permit gre any any", None),
        ],
    )
    def test_unconvertible_entry_unconverts_whole_acl(self, entry, reason):
        """Dropping one entry would silently change what the ACL filters."""
        text = f"ip access-list extended E\n deny ip host 10.0.0.66 any\n {entry}\n permit ip any any\n!\ninterface GigabitEthernet0/0/1\n ip access-group E in\n"
        result = c2h(text)
        assert_unconverted(result, entry, reason)
        assert_unconverted(result, "ip access-list extended E")
        assert_unconverted(result, "deny ip host 10.0.0.66 any")
        assert_unconverted(result, "ip access-group E in")
        assert not any(l.strip().startswith(("acl ", "rule ", "traffic-filter")) for l in commands(result))
        assert block_result(result, "ip access-list").complete is False

    def test_remark_kept_as_comment_without_unconverting_acl(self):
        result = c2h("access-list 10 remark mgmt hosts\naccess-list 10 permit host 10.0.0.1\n")
        assert has_cmd(result, "rule 5 permit source 10.0.0.1 0")
        assert_unconverted(result, "remark mgmt hosts")

    def test_huawei_rule_time_range_unconverted(self):
        result = h2c("acl number 3000\n rule 5 permit ip time-range WORK\n")
        assert_unconverted(result, "rule 5 permit ip time-range WORK", "Time Range")

    @pytest.mark.parametrize(
        "src, vendor, needle, reason",
        [
            ("mac access-list extended M1\n permit any any\n", C, "mac access-list extended M1", "ชั้นที่ 2"),
            ("time-range WORK\n periodic weekdays 8:00 to 17:00\n", C, "time-range WORK", "Time Range"),
            ("acl name L2 link\n rule 5 permit\n", H, "acl name L2 link", "ชั้นที่ 2"),
            ("acl name U1 user\n rule 5 permit\n", H, "acl name U1 user", "User-Defined"),
            ("time-range WORK 08:00 to 18:00 working-day\n", H, "time-range WORK", "Time Range"),
            ("acl number 3000 match-order auto\n rule 5 permit ip\n", H, "match-order auto", None),
        ],
    )
    def test_unsupported_acl_kinds(self, src, vendor, needle, reason):
        result = convert(src, vendor, H if vendor is C else C)
        assert_unconverted(result, needle, reason)


# =========================================================================== interface binding


class TestAclBinding:
    def test_cisco_numbered_binding(self):
        result = c2h("access-list 101 permit ip any any\n!\ninterface GigabitEthernet0/0/1\n ip access-group 101 in\n")
        line = cmd(result, "traffic-filter inbound acl 3001")
        assert line.provenance is Provenance.RULE
        assert line.category is T

    def test_cisco_named_binding(self):
        result = c2h("ip access-list extended WEB\n permit ip any any\n!\ninterface GigabitEthernet0/0/1\n ip access-group WEB out\n")
        assert has_cmd(result, "traffic-filter outbound acl name WEB")

    def test_huawei_bindings_to_cisco(self):
        text = "acl number 3001\n rule 5 permit ip\n#\nacl name WEB advance\n rule 5 permit ip\n#\ninterface GigabitEthernet0/0/1\n traffic-filter inbound acl 3001\n traffic-filter outbound acl name WEB\n"
        result = h2c(text)
        assert has_cmd(result, "ip access-group 101 in")
        assert has_cmd(result, "ip access-group WEB out")

    def test_acls_rendered_before_interfaces(self):
        result = c2h("interface GigabitEthernet0/0/1\n ip access-group 10 in\n!\naccess-list 10 permit any\n")
        out = commands(result)
        assert out.index("acl number 2009") < out.index("interface GigabitEthernet0/0/1")

    def test_implicit_deny_mismatch_warned_on_huawei(self):
        """Cisco drops unmatched packets; Huawei traffic-filter forwards them."""
        result = c2h("access-list 10 permit 10.0.0.0 0.0.0.255\n!\ninterface GigabitEthernet0/0/1\n ip access-group 10 in\n")
        line = cmd(result, "traffic-filter inbound acl 2009")
        assert line.warning and "deny" in line.warning

    def test_no_implicit_deny_warning_when_acl_ends_with_catch_all(self):
        result = c2h("access-list 10 permit 10.0.0.0 0.0.0.255\naccess-list 10 deny any\n!\ninterface GigabitEthernet0/0/1\n ip access-group 10 in\n")
        assert cmd(result, "traffic-filter inbound acl 2009").warning is None

    def test_implicit_permit_mismatch_warned_on_cisco(self):
        result = h2c("acl number 2000\n rule 5 deny source 10.0.0.0 0.0.0.255\n#\ninterface GigabitEthernet0/0/1\n traffic-filter inbound acl 2000\n")
        assert cmd(result, "ip access-group 1 in").warning

    def test_unsupported_acl_number_in_binding(self):
        result = c2h("interface GigabitEthernet0/0/1\n ip access-group 700 in\n")
        assert_unconverted(result, "ip access-group 700 in")


# =========================================================================== behavioural: packet decisions


def _addr_match(addr, ip: IPv4Address) -> bool:
    mask = ~int(addr.wildcard) & 0xFFFFFFFF
    return (int(ip) & mask) == (int(addr.address) & mask)


def _port_match(port, value: Optional[int]) -> bool:
    if port is None:
        return True
    if value is None:
        return False
    op, p = port.operator, port.ports
    return {"eq": value == p[0], "gt": value > p[0], "lt": value < p[0], "range": p[0] <= value <= p[-1]}[op]


def evaluate(acl: AclIR, proto: str, src: str, dst: str, sport=None, dport=None) -> Optional[str]:
    """First-match ACL evaluation; None = no entry matched (vendor default applies)."""
    for e in acl.entries:
        if e.protocol not in (None, "ip") and e.protocol != proto:
            continue
        if not _addr_match(e.source, IPv4Address(src)):
            continue
        if e.destination is not None and not _addr_match(e.destination, IPv4Address(dst)):
            continue
        if not _port_match(e.source_port, sport) or not _port_match(e.destination_port, dport):
            continue
        return e.action
    return None


PACKETS = [
    ("tcp", "10.2.3.4", "192.168.10.10", 40000, 80),
    ("tcp", "10.2.3.4", "192.168.10.10", 40000, 8050),
    ("tcp", "10.2.3.4", "192.168.10.10", 40000, 8081),
    ("tcp", "10.2.3.4", "192.168.10.11", 40000, 80),
    ("udp", "10.1.1.1", "8.8.8.8", 5353, 53),
    ("udp", "10.1.1.2", "8.8.8.8", 5353, 53),
    ("icmp", "172.16.0.1", "10.0.0.1", None, None),
    ("tcp", "10.2.0.9", "10.0.0.1", 2000, 23),
    ("tcp", "10.2.0.9", "10.0.0.1", 80, 23),
    ("tcp", "10.3.0.9", "10.0.0.1", 2000, 23),
    ("udp", "192.168.10.77", "1.1.1.1", 1, 1),
    ("udp", "192.168.11.77", "1.1.1.1", 1, 1),
]

CISCO_ACLS = """ip access-list extended WEB-IN
 permit tcp any host 192.168.10.10 eq www
 permit tcp any host 192.168.10.10 range 8000 8080
 deny ip any any
!
access-list 10 permit 192.168.10.0 0.0.0.255
access-list 10 deny any
access-list 101 permit udp host 10.1.1.1 any eq 53
access-list 101 permit icmp any any
access-list 101 deny tcp 10.2.0.0 0.0.255.255 gt 1023 any lt 1024
"""


class TestAclBehaviour:
    @pytest.mark.parametrize("packet", PACKETS)
    def test_same_decision_after_cisco_to_huawei(self, packet):
        source = parse_config(CISCO_ACLS, C).ir.acls
        target = parse_config(c2h(CISCO_ACLS).text, H).ir.acls
        assert len(source) == len(target) == 3
        for a, b in zip(source, target):
            assert evaluate(a, *packet) == evaluate(b, *packet), (a.name, a.ordinal, packet)

    @pytest.mark.parametrize("packet", PACKETS)
    def test_same_decision_after_huawei_to_cisco(self, packet):
        huawei = c2h(CISCO_ACLS).text
        source = parse_config(huawei, H).ir.acls
        target = parse_config(h2c(huawei).text, C).ir.acls
        for a, b in zip(source, target):
            assert evaluate(a, *packet) == evaluate(b, *packet)

    def test_decisions_are_not_trivial(self):
        acls = parse_config(CISCO_ACLS, C).ir.acls
        decisions = {evaluate(a, *p) for a in acls for p in PACKETS}
        assert decisions == {"permit", "deny", None}
