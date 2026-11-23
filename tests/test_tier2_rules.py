"""Tier-2 translation rules: RIPv2, Redistribution, Default gateway, NTP, Syslog, VTY/SSH.

Both directions, provenance labels, D/T/S categories, warnings for default mismatches
(proposal §2.3.2 item 5), intentionally-unconverted commands (item 7) and IR round-trip.
"""

from pathlib import Path

import pytest

from app.core.engine import convert
from app.core.ir import Provenance, SyntaxCategory
from app.core.parsers import parse_config
from app.core.prescan import prescan_config
from app.core.secret_stripper import contains_secret
from tests.helpers import C, H, block, block_result, c2h, cmd, commands, comments_with, h2c, has_cmd

FIXTURES = Path(__file__).parent / "fixtures"
CISCO_T23 = (FIXTURES / "cisco_tier23.txt").read_text(encoding="utf-8")
HUAWEI_T23 = (FIXTURES / "huawei_tier23.txt").read_text(encoding="utf-8")

D, T, S = SyntaxCategory.DIRECT, SyntaxCategory.TRANSFORM, SyntaxCategory.STRUCTURAL


def assert_unconverted(result, needle: str, reason_has: str | None = None):
    lines = comments_with(result, needle)
    assert lines, f"{needle!r} not preserved as a comment:\n{result.annotated_text}"
    assert all(l.provenance is Provenance.UNCONVERTED for l in lines)
    target_marker = result.target_vendor.comment_marker
    assert all(l.text.startswith(target_marker) for l in lines)
    if reason_has:
        assert any(reason_has in (l.warning or "") for l in lines), [l.warning for l in lines]
    return lines


# =========================================================================== RIPv2


CISCO_RIP = """router rip
 version 2
 no auto-summary
 network 10.0.0.0
 network 172.16.0.0
 passive-interface GigabitEthernet0/0/1
 default-information originate
"""

HUAWEI_RIP = """rip 1
 version 2
 undo summary
 network 10.0.0.0
 network 172.16.0.0
 silent-interface GigabitEthernet0/0/1
 default-route originate
"""


class TestRip:
    def test_cisco_to_huawei_block(self):
        result = c2h(CISCO_RIP)
        assert block(result, "rip 1") == [
            "rip 1",
            " version 2",
            " undo summary",
            " silent-interface GigabitEthernet0/0/1",
            " network 10.0.0.0",
            " network 172.16.0.0",
            " default-route originate",
        ]
        assert all(cmd(result, l.strip()).provenance is Provenance.RULE for l in block(result, "rip 1"))
        assert block_result(result, "router rip").complete is True

    def test_huawei_to_cisco_block(self):
        result = h2c(HUAWEI_RIP)
        assert block(result, "router rip") == [
            "router rip",
            " version 2",
            " no auto-summary",
            " passive-interface GigabitEthernet0/0/1",
            " network 10.0.0.0",
            " network 172.16.0.0",
            " default-information originate",
        ]
        assert block_result(result, "rip 1").complete is True

    def test_categories(self):
        result = c2h(CISCO_RIP)
        assert cmd(result, "version 2").category is D
        assert cmd(result, "network 10.0.0.0").category is D
        assert cmd(result, "silent-interface GigabitEthernet0/0/1").category is D
        assert cmd(result, "rip 1").category is T

    def test_auto_summary_on(self):
        assert has_cmd(c2h("router rip\n version 2\n auto-summary\n"), "summary")
        assert has_cmd(h2c("rip\n version 2\n summary\n"), "auto-summary")

    def test_huawei_rip_without_pid_is_process_1(self):
        result = h2c("rip\n version 2\n network 10.0.0.0\n")
        assert has_cmd(result, "router rip")
        assert block_result(result, "rip").complete is True

    def test_huawei_non_default_pid_warns_it_is_dropped(self):
        result = h2c("rip 7\n version 2\n network 10.0.0.0\n")
        line = cmd(result, "router rip")
        assert line.warning and "7" in line.warning

    def test_missing_version_2_warns(self):
        line = cmd(c2h("router rip\n network 10.0.0.0\n"), "rip 1")
        assert line.warning and "version 2" in line.warning

    def test_ripv1_unconverted(self):
        result = c2h("router rip\n version 1\n network 10.0.0.0\n")
        assert_unconverted(result, "version 1", "RIPv1")
        assert block_result(result, "router rip").complete is False

    @pytest.mark.parametrize("line", [" timers basic 10 60 60 80"])
    def test_cisco_timers_unconverted(self, line):
        result = c2h(CISCO_RIP + line + "\n")
        assert_unconverted(result, line.strip(), "Timers")

    def test_huawei_timers_unconverted(self):
        result = h2c(HUAWEI_RIP + " timers rip 10 60 80\n")
        assert_unconverted(result, "timers rip 10 60 80", "Timers")

    def test_cisco_interface_rip_authentication_unconverted(self):
        result = c2h("interface GigabitEthernet0/0/1\n ip rip authentication mode md5\n")
        assert_unconverted(result, "ip rip authentication mode md5", "Authentication")

    def test_huawei_second_rip_process_unconverted(self):
        result = h2c(HUAWEI_RIP + "#\nrip 2\n version 2\n network 192.168.0.0\n")
        assert has_cmd(result, "router rip")
        assert not has_cmd(result, "network 192.168.0.0")
        assert_unconverted(result, "rip 2", "Process")
        assert_unconverted(result, "network 192.168.0.0")

    def test_invalid_network_unconverted(self):
        assert_unconverted(c2h("router rip\n version 2\n network 10.0.0.300\n"), "network 10.0.0.300")

    def test_rip_secret_lines_never_leak(self):
        text = "rip 1\n version 2\n#\ninterface GigabitEthernet0/0/1\n rip authentication-mode simple plain RipPlainPw9\n"
        result = h2c(text)
        assert "RipPlainPw9" not in result.text + result.annotated_text
        assert contains_secret(" rip authentication-mode simple plain RipPlainPw9")


# =========================================================================== Redistribution


class TestRedistribution:
    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("redistribute static subnets metric 10", "import-route static cost 10"),
            ("redistribute connected subnets metric 20", "import-route direct cost 20"),
            ("redistribute rip subnets metric 30", "import-route rip 1 cost 30"),
            ("redistribute static subnets metric 10 metric-type 1", "import-route static cost 10 type 1"),
        ],
    )
    def test_into_ospf_both_ways(self, cisco, huawei):
        result = c2h(f"router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n {cisco}\n")
        line = cmd(result, huawei)
        assert line.provenance is Provenance.RULE
        assert line.category is T
        back = h2c(f"ospf 1\n {huawei}\n area 0.0.0.0\n  network 10.0.0.0 0.0.0.255\n")
        assert cmd(back, cisco).provenance is Provenance.RULE

    def test_cisco_ospf_without_subnets_keyword_accepted(self):
        result = c2h("router ospf 1\n redistribute static metric 10\n")
        assert has_cmd(result, "import-route static cost 10")

    @pytest.mark.parametrize(
        "cisco, huawei",
        [
            ("redistribute static metric 3", "import-route static cost 3"),
            ("redistribute connected metric 2", "import-route direct cost 2"),
            ("redistribute ospf 1 metric 5", "import-route ospf 1 cost 5"),
        ],
    )
    def test_into_rip_both_ways(self, cisco, huawei):
        result = c2h(f"router rip\n version 2\n {cisco}\n")
        assert cmd(result, huawei).provenance is Provenance.RULE
        back = h2c(f"rip 1\n version 2\n {huawei}\n")
        assert cmd(back, cisco).provenance is Provenance.RULE

    @pytest.mark.parametrize(
        "src, vendor, needle",
        [
            ("router ospf 1\n redistribute static subnets\n", C, "redistribute static subnets"),
            ("router rip\n version 2\n redistribute connected\n", C, "redistribute connected"),
            ("router bgp 65001\n redistribute static\n", C, "redistribute static"),
            ("ospf 1\n import-route static\n", H, "import-route static"),
            ("rip 1\n version 2\n import-route direct\n", H, "import-route direct"),
        ],
    )
    def test_missing_metric_unconverted_with_warning(self, src, vendor, needle):
        result = convert(src, vendor, H if vendor is C else C)
        lines = assert_unconverted(result, needle)
        assert "metric" in lines[0].warning.lower() or "ค่าตัววัด" in lines[0].warning
        assert not any(l.text.strip().startswith(("import-route", "redistribute")) for l in result.lines if not l.is_comment)

    @pytest.mark.parametrize(
        "src, vendor, needle",
        [
            ("router ospf 1\n redistribute static subnets metric 10 route-map RM\n", C, "route-map RM"),
            ("ospf 1\n import-route static cost 10 route-policy RP\n", H, "route-policy RP"),
        ],
    )
    def test_route_map_or_policy_unconverted(self, src, vendor, needle):
        result = convert(src, vendor, H if vendor is C else C)
        assert_unconverted(result, needle, "Route-Map")

    def test_unsupported_source_protocol_unconverted(self):
        result = c2h("router ospf 1\n redistribute bgp 65001 subnets metric 10\n")
        assert_unconverted(result, "redistribute bgp 65001 subnets metric 10")

    def test_into_bgp_metric_is_med(self):
        result = c2h("router bgp 65001\n redistribute connected metric 50\n")
        assert has_cmd(result, "import-route direct med 50")
        back = h2c("bgp 65001\n ipv4-family unicast\n  import-route static med 7\n")
        assert has_cmd(back, "redistribute static metric 7")


# =========================================================================== Default gateway


class TestDefaultGateway:
    def test_cisco_default_gateway_to_huawei_static_default(self):
        result = c2h("ip default-gateway 192.168.1.254\n")
        line = cmd(result, "ip route-static 0.0.0.0 0.0.0.0 192.168.1.254")
        assert line.provenance is Provenance.RULE
        assert line.category is T
        assert line.warning and "ip routing" in line.warning
        assert line.warning in result.warnings

    def test_invalid_gateway_unconverted(self):
        assert_unconverted(c2h("ip default-gateway gw.local\n"), "ip default-gateway gw.local")

    def test_huawei_static_default_stays_a_static_route(self):
        assert has_cmd(h2c("ip route-static 0.0.0.0 0.0.0.0 10.0.0.1\n"), "ip route 0.0.0.0 0.0.0.0 10.0.0.1")


# =========================================================================== NTP & Syslog


class TestNtpSyslog:
    def test_ntp_both_ways(self):
        line = cmd(c2h("ntp server 10.9.9.1\n"), "ntp-service unicast-server 10.9.9.1")
        assert (line.provenance, line.category) == (Provenance.RULE, D)
        line = cmd(h2c("ntp-service unicast-server 10.9.9.1\n"), "ntp server 10.9.9.1")
        assert (line.provenance, line.category) == (Provenance.RULE, D)

    def test_multiple_ntp_servers_keep_order(self):
        result = c2h("ntp server 10.9.9.1\nntp server 10.9.9.5\n")
        out = [l for l in commands(result) if l.startswith("ntp-service")]
        assert out == ["ntp-service unicast-server 10.9.9.1", "ntp-service unicast-server 10.9.9.5"]

    @pytest.mark.parametrize("src", ["ntp server pool.ntp.org", "ntp server 10.9.9.1 prefer source Loopback0"])
    def test_ntp_unsupported_forms_unconverted(self, src):
        assert_unconverted(c2h(src + "\n"), src)

    @pytest.mark.parametrize("src", ["logging host 10.9.9.2", "logging 10.9.9.2"])
    def test_syslog_cisco_to_huawei(self, src):
        line = cmd(c2h(src + "\n"), "info-center loghost 10.9.9.2")
        assert (line.provenance, line.category) == (Provenance.RULE, D)

    def test_syslog_huawei_to_cisco(self):
        line = cmd(h2c("info-center loghost 10.9.9.2\n"), "logging host 10.9.9.2")
        assert (line.provenance, line.category) == (Provenance.RULE, D)

    def test_other_logging_commands_unconverted(self):
        assert_unconverted(c2h("logging buffered 4096\n"), "logging buffered 4096")

    def test_ntp_authentication_key_is_stripped(self):
        result = c2h("ntp authentication-key 1 md5 NtpKey123\nntp server 10.9.9.1\n")
        assert "NtpKey123" not in result.text + result.annotated_text
        assert result.secret_stripped_count == 1


# =========================================================================== VTY / SSH


CISCO_VTY = "line vty 0 4\n login local\n transport input ssh\n"
HUAWEI_VTY = "user-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n"


class TestVty:
    def test_cisco_to_huawei_ssh(self):
        result = c2h(CISCO_VTY)
        assert block(result, "user-interface vty 0 4") == [
            "user-interface vty 0 4",
            " authentication-mode aaa",
            " protocol inbound ssh",
        ]
        assert cmd(result, "user-interface vty 0 4").provenance is Provenance.RULE
        assert cmd(result, "authentication-mode aaa").provenance is Provenance.RULE
        assert block_result(result, "line vty").complete is True

    def test_ssh_enables_stelnet_server_as_system_generated(self):
        result = c2h(CISCO_VTY)
        out = commands(result)
        stelnet = cmd(result, "stelnet server enable")
        assert stelnet.provenance is Provenance.SYSTEM
        assert stelnet.warning
        assert out.index("stelnet server enable") < out.index("user-interface vty 0 4")

    def test_telnet_only_does_not_enable_stelnet(self):
        result = c2h("line vty 0 4\n login local\n transport input telnet\n")
        assert has_cmd(result, "protocol inbound telnet")
        assert not has_cmd(result, "stelnet server enable")

    @pytest.mark.parametrize("transport", ["ssh telnet", "telnet ssh", "all"])
    def test_ssh_and_telnet_maps_to_all(self, transport):
        result = c2h(f"line vty 0 4\n transport input {transport}\n")
        assert has_cmd(result, "protocol inbound all")
        assert has_cmd(result, "stelnet server enable")

    def test_huawei_to_cisco(self):
        result = h2c("stelnet server enable\n" + HUAWEI_VTY)
        assert block(result, "line vty 0 4") == ["line vty 0 4", " login local", " transport input ssh"]
        assert cmd(result, "transport input ssh").warning  # Cisco needs RSA keys for SSH
        stelnet = comments_with(result, "stelnet server enable")
        assert stelnet and stelnet[0].provenance is Provenance.NOT_NEEDED
        assert block_result(result, "user-interface vty").complete is True

    def test_huawei_protocol_all(self):
        assert has_cmd(h2c("user-interface vty 0 4\n protocol inbound all\n"), "transport input ssh telnet")

    def test_vty_range_above_4_warns_on_huawei(self):
        line = cmd(c2h("line vty 0 15\n transport input ssh\n"), "user-interface vty 0 15")
        assert line.warning

    def test_single_vty_line(self):
        assert has_cmd(c2h("line vty 0\n login local\n"), "user-interface vty 0 0")

    def test_password_login_unconverted_and_password_never_leaks(self):
        result = c2h("line vty 0 4\n password VtyPw77\n login\n transport input ssh\n")
        assert "VtyPw77" not in result.text + result.annotated_text
        assert_unconverted(result, "login")
        assert result.secret_stripped_count == 1

    def test_huawei_password_mode_unconverted(self):
        result = h2c("user-interface vty 0 4\n authentication-mode password\n protocol inbound ssh\n")
        assert_unconverted(result, "authentication-mode password")

    @pytest.mark.parametrize(
        "src, vendor, needle",
        [
            ("line vty 0 4\n access-class 10 in\n", C, "access-class 10 in"),
            ("user-interface vty 0 4\n acl 2000 inbound\n", H, "acl 2000 inbound"),
        ],
    )
    def test_acl_on_vty_is_other_policy_use(self, src, vendor, needle):
        result = convert(src, vendor, H if vendor is C else C)
        assert_unconverted(result, needle, "ACL")

    def test_console_line_not_claimed(self):
        result = c2h("line con 0\n logging synchronous\n")
        assert_unconverted(result, "line con 0")

    def test_user_accounts_never_translated(self):
        result = c2h("username admin privilege 15 secret 9 $9$abcHash\n" + CISCO_VTY)
        assert "admin" not in result.text.replace("authentication-mode aaa", "")
        assert "$9$abcHash" not in result.annotated_text
        assert result.secret_stripped_count == 1


# =========================================================================== round-trip / pre-scan


class TestTier2And3RoundTrip:
    def test_cisco_huawei_cisco_preserves_ir(self):
        original = parse_config(CISCO_T23, C).ir
        back = parse_config(c2h(CISCO_T23).text, H).ir
        assert back.intent() == original.intent()

    def test_huawei_cisco_huawei_preserves_ir(self):
        original = parse_config(HUAWEI_T23, H).ir
        back = parse_config(h2c(HUAWEI_T23).text, C).ir
        assert back.intent() == original.intent()

    @pytest.mark.parametrize("src, vendor", [(CISCO_T23, C), (HUAWEI_T23, H)])
    def test_in_scope_fixture_fully_converted(self, src, vendor):
        result = convert(src, vendor, H if vendor is C else C)
        assert result.unconverted_items == [], result.annotated_text
        assert all(b.complete for b in result.blocks)

    @pytest.mark.parametrize("src, vendor", [(CISCO_T23, C), (HUAWEI_T23, H)])
    def test_prescan_full_coverage(self, src, vendor):
        report = prescan_config(src, vendor, H if vendor is C else C)
        assert report.coverage_percent == 100.0
        assert report.unsupported_items == []

    def test_prescan_lists_tier2_unsupported_lines(self):
        text = "router rip\n version 2\n timers basic 10 60 60 80\n redistribute static\n"
        report = prescan_config(text, C, H)
        assert [i.line_no for i in report.unsupported_items] == [3, 4]
        assert report.coverage_percent == 50.0
