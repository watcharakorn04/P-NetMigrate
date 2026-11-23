"""Pre-scan analyzer (proposal §2.3.1 item 1.2.1): coverage report, no conversion."""

from pathlib import Path

import pytest

from app.core.ir import Vendor
from app.core.prescan import PrescanReport, prescan_config

C = Vendor.CISCO_IOS_XE
H = Vendor.HUAWEI_VRP
FIXTURES = Path(__file__).parent / "fixtures"

MIXED_CISCO = """hostname R1
!
interface Tunnel0
 ip address 10.0.0.1 255.255.255.0
!
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
 area 1 nssa
!
ip route 10.0.0.0 255.0.0.0 1.1.1.1 name BACKUP
end
"""


class TestPrescanCounts:
    def test_returns_report(self):
        assert isinstance(prescan_config("hostname R1\n", C, H), PrescanReport)

    def test_mixed_file_counts(self):
        report = prescan_config(MIXED_CISCO, C, H)
        assert report.total_lines == 8  # blanks and "!" separators excluded
        assert report.supported_lines == 4
        assert report.unsupported_lines == 4
        assert report.coverage_percent == 50.0
        assert [i.line_no for i in report.unsupported_items] == [3, 4, 8, 10]

    def test_unsupported_items_carry_command_and_reason(self):
        report = prescan_config(MIXED_CISCO, C, H)
        by_line = {i.line_no: i for i in report.unsupported_items}
        assert by_line[3].command == "interface Tunnel0"
        assert "Tunnel" in by_line[3].reason
        assert "NSSA" in by_line[8].reason
        assert by_line[10].command == "ip route 10.0.0.0 255.0.0.0 1.1.1.1 name BACKUP"
        assert all(i.reason for i in report.unsupported_items)

    @pytest.mark.parametrize("fixture, vendor", [("cisco_tier1.txt", C), ("huawei_tier1.txt", H)])
    def test_in_scope_fixture_is_full_coverage(self, fixture, vendor):
        text = (FIXTURES / fixture).read_text(encoding="utf-8")
        report = prescan_config(text, vendor, H if vendor is C else C)
        assert report.coverage_percent == 100.0
        assert report.unsupported_items == []
        assert report.total_lines == report.supported_lines > 0

    def test_not_needed_counts_as_supported(self):
        report = prescan_config("interface GigabitEthernet0/0/1\n switchport trunk encapsulation dot1q\n", C, H)
        assert report.supported_lines == 2
        assert report.coverage_percent == 100.0

    def test_coverage_is_rounded_percentage(self):
        report = prescan_config("hostname R1\nipv6 unicast-routing\nip domain name x.local\n", C, H)
        assert report.coverage_percent == pytest.approx(66.67)

    def test_empty_input(self):
        report = prescan_config("", C, H)
        assert report.total_lines == 0
        assert report.coverage_percent == 100.0

    def test_huawei_intentionally_unconverted_reported(self):
        text = "interface GigabitEthernet0/0/1\n port link-type trunk\n port trunk allow-pass vlan all\n"
        report = prescan_config(text, H, C)
        assert [i.line_no for i in report.unsupported_items] == [3]
        assert report.unsupported_items[0].command == "port trunk allow-pass vlan all"

    def test_same_vendor_rejected(self):
        with pytest.raises(ValueError):
            prescan_config("hostname R1\n", H, H)


class TestPrescanSecurity:
    def test_secrets_stripped_first_and_line_numbers_refer_to_original_file(self):
        text = "enable secret 5 TopSecretHash\nusername bob password 0 BobPw\nhostname R1\nipv6 unicast-routing\n"
        report = prescan_config(text, C, H)
        assert report.secret_stripped_count == 2
        assert report.total_lines == 2  # stripped lines are not counted as config lines
        assert [i.line_no for i in report.unsupported_items] == [4]

    def test_no_secret_in_report(self):
        text = (FIXTURES / "cisco_with_secrets.txt").read_text(encoding="utf-8")
        report = prescan_config(text, C, H)
        dumped = report.model_dump_json()
        for secret in ("CiscoEnableHashXyZ", "PlainEnablePw1", "netadmin", "OspfMd5Key77", "BgpNeighPw99",
                       "PubCommRO", "TacacsKey55", "RadiusKey66", "VtyLinePw42", "ConsoleSecret8"):
            assert secret not in dumped
        assert report.secret_stripped_count == 12
