"""Security gate tests (Non-Negotiables #1 and #2) + /api/health.

These tests must never be weakened or skipped.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.ir import ConversionMode, Provenance, Vendor
from app.core.secret_stripper import SanitizedResult, contains_secret, strip_secrets
from app.main import app

FIXTURES = Path(__file__).parent / "fixtures"

CISCO_TEXT = (FIXTURES / "cisco_with_secrets.txt").read_text(encoding="utf-8")
HUAWEI_TEXT = (FIXTURES / "huawei_with_secrets.txt").read_text(encoding="utf-8")

# Every secret value / username planted in the fixtures. None may ever leak.
CISCO_SECRETS = [
    "$9$CiscoEnableHashXyZ",
    "PlainEnablePw1",
    "netadmin",
    "$9$UserHashAbC123",
    "OspfMd5Key77",
    "BgpNeighPw99",
    "PubCommRO",
    "PrivCommRW",
    "TacacsKey55",
    "RadiusKey66",
    "VtyLinePw42",
    "ConsoleSecret8",
]
HUAWEI_SECRETS = [
    "%^%#SuperCipherQwE%^%#",
    "SuperCipherQwE",
    "huaadmin",
    "$1a$LocalUserHashZz$",
    "OspfHuaKey33",
    "HuaBgpPw88",
    "HuaPubComm",
    "HuaPrivComm",
    "HuaVtyPw21",
]

CISCO_EXPECTED_STRIPPED = [3, 4, 5, 12, 20, 22, 23, 24, 25, 26, 30, 34]
HUAWEI_EXPECTED_STRIPPED = [4, 7, 8, 9, 14, 22, 24, 25, 29]


def _line(text: str, n: int) -> str:
    return text.splitlines()[n - 1]


def _all_output(result: SanitizedResult) -> str:
    return result.sanitized_text + "\n" + "\n".join(result.advisory_lines)


# --------------------------------------------------------------------------- Cisco


class TestCiscoStripping:
    def test_returns_sanitized_result(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        assert isinstance(result, SanitizedResult)

    def test_exact_lines_stripped(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        assert result.stripped_line_numbers == CISCO_EXPECTED_STRIPPED

    @pytest.mark.parametrize(
        "line",
        [
            "username admin privilege 15 secret 9 $9$abc",
            "username bob password 0 bobpw",
            "enable secret 5 $1$xyz",
            "enable password cisco",
            " password cisco123",
            " secret 9 $9$abc",
            "snmp-server community public RO",
            "tacacs-server host 1.1.1.1 key tackey",
            "tacacs-server key tackey",
            "radius-server host 1.1.1.2 key radkey",
            "radius-server key radkey",
            " neighbor 1.1.1.1 password bgppw",
            " ip ospf message-digest-key 1 md5 ospfkey",
            "crypto key generate rsa modulus 2048",
            "crypto isakmp key vpnkey address 1.1.1.1",
        ],
    )
    def test_each_cisco_credential_form_detected(self, line):
        assert contains_secret(line), line

    def test_non_secret_lines_kept(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        for keep in (
            "hostname R1-CORE",
            " ip address 10.0.0.1 255.255.255.252",
            " neighbor 10.0.0.2 remote-as 65002",
            "line vty 0 4",
            " transport input ssh",
            "service password-encryption",
            "ip route 0.0.0.0 0.0.0.0 10.0.0.2",
        ):
            assert keep in result.sanitized_text.splitlines(), keep

    def test_zero_leak_in_ai_bound_text(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        for secret in CISCO_SECRETS:
            assert secret not in result.sanitized_text, secret

    def test_zero_leak_in_advisory_comments(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        for secret in CISCO_SECRETS:
            for adv in result.advisory_lines:
                assert secret not in adv, (secret, adv)

    def test_advisory_uses_cisco_marker_and_one_per_stripped_line(self):
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE)
        assert len(result.advisory_lines) == len(CISCO_EXPECTED_STRIPPED)
        assert all(a.startswith("!") for a in result.advisory_lines)
        assert all(Provenance.SYSTEM.value in a for a in result.advisory_lines)


# --------------------------------------------------------------------------- Huawei


class TestHuaweiStripping:
    def test_exact_lines_stripped(self):
        result = strip_secrets(HUAWEI_TEXT, Vendor.HUAWEI_VRP)
        assert result.stripped_line_numbers == HUAWEI_EXPECTED_STRIPPED

    @pytest.mark.parametrize(
        "line",
        [
            " local-user admin password irreversible-cipher abc",
            " local-user admin service-type ssh",
            "super password level 15 cipher abc",
            " set authentication password cipher abc",
            "snmp-agent community read public",
            " peer 1.1.1.1 password cipher abc",
            " ospf authentication-mode md5 1 cipher abc",
            " authentication-mode md5 1 cipher abc",
            "hwtacacs-server shared-key cipher abc",
        ],
    )
    def test_each_huawei_credential_form_detected(self, line):
        assert contains_secret(line), line

    def test_non_secret_lines_kept(self):
        result = strip_secrets(HUAWEI_TEXT, Vendor.HUAWEI_VRP)
        for keep in (
            "sysname R2-EDGE",
            "aaa",
            " peer 10.0.0.1 as-number 65001",
            "user-interface vty 0 4",
            " authentication-mode password",
            " protocol inbound ssh",
            "ip route-static 0.0.0.0 0.0.0.0 10.0.0.1",
        ):
            assert keep in result.sanitized_text.splitlines(), keep

    def test_zero_leak_in_ai_bound_text_and_comments(self):
        result = strip_secrets(HUAWEI_TEXT, Vendor.HUAWEI_VRP)
        output = _all_output(result)
        for secret in HUAWEI_SECRETS:
            assert secret not in output, secret

    def test_advisory_uses_huawei_marker(self):
        result = strip_secrets(HUAWEI_TEXT, Vendor.HUAWEI_VRP)
        assert result.advisory_lines
        assert all(a.startswith("#") for a in result.advisory_lines)


# --------------------------------------------------------------------------- cross-cutting


class TestSecurityGate:
    def test_advisory_marker_follows_target_vendor(self):
        # Cisco source converted to Huawei -> advisories are written into a Huawei file.
        result = strip_secrets(CISCO_TEXT, Vendor.CISCO_IOS_XE, advisory_vendor=Vendor.HUAWEI_VRP)
        assert all(a.startswith("#") for a in result.advisory_lines)

    @pytest.mark.parametrize(
        "text, declared, secrets",
        [(CISCO_TEXT, Vendor.HUAWEI_VRP, CISCO_SECRETS), (HUAWEI_TEXT, Vendor.CISCO_IOS_XE, HUAWEI_SECRETS)],
    )
    def test_mis_declared_vendor_still_leaks_nothing(self, text, declared, secrets):
        output = _all_output(strip_secrets(text, declared))
        for secret in secrets:
            assert secret not in output, secret

    def test_secret_inside_source_comment_is_stripped(self):
        text = "hostname R1\n! old enable password was Hunter2Pw\n# local-user x password cipher Hunter3Pw\n"
        result = strip_secrets(text, Vendor.CISCO_IOS_XE)
        assert result.stripped_line_numbers == [2, 3]
        assert "Hunter2Pw" not in _all_output(result)
        assert "Hunter3Pw" not in _all_output(result)

    def test_clean_config_is_unchanged(self):
        text = "hostname R1\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255\n"
        result = strip_secrets(text, Vendor.CISCO_IOS_XE)
        assert result.sanitized_text == text
        assert result.stripped_line_numbers == []
        assert result.advisory_lines == []

    def test_crlf_input_handled(self):
        text = "hostname R1\r\nenable secret 5 CrlfSecret1\r\nend\r\n"
        result = strip_secrets(text, Vendor.CISCO_IOS_XE)
        assert result.stripped_line_numbers == [2]
        assert "CrlfSecret1" not in _all_output(result)

    def test_case_insensitive(self):
        assert contains_secret("ENABLE SECRET 5 abc")
        assert contains_secret(" Local-User admin Password cipher abc")


# --------------------------------------------------------------------------- /api/health


@pytest.fixture
def client():
    yield TestClient(app)
    app.dependency_overrides.clear()


def _with_key(key: str):
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=key, _env_file=None)


class TestHealth:
    def test_health_without_api_key_falls_back_to_rule_only(self, client):
        _with_key("")
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert body["llm_api_key_configured"] is False
        assert body["ai_available"] is False
        assert body["default_mode"] == ConversionMode.HYBRID.value
        assert body["effective_mode"] == ConversionMode.RULE_ONLY.value
        assert body["modes"] == {"hybrid": False, "rule_only": True, "ai_only": False}

    def test_health_with_api_key_keeps_hybrid(self, client):
        _with_key("sk-test-DoNotLeakThisKey")
        resp = client.get("/api/health")
        body = resp.json()
        assert resp.status_code == 200
        assert body["llm_api_key_configured"] is True
        assert body["ai_available"] is True
        assert body["effective_mode"] == ConversionMode.HYBRID.value
        assert body["modes"] == {"hybrid": True, "rule_only": True, "ai_only": True}

    def test_health_never_echoes_api_key(self, client):
        _with_key("sk-test-DoNotLeakThisKey")
        assert "DoNotLeakThisKey" not in client.get("/api/health").text

    def test_whitespace_only_key_counts_as_missing(self, client):
        _with_key("   ")
        assert client.get("/api/health").json()["llm_api_key_configured"] is False
