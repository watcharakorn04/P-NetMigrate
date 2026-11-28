"""Regression tests from the medium-complexity Cisco -> Huawei VRP verification.

1. `rsa local-key-pair create` (interactive: [Y/N] + modulus size, hangs scripted pushes) is
   never emitted from AI output — replaced by a SYSTEM "ตัดข้อมูลลับออก" comment advisory —
   and never deployed.
2. Deterministic rules (hybrid mode never sends these lines to AI):
     clock timezone ICT 7 0            -> clock timezone ICT add 07:00:00
     ip ssh version 2                  -> ssh server compatible-ssh1x disable   (no stelnet command)
     ip ssh time-out <s>               -> ssh server timeout <s>                (never ssh client timeout)
     ip ssh authentication-retries <n> -> ssh server authentication-retries <n> (never ssh server retry)
     login local (line vty / line con) -> authentication-mode aaa              (never authentication-mode local)
     ip dhcp snooping vlan <list>      -> vlan <id> / dhcp snooping enable / quit per VLAN
     spanning-tree bpduguard enable    -> "ไม่ต้องใช้คำสั่งนี้" inside interface / port-group;
                                          stp bpdu-protection only at system-view level
     switchport port-security maximum <n> -> port-security max-mac-num <n>
3. The Huawei AI prompt (ai_only) states the same constraints.
"""

from __future__ import annotations

import re

import pytest

from app.core.engine import (
    ADVISORY_AI_INTERACTIVE,
    NOTICE_HYBRID_NOTHING_TO_SEND,
    convert,
    convert_selected,
)
from app.core.ir import ConversionMode, Provenance
from app.core.parsers import parse_config
from app.core.renderers.common import ADVISORY_DHCP_ENABLE, WARN_DHCP_ENABLE, WARN_DHCP_SNOOPING_VLAN_UNDECLARED
from app.core.rules.tier1_vlan import REASON_BPDUGUARD_INTERFACE
from app.core.rules.tier2_services import REASON_DHCP_SERVICE, format_cisco_timezone, format_huawei_timezone
from app.core.secret_stripper import contains_secret, is_interactive_command
from app.i18n import translate_message
from app.services.ai_translator import AIItem, _system_prompt
from app.services.deploy_service import R_INTERACTIVE, build_plan, final_commands, plan_from_text
from tests.helpers import C, H, block, block_result, c2h, cmd, commands, comments_with, h2c, has_cmd

HYBRID, AI_ONLY = ConversionMode.HYBRID, ConversionMode.AI_ONLY


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return build_plan(lines, result.target_vendor).commands


def _not_needed(result, needle: str):
    notes = comments_with(result, needle)
    assert notes, result.annotated_text
    assert all(n.provenance is Provenance.NOT_NEEDED for n in notes)
    return notes


class FakeAI:
    """Answers every partial job with `answer`; whole-file jobs with `config_answer`."""

    def __init__(self, answer=None, config_answer=None):
        self.answer = list(answer or [])
        self.config_answer = list(config_answer or [])
        self.sent: list[str] = []
        self.config_sent: list[str] = []

    def translate_items(self, items: list[AIItem], source, target):
        self.sent += [l.strip() for i in items for l in i.lines]
        return {i.id: list(self.answer) for i in items}

    def translate_config(self, text, source, target):
        self.config_sent.append(text)
        return list(self.config_answer)


# A realistic medium-complexity access switch using every rule of this change.
MEDIUM = """configure terminal
hostname ACC-SW1
clock timezone ICT 7 0
ip domain-name lab.local
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
ip dhcp snooping
ip dhcp snooping vlan 10,20
spanning-tree portfast bpduguard default
vlan 10
 name USERS
vlan 20
 name VOICE
interface range GigabitEthernet0/1 - 4
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk allowed vlan 10,20
 ip dhcp snooping trust
interface GigabitEthernet0/5
 switchport mode access
 spanning-tree bpduguard enable
line con 0
 login local
 logging synchronous
line vty 0 4
 login local
 transport input ssh
end
"""


# =========================================================================== 1. interactive rsa


class TestInteractiveKeyGeneration:
    @pytest.mark.parametrize(
        "line",
        [
            "rsa local-key-pair create",
            "RSA LOCAL-KEY-PAIR CREATE",
            " rsa local-key-pair create 2048",
            "dsa local-key-pair create",
            "ecc local-key-pair create",
            "crypto key generate rsa modulus 2048",
        ],
    )
    def test_detected(self, line):
        assert is_interactive_command(line)

    @pytest.mark.parametrize(
        "line",
        ["# rsa local-key-pair create", "! rsa local-key-pair create", "stelnet server enable",
         "rsa peer-public-key x", "ssh server compatible-ssh1x disable", ""],
    )
    def test_not_detected(self, line):
        assert not is_interactive_command(line)

    def test_advisory_has_no_secret_and_mentions_stripping(self):
        assert not contains_secret(f"# [{Provenance.SYSTEM.value}] {ADVISORY_AI_INTERACTIVE}")
        assert "ตัดข้อมูลลับออก" in ADVISORY_AI_INTERACTIVE
        assert "rsa local-key-pair create" in ADVISORY_AI_INTERACTIVE

    def _assert_blocked(self, result):
        assert not has_cmd(result, "rsa local-key-pair create")
        assert all("rsa local-key-pair create" not in c for c in commands(result))
        advisories = comments_with(result, ADVISORY_AI_INTERACTIVE)
        assert advisories and all(a.provenance is Provenance.SYSTEM for a in advisories)
        assert all("rsa local-key-pair create" not in c for c in _deploy(result))

    def test_hybrid_ai_answer_is_replaced(self):
        # The source key line is stripped before the AI call; the AI re-emits the command anyway.
        src = "hostname R1\ncrypto key generate rsa modulus 2048\nip http server\n"
        fake = FakeAI(["rsa local-key-pair create", "http server enable"])
        result = convert(src, C, H, HYBRID, translator=fake)
        assert all("crypto" not in s for s in fake.sent)  # stripped before the AI request
        self._assert_blocked(result)
        assert cmd(result, "http server enable").provenance is Provenance.AI  # the rest is kept

    def test_ai_only_answer_is_replaced(self):
        src = "hostname R1\ncrypto key generate rsa modulus 2048\n"
        fake = FakeAI(config_answer=["system-view", "sysname R1", "rsa local-key-pair create", "return"])
        result = convert(src, C, H, AI_ONLY, translator=fake)
        assert "crypto key generate" not in fake.config_sent[0]
        self._assert_blocked(result)
        assert has_cmd(result, "sysname R1")

    def test_user_selected_answer_is_replaced(self):
        src = "hostname R1\nip http server\n"
        result = convert_selected(src, C, H, [2], FakeAI([" rsa local-key-pair create"]))
        self._assert_blocked(result)

    def test_deploy_strips_pasted_interactive_command(self):
        plan = plan_from_text("sysname R1\nrsa local-key-pair create\n", H)
        assert plan.commands == ["sysname R1"]
        assert {"line": 2, "text": "rsa local-key-pair create", "reason": R_INTERACTIVE} in plan.removed
        commands_, removed = final_commands("rsa local-key-pair create\nsysname R1\n", H)
        assert commands_ == ["sysname R1"] and removed[0]["reason"] == R_INTERACTIVE

    def test_deploy_strips_even_rule_labelled_interactive_line(self):
        plan = build_plan([{"text": "rsa local-key-pair create", "provenance": "RULE"}], H)
        assert plan.commands == [] and plan.removed[0]["reason"] == R_INTERACTIVE

    def test_interactive_reason_has_both_languages(self):
        from app.i18n_pages import UI_PAGES

        entry = UI_PAGES["dep_reason_interactive"]
        assert entry["th"] and entry["en"]


# =========================================================================== 2a. clock timezone


class TestClockTimezone:
    @pytest.mark.parametrize(
        "src, expected",
        [
            ("clock timezone ICT 7 0", "clock timezone ICT add 07:00:00"),
            ("clock timezone ICT 7", "clock timezone ICT add 07:00:00"),
            ("clock timezone IST 5 30", "clock timezone IST add 05:30:00"),
            ("clock timezone EST -5 0", "clock timezone EST minus 05:00:00"),
            ("clock timezone UTC 0 0", "clock timezone UTC add 00:00:00"),
        ],
    )
    def test_cisco_to_huawei(self, src, expected):
        result = c2h(src + "\n")
        line = cmd(result, expected)
        assert line.provenance is Provenance.RULE and line.source_line == 1
        assert not result.unconverted_items

    @pytest.mark.parametrize(
        "src, expected",
        [
            ("clock timezone ICT add 07:00:00", "clock timezone ICT 7 0"),
            ("clock timezone IST add 05:30", "clock timezone IST 5 30"),
            ("clock timezone EST minus 05:00:00", "clock timezone EST -5 0"),
        ],
    )
    def test_huawei_to_cisco(self, src, expected):
        result = h2c(src + "\n")
        assert cmd(result, expected).provenance is Provenance.RULE

    @pytest.mark.parametrize(
        "src", ["clock timezone ICT 7 75", "clock timezone ICT 30 0"]
    )
    def test_bad_offset_unconverted(self, src):
        result = c2h(src + "\n")
        assert [i.line_no for i in result.unconverted_items] == [1]
        assert "clock timezone" not in "\n".join(commands(result))

    def test_huawei_seconds_not_representable(self):
        result = h2c("clock timezone X add 07:00:30\n")
        assert [i.line_no for i in result.unconverted_items] == [1]

    def test_formatters(self):
        assert format_huawei_timezone(420) == "add 07:00:00"
        assert format_huawei_timezone(-330) == "minus 05:30:00"
        assert format_cisco_timezone(-330) == "-5 30"


# =========================================================================== 2b. SSH server


class TestSshServer:
    SRC = "ip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3\n"

    def test_cisco_to_huawei(self):
        result = c2h(self.SRC)
        assert cmd(result, "ssh server compatible-ssh1x disable").source_line == 1
        assert cmd(result, "ssh server timeout 60").source_line == 2
        assert cmd(result, "ssh server authentication-retries 3").source_line == 3
        assert not result.unconverted_items
        text = "\n".join(commands(result))
        assert "ssh client timeout" not in text
        assert "ssh server retry" not in text

    def test_no_stelnet_command_is_added(self):
        result = c2h(self.SRC + "line vty 0 4\n login local\n transport input ssh\n")
        assert not has_cmd(result, "stelnet server enable")
        stelnet = comments_with(result, "stelnet server enable")
        assert stelnet and all(l.provenance is Provenance.SYSTEM and l.is_comment for l in stelnet)
        assert "stelnet server enable" not in _deploy(result)

    def test_huawei_to_cisco(self):
        src = "ssh server compatible-ssh1x disable\nssh server timeout 60\nssh server authentication-retries 3\n"
        result = h2c(src)
        for line in ("ip ssh version 2", "ip ssh time-out 60", "ip ssh authentication-retries 3"):
            assert cmd(result, line).provenance is Provenance.RULE

    def test_legacy_huawei_undo_form(self):
        assert has_cmd(h2c("undo ssh server compatible-ssh1x enable\n"), "ip ssh version 2")

    @pytest.mark.parametrize("src", ["ip ssh authentication-retries 0\n", "ip ssh time-out 500\n", "ip ssh version 1\n"])
    def test_out_of_range_or_v1_unconverted(self, src):
        result = c2h(src)
        assert [i.line_no for i in result.unconverted_items] == [1]

    def test_round_trip(self):
        original = parse_config(self.SRC, C).ir
        assert parse_config(c2h(self.SRC).text, H).ir.intent() == original.intent()


# =========================================================================== 2c. login local


class TestLoginLocal:
    @pytest.mark.parametrize(
        "src, header",
        [
            ("line vty 0 4\n login local\n", "user-interface vty 0 4"),
            ("line con 0\n login local\n", "user-interface con 0"),
            ("line console 0\n login local\n", "user-interface con 0"),
        ],
    )
    def test_maps_to_authentication_mode_aaa(self, src, header):
        result = c2h(src)
        assert block(result, header) == [header, " authentication-mode aaa"]
        assert not result.unconverted_items
        assert "authentication-mode local" not in result.text

    def test_console_logging_synchronous_not_needed(self):
        result = c2h("line con 0\n login local\n logging synchronous\n")
        _not_needed(result, "logging synchronous")
        assert block_result(result, "line con 0").complete

    def test_console_password_login_stays_unconverted(self):
        result = c2h("line con 0\n login\n")
        assert [i.command.strip() for i in result.unconverted_items] == ["login"]

    def test_huawei_console_to_cisco(self):
        result = h2c("user-interface con 0\n authentication-mode aaa\n")
        assert block(result, "line con 0") == ["line con 0", " login local"]

    def test_console_rendered_before_vty(self):
        out = commands(c2h("line vty 0 4\n login local\nline con 0\n login local\n"))
        assert out.index("user-interface con 0") < out.index("user-interface vty 0 4")

    def test_console_round_trip(self):
        src = "line con 0\n login local\nline vty 0 4\n login local\n transport input ssh\n"
        original = parse_config(src, C).ir
        assert parse_config(c2h(src).text, H).ir.intent() == original.intent()


# =========================================================================== 2d. DHCP snooping


class TestDhcpSnooping:
    SRC = "vlan 10\n name USERS\nvlan 20\n name VOICE\nip dhcp snooping\nip dhcp snooping vlan 10,20\n"

    def test_per_vlan_blocks(self):
        out = commands(c2h(self.SRC))
        start = out.index("dhcp snooping enable")
        assert out[start + 1 : start + 7] == [
            "vlan 10", " dhcp snooping enable", "quit",
            "vlan 20", " dhcp snooping enable", "quit",
        ]

    def test_never_global_vlan_form(self):
        result = c2h(self.SRC)
        assert not any(re.search(r"dhcp[ \t]+snooping[ \t]+enable[ \t]+vlan", l) for l in result.text.splitlines())

    def test_labels_and_deploy(self):
        result = c2h(self.SRC)
        snoop = [l for l in result.lines if not l.is_comment and "dhcp snooping" in l.text]
        assert snoop and all(l.provenance is Provenance.RULE for l in snoop)
        deployed = _deploy(result)
        assert deployed.count(" dhcp snooping enable") == 2 and "dhcp snooping enable" in deployed
        assert not result.unconverted_items

    def test_dhcp_enable_is_comment_advisory_only(self):
        result = c2h(self.SRC)
        assert not has_cmd(result, "dhcp enable")
        advisory = comments_with(result, ADVISORY_DHCP_ENABLE)
        assert len(advisory) == 1 and advisory[0].provenance is Provenance.SYSTEM
        assert advisory[0].warning == WARN_DHCP_ENABLE
        assert "dhcp enable" not in _deploy(result)

    def test_range_expanded(self):
        out = commands(c2h("ip dhcp snooping vlan 30-32\n"))
        assert [l for l in out if l.startswith("vlan ")] == ["vlan 30", "vlan 31", "vlan 32"]

    def test_undeclared_vlan_warns(self):
        result = c2h("vlan 10\nip dhcp snooping vlan 10,99\n")
        vlan_lines = [l for l in result.lines if not l.is_comment and l.text in ("vlan 10", "vlan 99")]
        snoop_99 = [l for l in vlan_lines if l.text == "vlan 99" and l.source_line == 2]
        assert snoop_99 and snoop_99[0].warning == WARN_DHCP_SNOOPING_VLAN_UNDECLARED
        snoop_10 = [l for l in vlan_lines if l.text == "vlan 10" and l.source_line == 2]
        assert snoop_10 and snoop_10[0].warning is None

    def test_trust_port(self):
        result = c2h("interface GigabitEthernet0/24\n ip dhcp snooping trust\n")
        assert cmd(result, "dhcp snooping trusted").provenance is Provenance.RULE

    def test_huawei_to_cisco(self):
        src = ("dhcp enable\ndhcp snooping enable\nvlan 10\n dhcp snooping enable\nquit\n"
               "vlan 20\n dhcp snooping enable\nquit\ninterface GigabitEthernet0/0/24\n dhcp snooping trusted\n")
        result = h2c(src)
        assert has_cmd(result, "ip dhcp snooping")
        assert has_cmd(result, "ip dhcp snooping vlan 10,20")
        assert has_cmd(result, "ip dhcp snooping trust")
        notes = _not_needed(result, "dhcp enable")
        assert any(REASON_DHCP_SERVICE in (n.text + (n.warning or "")) for n in notes)
        assert not result.unconverted_items

    def test_round_trip(self):
        original = parse_config(self.SRC, C).ir
        assert parse_config(c2h(self.SRC).text, H).ir.intent() == original.intent()


# =========================================================================== 2e. STP BPDU protection


class TestBpduProtection:
    def _inside_blocks(self, result) -> list[str]:
        """Indented (child) commands — i.e. anything inside interface / port-group views."""
        return [l for l in commands(result) if l.startswith(" ")]

    @pytest.mark.parametrize(
        "src",
        [
            "interface GigabitEthernet0/5\n spanning-tree portfast\n spanning-tree bpduguard enable\n",
            "interface range GigabitEthernet0/1 - 4\n spanning-tree portfast\n spanning-tree bpduguard enable\n",
        ],
    )
    def test_interface_level_is_not_needed(self, src):
        result = c2h(src)
        assert all("bpdu-protection" not in l for l in self._inside_blocks(result))
        notes = _not_needed(result, "spanning-tree bpduguard enable")
        assert REASON_BPDUGUARD_INTERFACE in notes[0].text
        assert "system-view" in REASON_BPDUGUARD_INTERFACE
        assert not result.unconverted_items
        assert has_cmd(result, "stp edged-port enable")

    def test_interface_level_never_sent_to_ai(self):
        fake = FakeAI(["stp bpdu-protection"])
        src = "interface GigabitEthernet0/5\n spanning-tree portfast\n spanning-tree bpduguard enable\n"
        result = convert(src, C, H, HYBRID, translator=fake)
        assert fake.sent == []
        assert NOTICE_HYBRID_NOTHING_TO_SEND in result.notices

    @pytest.mark.parametrize(
        "src", ["spanning-tree portfast bpduguard default\n", "spanning-tree portfast edge bpduguard default\n"]
    )
    def test_global_default_maps_to_system_view_command(self, src):
        result = c2h("configure terminal\n" + src + "interface GigabitEthernet0/5\n spanning-tree portfast\n")
        line = cmd(result, "stp bpdu-protection")
        assert line.text == "stp bpdu-protection"  # top level, not indented
        assert line.provenance is Provenance.RULE
        out = commands(result)
        assert out.index("system-view") < out.index("stp bpdu-protection") < out.index("interface GigabitEthernet0/5")

    def test_huawei_to_cisco_global(self):
        assert has_cmd(h2c("stp bpdu-protection\n"), "spanning-tree portfast bpduguard default")


# =========================================================================== 2f. port security


class TestPortSecurity:
    SRC = (
        "interface GigabitEthernet0/1\n switchport mode access\n switchport port-security\n"
        " switchport port-security maximum 2\n switchport port-security violation restrict\n"
        " switchport port-security mac-address sticky\n"
    )

    def test_cisco_to_huawei(self):
        result = c2h(self.SRC)
        assert block(result, "interface GigabitEthernet0/1") == [
            "interface GigabitEthernet0/1",
            " port link-type access",
            " port-security enable",
            " port-security max-mac-num 2",
            " port-security protect-action restrict",
            " port-security mac-address sticky",
        ]
        assert "max-mac-number" not in result.text
        assert not result.unconverted_items

    def test_shutdown_violation_maps_to_error_down(self):
        result = c2h("interface GigabitEthernet0/1\n switchport port-security violation shutdown\n")
        assert has_cmd(result, "port-security protect-action error-down")

    def test_huawei_to_cisco(self):
        src = ("interface GigabitEthernet0/0/1\n port-security enable\n port-security max-mac-num 5\n"
               " port-security protect-action error-down\n")
        result = h2c(src)
        assert has_cmd(result, "switchport port-security")
        assert has_cmd(result, "switchport port-security maximum 5")
        assert has_cmd(result, "switchport port-security violation shutdown")

    def test_zero_maximum_unconverted(self):
        result = c2h("interface GigabitEthernet0/1\n switchport port-security maximum 0\n")
        assert [i.command.strip() for i in result.unconverted_items] == ["switchport port-security maximum 0"]

    def test_round_trip(self):
        original = parse_config(self.SRC, C).ir
        assert parse_config(c2h(self.SRC).text, H).ir.intent() == original.intent()


# =========================================================================== medium config, hybrid


class TestMediumConfigHybrid:
    def test_fully_converted_by_rules(self):
        result = c2h(MEDIUM)
        assert not result.unconverted_items, result.annotated_text

    def test_hybrid_sends_nothing_to_ai(self):
        fake = FakeAI(["rsa local-key-pair create"])
        result = convert(MEDIUM, C, H, HYBRID, translator=fake)
        assert fake.sent == []
        assert result.ai_sent_line_numbers == []
        assert NOTICE_HYBRID_NOTHING_TO_SEND in result.notices
        assert result.ai_line_count == 0

    def test_expected_huawei_commands(self):
        result = c2h(MEDIUM)
        for line in (
            "clock timezone ICT add 07:00:00",
            "ssh server compatible-ssh1x disable",
            "ssh server timeout 60",
            "ssh server authentication-retries 3",
            "stp bpdu-protection",
        ):
            assert cmd(result, line).text == line  # exactly once, top level
        assert commands(result).count(" authentication-mode aaa") == 2
        assert commands(result).count(" port-security max-mac-num 2") == 1
        assert commands(result).count(" dhcp snooping enable") == 2

    def test_forbidden_forms_absent(self):
        text = c2h(MEDIUM).text
        for bad in (
            "rsa local-key-pair create",
            "ssh client timeout",
            "ssh server retry",
            "authentication-mode local",
            "max-mac-number",
        ):
            assert bad not in text
        assert not re.search(r"dhcp[ \t]+snooping[ \t]+enable[ \t]+vlan", text)
        assert not any(l.strip() == "stelnet server enable" for l in commands(c2h(MEDIUM)))

    def test_bpdu_protection_only_at_system_view(self):
        out = commands(c2h(MEDIUM))
        assert [l for l in out if "bpdu-protection" in l] == ["stp bpdu-protection"]

    def test_all_rule_lines_deployable(self):
        deployed = _deploy(c2h(MEDIUM))
        assert "stp bpdu-protection" in deployed
        assert " port-security max-mac-num 2" in deployed
        assert "clock timezone ICT add 07:00:00" in deployed


# =========================================================================== 3. AI prompt


class TestHuaweiPromptConstraints:
    @pytest.fixture
    def prompt(self):
        return _system_prompt(C, H)

    def test_never_rsa_key_pair(self, prompt):
        assert "Never emit 'rsa local-key-pair create'" in prompt
        assert "[Y/N]" in prompt

    def test_clock(self, prompt):
        assert "'clock timezone <tz> add HH:MM:SS'" in prompt
        assert "'clock timezone ICT 7 0' -> 'clock timezone ICT add 07:00:00'" in prompt

    def test_ssh(self, prompt):
        assert "'ip ssh version 2' -> 'ssh server compatible-ssh1x disable'" in prompt
        assert "'ssh server timeout <sec>' (never 'ssh client timeout')" in prompt
        assert "'ssh server authentication-retries <n>' (never 'ssh server retry')" in prompt
        assert "Do not add 'stelnet server enable' on your own" in prompt

    def test_login_local(self, prompt):
        assert "'login local' inside 'line vty' or 'line con' -> 'authentication-mode aaa'" in prompt
        assert "(never 'authentication-mode local')" in prompt

    def test_dhcp_snooping(self, prompt):
        assert "('vlan <id>', then ' dhcp snooping enable', then 'quit')" in prompt
        assert "Never emit the global form 'dhcp snooping enable vlan ...'" in prompt

    def test_bpdu_protection(self, prompt):
        assert "Emit 'stp bpdu-protection' ONLY at global system-view level" in prompt
        assert "NEVER inside an 'interface' or 'port-group' block" in prompt

    def test_port_security(self, prompt):
        assert "'port-security max-mac-num <n>'" in prompt
        assert "(never 'port-security max-mac-number')" in prompt

    def test_cisco_target_has_none_of_them(self):
        prompt = _system_prompt(H, C)
        for needle in ("rsa local-key-pair", "compatible-ssh1x", "max-mac-num", "stp bpdu-protection",
                       "dhcp snooping enable"):
            assert needle not in prompt


# =========================================================================== i18n


@pytest.mark.parametrize(
    "message",
    [REASON_BPDUGUARD_INTERFACE, REASON_DHCP_SERVICE, WARN_DHCP_ENABLE, WARN_DHCP_SNOOPING_VLAN_UNDECLARED,
     ADVISORY_AI_INTERACTIVE],
)
def test_new_messages_have_english(message):
    english = translate_message(message, "en")
    assert english != message and not re.search("[฀-๿]", english)
    assert translate_message(message, "th") == message
