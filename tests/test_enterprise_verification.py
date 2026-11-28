"""High-complexity Enterprise Cisco -> Huawei VRP verification (after commit a5c7bd9).

1. AI prompt forbids the invented `undo ssh server` (and still forbids auto-adding `stelnet server enable`).
2. EtherChannel / LACP: Port-channel <-> Eth-Trunk, `channel-group <id> mode active` <->
   `mode lacp-static` (in Eth-Trunk) + `eth-trunk <id>` (in members); Eth-Trunk always comes
   before its members, in every mode (incl. AI output).
3. STP root bridge: `spanning-tree vlan <list> root primary|secondary` -> `stp root primary|secondary`
   (no vlan parameter) + single-instance warning.
4. Storm control always uses `percent`; `switchport voice vlan` -> `voice-vlan <vid> enable` + hybrid warning.
5. OSPF: `ip ospf network point-to-point` -> `ospf network-type p2p`; `passive-interface default`
   -> `silent-interface all`; `no passive-interface <if>` -> `undo silent-interface <if>`.
6. HSRP tracking -> `vrrp vrid <g> track interface <if> reduced <dec>` inside `interface Vlanif<id>`
   (never a standalone `bfd track`); `logging source-interface` -> `info-center loghost source`;
   AI prompt keeps 4-octet ACL wildcards.
"""

from __future__ import annotations

import re

import pytest

from app.core.engine import convert, convert_selected
from app.core.ir import ConversionMode, Provenance, RenderedLine
from app.core.parsers import parse_config
from app.core.renderers.common import (
    WARN_CISCO_VRRP,
    WARN_ETH_TRUNK_MEMBER,
    WARN_HSRP_TO_VRRP,
    WARN_STP_ROOT_SINGLE_INSTANCE,
    WARN_TRACK_OBJECT_ASSIGNED,
    WARN_VOICE_VLAN_HYBRID,
    WARN_VRRP_NO_VIRTUAL_IP,
)
from app.core.renderers.huawei_vrp import order_eth_trunk
from app.core.rules.base import REASON_BAD_VALUE, auto_ai_eligible
from app.core.rules.tier1_interface import (
    FEATURE_PAGP,
    REASON_CHANNEL_MODE_CONFLICT,
    REASON_CHANNEL_PROTOCOL,
    REASON_LACP_NOT_TRUNK,
    REASON_TRACK_UNKNOWN,
    REASON_TRACK_UNUSED,
    REASON_VRRP_PREEMPT,
)
from app.core.rules.tier1_vlan import REASON_STORM_FRACTION
from app.core.rules.tier2_services import REASON_STP_ROOT_CONFLICT, REASON_STP_ROOT_NO_VLANS
from app.i18n import translate_message
from app.services.ai_translator import _system_prompt
from app.services.deploy_service import build_plan
from tests.helpers import C, H, block, c2h, cmd, commands, h2c, has_cmd

HYBRID, AI_ONLY = ConversionMode.HYBRID, ConversionMode.AI_ONLY
RULE = Provenance.RULE


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return build_plan(lines, result.target_vendor).commands


def _index(result, text: str) -> int:
    return next(i for i, l in enumerate(result.lines) if not l.is_comment and l.text.strip() == text)


def _reasons(result) -> dict[int, str]:
    return {i.line_no: i.reason for i in result.unconverted_items}


class NoAI:
    """Hybrid translator that fails the test if the rules leave anything for AI."""

    def translate_items(self, items, source, target):  # pragma: no cover
        raise AssertionError(f"rules should cover every line, AI got {[i.lines for i in items]}")

    def translate_config(self, text, source, target):  # pragma: no cover
        raise AssertionError("ai_only not expected")


class Recorder:
    """Hybrid translator that records what it was asked and answers a fixed line per item."""

    def __init__(self, answer: list[str] | None = None):
        self.sent: list[list[str]] = []
        self.answer = answer or ["# review"]

    def translate_items(self, items, source, target):
        self.sent.extend(i.lines for i in items)
        return {i.id: list(self.answer) for i in items}


# =========================================================================== 1. AI prompt: SSH


class TestPromptSsh:
    def test_undo_ssh_server_is_forbidden(self):
        prompt = _system_prompt(C, H)
        assert "NEVER invent 'undo ssh server'" in prompt
        assert "does not exist in Huawei VRP" in prompt

    def test_stelnet_rule_is_kept(self):
        prompt = _system_prompt(C, H)
        assert "NEVER invent or auto-add 'stelnet server enable'" in prompt
        assert "Do not add 'stelnet server enable' on your own" in prompt

    def test_rule_engine_never_emits_undo_ssh_server(self):
        src = "ip ssh version 2\nip ssh time-out 60\nline vty 0 4\n login local\n transport input ssh\n"
        result = c2h(src)
        assert not any("undo ssh server" in l.text for l in result.lines)
        assert not has_cmd(result, "stelnet server enable")  # advisory comment only


# =========================================================================== 2. EtherChannel / LACP


class TestEtherChannel:
    SRC = (
        "interface Port-channel1\n"
        " description UPLINK\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan 10,20\n"
        "interface GigabitEthernet0/0/1\n"
        " channel-group 1 mode active\n"
        "interface GigabitEthernet0/0/2\n"
        " channel-protocol lacp\n"
        " channel-group 1 mode active\n"
    )

    def test_port_channel_becomes_eth_trunk_with_lacp_static(self):
        result = c2h(self.SRC)
        trunk = block(result, "interface Eth-Trunk1")
        assert trunk[:2] == ["interface Eth-Trunk1", " description UPLINK"]
        assert " mode lacp-static" in trunk
        assert trunk.index(" mode lacp-static") < trunk.index(" port link-type trunk")
        assert cmd(result, "mode lacp-static").provenance is RULE
        assert cmd(result, "mode lacp-static").source_line == 6  # from the first member's channel-group

    def test_members_bind_eth_trunk(self):
        result = c2h(self.SRC)
        assert block(result, "interface GigabitEthernet0/0/1") == ["interface GigabitEthernet0/0/1", " eth-trunk 1"]
        assert block(result, "interface GigabitEthernet0/0/2") == ["interface GigabitEthernet0/0/2", " eth-trunk 1"]
        member = [l for l in result.lines if l.text == " eth-trunk 1"]
        assert len(member) == 2 and all(l.provenance is RULE and l.warning == WARN_ETH_TRUNK_MEMBER for l in member)
        assert not any("channel-group" in l.text for l in result.lines if not l.is_comment)

    def test_channel_protocol_lacp_is_not_needed(self):
        result = c2h(self.SRC)
        assert _reasons(result) == {}
        notes = [l for l in result.lines if l.provenance is Provenance.NOT_NEEDED]
        assert len(notes) == 1 and notes[0].source_line == 8 and REASON_CHANNEL_PROTOCOL in notes[0].text

    def test_eth_trunk_rendered_before_members_when_source_lists_it_last(self):
        src = (
            "interface GigabitEthernet0/0/1\n channel-group 2 mode active\n"
            "interface GigabitEthernet0/0/2\n channel-group 2 mode active\n"
            "interface Port-channel2\n switchport mode access\n switchport access vlan 10\n"
        )
        result = c2h(src)
        assert _index(result, "interface Eth-Trunk2") < _index(result, "interface GigabitEthernet0/0/1")
        trunk = cmd(result, "interface Eth-Trunk2")
        assert trunk.source_line == 5  # header keeps its own source line
        assert block(result, "interface Eth-Trunk2") == [
            "interface Eth-Trunk2", " mode lacp-static", " port link-type access", " port default vlan 10"]

    def test_member_without_port_channel_block_still_creates_eth_trunk(self):
        result = c2h("interface GigabitEthernet0/0/1\n channel-group 3 mode active\n")
        assert block(result, "interface Eth-Trunk3") == ["interface Eth-Trunk3", " mode lacp-static"]
        assert cmd(result, "interface Eth-Trunk3").provenance is RULE
        assert _index(result, "interface Eth-Trunk3") < _index(result, "interface GigabitEthernet0/0/1")
        assert not result.unconverted_items

    def test_mode_on_is_manual_eth_trunk(self):
        result = c2h("interface Port-channel4\ninterface GigabitEthernet0/0/1\n channel-group 4 mode on\n")
        assert has_cmd(result, "eth-trunk 4")
        assert not any("lacp" in l.text for l in result.lines if not l.is_comment)

    def test_range_members_use_port_group(self):
        result = c2h("interface range GigabitEthernet0/0/1 - 2\n channel-group 5 mode active\n")
        out = commands(result)
        pg = out.index("port-group group-member GigabitEthernet0/0/1 to GigabitEthernet0/0/2")
        assert out[pg + 1] == " eth-trunk 5"
        assert out.index("interface Eth-Trunk5") < pg

    @pytest.mark.parametrize("mode", ["passive", "desirable", "auto"])
    def test_pagp_and_passive_are_not_supported(self, mode):
        result = c2h(f"interface GigabitEthernet0/0/1\n channel-group 1 mode {mode}\n")
        reason = _reasons(result)[2]
        assert FEATURE_PAGP in reason and not auto_ai_eligible(reason)
        assert not has_cmd(result, "eth-trunk 1")

    def test_conflicting_member_modes(self):
        src = ("interface GigabitEthernet0/0/1\n channel-group 1 mode active\n"
               "interface GigabitEthernet0/0/2\n channel-group 1 mode on\n")
        result = c2h(src)
        assert _reasons(result) == {4: REASON_CHANNEL_MODE_CONFLICT}

    def test_deploy_plan_keeps_trunk_before_members(self):
        plan = _deploy(c2h(self.SRC))
        assert plan.index("interface Eth-Trunk1") < plan.index("interface GigabitEthernet0/0/1")
        assert " mode lacp-static" in plan and plan.count(" eth-trunk 1") == 2

    def test_hybrid_does_not_call_ai(self):
        result = convert(self.SRC, C, H, HYBRID, translator=NoAI())
        assert not any(l.provenance is Provenance.AI for l in result.lines)

    def test_huawei_to_cisco(self):
        src = ("interface Eth-Trunk1\n mode lacp-static\n port link-type trunk\n"
               "interface GigabitEthernet0/0/1\n eth-trunk 1\n")
        result = h2c(src)
        assert has_cmd(result, "interface Port-channel1")
        assert block(result, "interface GigabitEthernet0/0/1") == [
            "interface GigabitEthernet0/0/1", " channel-group 1 mode active"]
        assert not result.unconverted_items

    def test_huawei_manual_trunk_to_cisco_mode_on(self):
        result = h2c("interface Eth-Trunk1\ninterface GigabitEthernet0/0/1\n eth-trunk 1\n")
        assert has_cmd(result, "channel-group 1 mode on")

    def test_lacp_static_outside_eth_trunk_is_unconverted(self):
        result = h2c("interface GigabitEthernet0/0/1\n mode lacp-static\n")
        assert _reasons(result) == {2: REASON_LACP_NOT_TRUNK}

    def test_round_trip_intent(self):
        first = parse_config(self.SRC, C).ir
        again = parse_config("\n".join(l.text for l in c2h(self.SRC).lines), H).ir
        assert first.intent()["interfaces"] == again.intent()["interfaces"]


class TestEthTrunkFinalAssembly:
    def _lines(self, *texts: str) -> list[RenderedLine]:
        return [RenderedLine(text=t, provenance=Provenance.AI, is_comment=t.startswith("#")) for t in texts]

    def test_ai_output_trunk_moved_before_members(self):
        lines = self._lines(
            "system-view",
            "interface GigabitEthernet0/0/1", " eth-trunk 1", "quit",
            "interface GigabitEthernet0/0/2", " eth-trunk 1", "quit",
            "interface Eth-Trunk1", " mode lacp-static", " port link-type trunk", "quit",
            "return",
        )
        out = [l.text for l in order_eth_trunk(lines)]
        assert out == [
            "system-view",
            "interface Eth-Trunk1", " mode lacp-static", " port link-type trunk", "quit",
            "interface GigabitEthernet0/0/1", " eth-trunk 1", "quit",
            "interface GigabitEthernet0/0/2", " eth-trunk 1", "quit",
            "return",
        ]

    def test_correct_order_is_untouched(self):
        lines = self._lines("interface Eth-Trunk1", " mode lacp-static", "#",
                            "interface GigabitEthernet0/0/1", " eth-trunk 1", "#")
        assert order_eth_trunk(lines) == lines

    def test_port_group_member_counts(self):
        lines = self._lines("port-group group-member GigabitEthernet0/0/1 to GigabitEthernet0/0/2", " eth-trunk 7",
                            "#", "interface Eth-Trunk7", " mode lacp-static", "#")
        out = [l.text for l in order_eth_trunk(lines)]
        assert out.index("interface Eth-Trunk7") < out.index(
            "port-group group-member GigabitEthernet0/0/1 to GigabitEthernet0/0/2")

    def test_ai_only_mode_is_reordered(self):
        class Fake:
            def translate_config(self, text, source, target):
                return ["system-view", "interface GigabitEthernet0/0/1", " eth-trunk 1", "quit",
                        "interface Eth-Trunk1", " mode lacp-static", "quit", "return"]

        result = convert("interface GigabitEthernet0/0/1\n channel-group 1 mode active\n", C, H, AI_ONLY,
                         translator=Fake())
        assert _index(result, "interface Eth-Trunk1") < _index(result, "interface GigabitEthernet0/0/1")

    def test_ai_prompt_states_eth_trunk_mapping_and_order(self):
        prompt = _system_prompt(C, H)
        assert "'interface Port-channel<id>' -> 'interface Eth-Trunk<id>'" in prompt
        assert "'channel-group <id> mode active' -> ' mode lacp-static'" in prompt
        assert "' eth-trunk <id>' inside the member interface" in prompt
        assert "ALWAYS emit the 'interface Eth-Trunk<id>' block BEFORE any member" in prompt


# =========================================================================== 3. STP root bridge


class TestStpRoot:
    def test_primary_without_vlan_parameter(self):
        result = c2h("spanning-tree mode rapid-pvst\nspanning-tree vlan 10,20,30-35 root primary\n")
        line = cmd(result, "stp root primary")
        assert line.text == "stp root primary"  # system view, no vlan parameter
        assert line.provenance is RULE and line.warning == WARN_STP_ROOT_SINGLE_INSTANCE
        assert not any("vlan" in l.text for l in result.lines if not l.is_comment and "stp" in l.text)
        assert _index(result, "stp mode rstp") < _index(result, "stp root primary")
        assert not result.unconverted_items

    def test_secondary(self):
        assert cmd(c2h("spanning-tree vlan 1-4094 root secondary\n"), "stp root secondary").provenance is RULE

    def test_same_role_lines_merge_into_one_command(self):
        result = c2h("spanning-tree vlan 10 root primary\nspanning-tree vlan 20 root primary\n")
        assert commands(result).count("stp root primary") == 1
        assert not result.unconverted_items

    def test_conflicting_roles_are_not_guessed(self):
        result = c2h("spanning-tree vlan 10 root primary\nspanning-tree vlan 20 root secondary\n")
        assert has_cmd(result, "stp root primary") and not has_cmd(result, "stp root secondary")
        assert _reasons(result) == {2: REASON_STP_ROOT_CONFLICT}
        assert not auto_ai_eligible(REASON_STP_ROOT_CONFLICT)

    def test_warning_mentions_single_instance_and_mstp(self):
        assert "stp mode rstp" in WARN_STP_ROOT_SINGLE_INSTANCE
        assert "stp instance <id> root primary" in WARN_STP_ROOT_SINGLE_INSTANCE

    def test_deployable(self):
        assert "stp root primary" in _deploy(c2h("spanning-tree vlan 10 root primary\n"))

    def test_huawei_to_cisco_is_not_guessed(self):
        result = h2c("stp root primary\n")
        assert _reasons(result) == {1: REASON_STP_ROOT_NO_VLANS}
        assert not any("spanning-tree vlan" in l for l in commands(result))

    def test_ir_keeps_role_and_vlans(self):
        ir = parse_config("spanning-tree vlan 10,20 root primary\nspanning-tree vlan 30 root primary\n", C).ir
        assert (ir.stp_root, ir.stp_root_vlans) == ("primary", [10, 20, 30])

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'spanning-tree vlan <list> root primary' -> 'stp root primary'" in prompt
        assert "'spanning-tree vlan <list> root secondary' -> 'stp root secondary'" in prompt
        assert "NO 'vlan' parameter" in prompt and "'stp instance <id> root primary'" in prompt


# =========================================================================== 4. storm control & voice VLAN


class TestStormControl:
    @pytest.mark.parametrize(
        ("src", "expected"),
        [
            ("storm-control broadcast level 10", "storm-control broadcast min-rate percent 10 max-rate percent 10"),
            ("storm-control broadcast level 10.00", "storm-control broadcast min-rate percent 10 max-rate percent 10"),
            ("storm-control multicast level 20 10", "storm-control multicast min-rate percent 10 max-rate percent 20"),
            ("storm-control unicast level 80", "storm-control unicast min-rate percent 80 max-rate percent 80"),
        ],
    )
    def test_percent_is_always_written(self, src, expected):
        result = c2h(f"interface GigabitEthernet0/0/5\n {src}\n")
        line = cmd(result, expected)
        assert line.provenance is RULE and line.source_line == 2
        assert not result.unconverted_items

    def test_never_bare_numbers(self):
        result = c2h("interface GigabitEthernet0/0/5\n storm-control broadcast level 5\n")
        storm = [l.text for l in result.lines if "storm-control" in l.text and not l.is_comment]
        assert storm and all(re.search(r"min-rate percent \d+ max-rate percent \d+$", t) for t in storm)
        assert not any(re.search(r"min-rate \d", t) for t in storm)

    def test_fractional_percent_is_not_rounded_or_sent_to_ai(self):
        src = "interface GigabitEthernet0/0/5\n storm-control broadcast level 10.50\n"
        result = c2h(src)
        assert _reasons(result) == {2: REASON_STORM_FRACTION}
        rec = Recorder()
        convert(src, C, H, HYBRID, translator=rec)
        assert rec.sent == []

    @pytest.mark.parametrize("level", ["0", "101", "20 30"])
    def test_out_of_range_values(self, level):
        result = c2h(f"interface GigabitEthernet0/0/5\n storm-control broadcast level {level}\n")
        assert _reasons(result) == {2: REASON_BAD_VALUE}

    def test_pps_and_bps_forms_have_no_rule(self):
        result = c2h("interface GigabitEthernet0/0/5\n storm-control broadcast level pps 1000\n")
        assert 2 in _reasons(result) and auto_ai_eligible(_reasons(result)[2])

    def test_huawei_to_cisco(self):
        src = ("interface GigabitEthernet0/0/5\n storm-control broadcast min-rate percent 10 max-rate percent 10\n"
               " storm-control multicast min-rate percent 5 max-rate percent 20\n")
        result = h2c(src)
        assert has_cmd(result, "storm-control broadcast level 10")
        assert has_cmd(result, "storm-control multicast level 20 5")
        assert not result.unconverted_items

    def test_round_trip_intent(self):
        src = "interface GigabitEthernet0/0/5\n storm-control broadcast level 10\n storm-control unicast level 50 40\n"
        first = parse_config(src, C).ir
        again = parse_config("\n".join(l.text for l in c2h(src).lines), H).ir
        assert first.intent()["interfaces"] == again.intent()["interfaces"]

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'storm-control broadcast min-rate percent <pct> max-rate percent <pct>'" in prompt
        assert "ALWAYS include the keyword 'percent'" in prompt
        assert "packets per second" in prompt


class TestVoiceVlan:
    SRC = ("interface GigabitEthernet0/0/5\n switchport mode access\n switchport access vlan 10\n"
           " switchport voice vlan 20\n")

    def test_cisco_to_huawei(self):
        result = c2h(self.SRC)
        line = cmd(result, "voice-vlan 20 enable")
        assert line.provenance is RULE and line.warning == WARN_VOICE_VLAN_HYBRID
        assert not result.unconverted_items
        assert not has_cmd(result, "port link-type hybrid")  # advice only, never converted to hybrid

    def test_warning_names_the_hybrid_commands(self):
        for needle in ("port link-type hybrid", "port hybrid tagged vlan", "port hybrid untagged vlan"):
            assert needle in WARN_VOICE_VLAN_HYBRID

    def test_huawei_to_cisco(self):
        result = h2c("interface GigabitEthernet0/0/5\n voice-vlan 20 enable\n")
        assert has_cmd(result, "switchport voice vlan 20") and not result.unconverted_items

    def test_bad_vlan(self):
        result = c2h("interface GigabitEthernet0/0/5\n switchport voice vlan 5000\n")
        assert 2 in _reasons(result)

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'switchport voice vlan <vid>' -> 'voice-vlan <vid> enable'" in prompt
        assert "'port hybrid tagged vlan <vid>'" in prompt and "'port hybrid untagged vlan <access_vid>'" in prompt


# =========================================================================== 5. OSPF p2p & silent-interface


class TestOspfEnterprise:
    SRC = (
        "interface Vlan10\n ip address 10.0.10.1 255.255.255.0\n ip ospf network point-to-point\n"
        "router ospf 1\n router-id 1.1.1.1\n passive-interface default\n no passive-interface Vlan10\n"
        " no passive-interface GigabitEthernet0/0/1\n network 10.0.10.0 0.0.0.255 area 0\n"
    )

    def test_p2p(self):
        result = c2h(self.SRC)
        assert cmd(result, "ospf network-type p2p").provenance is RULE

    def test_passive_default_and_exceptions(self):
        result = c2h(self.SRC)
        ospf = block(result, "ospf 1 router-id 1.1.1.1")
        assert ospf[1:4] == [" silent-interface all", " undo silent-interface Vlanif10",
                             " undo silent-interface GigabitEthernet0/0/1"]
        assert cmd(result, "silent-interface all").source_line == 6
        assert cmd(result, "undo silent-interface Vlanif10").source_line == 7
        assert not result.unconverted_items

    def test_hybrid_does_not_call_ai(self):
        convert(self.SRC, C, H, HYBRID, translator=NoAI())

    def test_huawei_to_cisco(self):
        src = ("ospf 1\n silent-interface all\n undo silent-interface Vlanif10\n area 0.0.0.0\n"
               "  network 10.0.10.0 0.0.0.255\n")
        result = h2c(src)
        out = commands(result)
        assert out.index(" passive-interface default") < out.index(" no passive-interface Vlan10")
        assert not result.unconverted_items

    def test_round_trip_intent(self):
        first = parse_config(self.SRC, C).ir
        again = parse_config("\n".join(l.text for l in c2h(self.SRC).lines), H).ir
        assert first.intent()["ospf"] == again.intent()["ospf"]

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'ip ospf network point-to-point' -> 'ospf network-type p2p'" in prompt
        assert "'passive-interface default' -> 'silent-interface all'" in prompt
        assert "'no passive-interface <if>' -> 'undo silent-interface <if>'" in prompt


# =========================================================================== 6. HSRP -> VRRP tracking, syslog source


class TestHsrpTracking:
    SRC = (
        "track 1 interface GigabitEthernet0/0/24 line-protocol\n"
        "interface Vlan10\n"
        " ip address 10.0.10.2 255.255.255.0\n"
        " standby 10 ip 10.0.10.1\n"
        " standby 10 priority 110\n"
        " standby 10 preempt\n"
        " standby 10 track 1 decrement 20\n"
        " standby 10 track GigabitEthernet0/0/23 30\n"
    )

    def test_vrrp_inside_vlanif(self):
        result = c2h(self.SRC)
        assert block(result, "interface Vlanif10") == [
            "interface Vlanif10",
            " ip address 10.0.10.2 255.255.255.0",
            " vrrp vrid 10 virtual-ip 10.0.10.1",
            " vrrp vrid 10 priority 110",
            " vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20",
            " vrrp vrid 10 track interface GigabitEthernet0/0/23 reduced 30",
        ]
        assert not result.unconverted_items

    def test_labels_and_warnings(self):
        result = c2h(self.SRC)
        vip = cmd(result, "vrrp vrid 10 virtual-ip 10.0.10.1")
        assert vip.provenance is RULE and vip.warning == WARN_HSRP_TO_VRRP
        track = cmd(result, "vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20")
        assert track.provenance is RULE and track.source_line == 7

    def test_preempt_is_not_needed(self):
        result = c2h(self.SRC)
        notes = [l for l in result.lines if l.provenance is Provenance.NOT_NEEDED]
        assert len(notes) == 1 and notes[0].source_line == 6 and REASON_VRRP_PREEMPT in notes[0].text

    def test_never_bfd_track_or_track_object(self):
        result = c2h(self.SRC)
        for l in result.lines:
            if l.is_comment:
                continue
            assert "bfd" not in l.text.lower()
            assert not re.match(r"^\s*track\b", l.text)

    def test_track_object_folded_into_vrrp_line(self):
        result = c2h(self.SRC)
        assert not any(l.source_line == 1 and not l.is_comment for l in result.lines)  # no standalone command
        assert 1 not in _reasons(result)

    def test_unknown_track_object(self):
        src = "interface Vlan10\n ip address 10.0.10.2 255.255.255.0\n standby 10 track 9 decrement 20\n"
        result = c2h(src)
        assert _reasons(result) == {3: REASON_TRACK_UNKNOWN}
        assert not any("track" in l for l in commands(result))

    def test_unused_track_object_stays_unconverted_and_not_sent_to_ai(self):
        src = "track 5 interface GigabitEthernet0/0/1 line-protocol\n"
        result = c2h(src)
        assert _reasons(result) == {1: REASON_TRACK_UNUSED}
        rec = Recorder(["bfd track 5"])
        out = convert(src, C, H, HYBRID, translator=rec)
        assert rec.sent == [] and not has_cmd(out, "bfd track 5")

    def test_track_without_virtual_ip_warns(self):
        src = "interface Vlan10\n ip address 10.0.10.2 255.255.255.0\n standby 10 track GigabitEthernet0/0/1 10\n"
        line = cmd(c2h(src), "vrrp vrid 10 track interface GigabitEthernet0/0/1 reduced 10")
        assert WARN_VRRP_NO_VIRTUAL_IP in line.warning

    @pytest.mark.parametrize("src", [" standby 0 ip 10.0.10.1", " standby 300 ip 10.0.10.1",
                                     " standby 10 priority 255", " standby 10 track Gi0/0/1 0"])
    def test_bad_values(self, src):
        result = c2h(f"interface Vlan10\n{src}\n")
        assert _reasons(result) == {2: REASON_BAD_VALUE}

    def test_deploy_plan(self):
        plan = _deploy(c2h(self.SRC))
        assert " vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20" in plan
        assert plan.index(" vrrp vrid 10 virtual-ip 10.0.10.1") < plan.index(
            " vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20")

    def test_hybrid_does_not_call_ai(self):
        convert(self.SRC, C, H, HYBRID, translator=NoAI())

    def test_huawei_to_cisco_assigns_track_objects(self):
        src = ("interface Vlanif10\n ip address 10.0.10.2 255.255.255.0\n vrrp vrid 10 virtual-ip 10.0.10.1\n"
               " vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20\n")
        result = h2c(src)
        obj = cmd(result, "track 1 interface GigabitEthernet0/0/24 line-protocol")
        assert obj.provenance is Provenance.SYSTEM and obj.warning == WARN_TRACK_OBJECT_ASSIGNED
        assert cmd(result, "vrrp 10 ip 10.0.10.1").warning == WARN_CISCO_VRRP
        assert has_cmd(result, "vrrp 10 track 1 decrement 20")
        assert _index(result, "track 1 interface GigabitEthernet0/0/24 line-protocol") < _index(result, "interface Vlan10")
        assert not result.unconverted_items

    def test_round_trip_tracks(self):
        first = parse_config(self.SRC, C).ir
        again = parse_config("\n".join(l.text for l in c2h(self.SRC).lines), H).ir
        a = first.intent()["interfaces"][0]["vrrp_groups"][0]
        b = again.intent()["interfaces"][0]["vrrp_groups"][0]
        assert (a["virtual_ip"], a["priority"], a["tracks"]) == (b["virtual_ip"], b["priority"], b["tracks"])

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'vrrp vrid <vrid> track interface <if> reduced <dec>'" in prompt
        assert "inside the 'interface Vlanif<id>' block" in prompt
        assert "NEVER emit a standalone 'bfd track ...'" in prompt


class TestSyslogSource:
    def test_cisco_to_huawei(self):
        result = c2h("logging host 10.9.9.9\nlogging source-interface Vlan10\n")
        line = cmd(result, "info-center loghost source Vlanif10")
        assert line.provenance is RULE and line.source_line == 2
        assert not any(re.match(r"^info-center\s+source\b", l) for l in commands(result))
        assert not result.unconverted_items

    def test_loopback_and_physical(self):
        assert has_cmd(c2h("logging source-interface Loopback0\n"), "info-center loghost source LoopBack0")
        assert has_cmd(c2h("logging source-interface Gi0/0/1\n"), "info-center loghost source GigabitEthernet0/0/1")

    def test_unknown_interface(self):
        result = c2h("logging source-interface Foo1\n")
        assert 1 in _reasons(result)

    def test_huawei_to_cisco(self):
        result = h2c("info-center loghost source Vlanif10\n")
        assert has_cmd(result, "logging source-interface Vlan10") and not result.unconverted_items

    def test_ai_prompt(self):
        prompt = _system_prompt(C, H)
        assert "'logging source-interface <if>' -> 'info-center loghost source <if>'" in prompt
        assert "NEVER 'info-center source <if>'" in prompt


class TestPromptAclWildcard:
    def test_four_octet_wildcards(self):
        prompt = _system_prompt(C, H)
        assert "keep all 4 octets" in prompt and "'0.0.0.255'" in prompt and "never '0.0.255'" in prompt

    def test_rule_engine_keeps_four_octets(self):
        result = c2h("access-list 10 permit 192.168.1.0 0.0.0.255\n")
        assert any(l.text.strip().endswith("192.168.1.0 0.0.0.255") for l in result.lines if not l.is_comment)


class TestCiscoTargetPrompt:
    def test_has_no_huawei_enterprise_constraints(self):
        prompt = _system_prompt(H, C)
        for needle in ("undo ssh server", "lacp-static", "stp root", "min-rate percent", "voice-vlan",
                       "silent-interface all", "vrrp vrid", "info-center loghost source", "bfd track"):
            assert needle not in prompt


# =========================================================================== end-to-end enterprise config


ENTERPRISE = """hostname CORE1
spanning-tree mode rapid-pvst
spanning-tree vlan 10,20 root primary
track 1 interface GigabitEthernet0/0/24 line-protocol
interface GigabitEthernet0/0/1
 channel-group 1 mode active
interface GigabitEthernet0/0/2
 channel-group 1 mode active
interface Port-channel1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
interface GigabitEthernet0/0/5
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
 storm-control broadcast level 10.00
interface Vlan10
 ip address 10.0.10.2 255.255.255.0
 standby 10 ip 10.0.10.1
 standby 10 priority 110
 standby 10 track 1 decrement 20
router ospf 1
 passive-interface default
 no passive-interface Vlan10
 network 10.0.10.0 0.0.0.255 area 0
logging host 10.9.9.9
logging source-interface Vlan10
"""


class TestEnterpriseEndToEnd:
    def test_rule_only_converts_everything(self):
        result = c2h(ENTERPRISE)
        assert not result.unconverted_items
        assert all(l.provenance in (RULE, Provenance.SYSTEM) for l in result.lines if not l.is_comment)

    def test_hybrid_never_needs_ai(self):
        result = convert(ENTERPRISE, C, H, HYBRID, translator=NoAI())
        assert not any(l.provenance is Provenance.AI for l in result.lines)

    def test_user_selected_with_nothing_unconverted(self):
        result = convert_selected(ENTERPRISE, C, H, [3, 6], Recorder())
        assert not any(l.provenance is Provenance.AI for l in result.lines)

    def test_key_commands(self):
        result = c2h(ENTERPRISE)
        for text in ("stp root primary", "interface Eth-Trunk1", "mode lacp-static", "eth-trunk 1",
                     "voice-vlan 20 enable", "storm-control broadcast min-rate percent 10 max-rate percent 10",
                     "vrrp vrid 10 track interface GigabitEthernet0/0/24 reduced 20",
                     "silent-interface all", "undo silent-interface Vlanif10", "info-center loghost source Vlanif10"):
            assert has_cmd(result, text), text
        assert _index(result, "interface Eth-Trunk1") < _index(result, "interface GigabitEthernet0/0/1")


# =========================================================================== i18n


@pytest.mark.parametrize(
    "message",
    [
        WARN_STP_ROOT_SINGLE_INSTANCE, WARN_ETH_TRUNK_MEMBER, WARN_VOICE_VLAN_HYBRID, WARN_HSRP_TO_VRRP,
        WARN_VRRP_NO_VIRTUAL_IP, WARN_TRACK_OBJECT_ASSIGNED, WARN_CISCO_VRRP,
        REASON_CHANNEL_PROTOCOL, REASON_CHANNEL_MODE_CONFLICT, REASON_LACP_NOT_TRUNK, REASON_VRRP_PREEMPT,
        REASON_TRACK_UNUSED, REASON_TRACK_UNKNOWN, REASON_STORM_FRACTION, REASON_STP_ROOT_CONFLICT,
        REASON_STP_ROOT_NO_VLANS,
    ],
)
def test_new_messages_have_english(message):
    english = translate_message(message, "en")
    assert english != message and not re.search("[฀-๿]", english)
    assert translate_message(message, "th") == message


def test_pagp_reason_has_english():
    result = c2h("interface GigabitEthernet0/0/1\n channel-group 1 mode passive\n")
    english = translate_message(_reasons(result)[2], "en")
    assert not re.search("[฀-๿]", english) and "PAgP" in english
