"""High-complexity Enterprise verification, round 2 (after commit 3fbf8c9).

1. Cisco `no switchport` <-> Huawei `undo portswitch` (rule), and `undo portswitch` is ALWAYS the
   first command of its interface view (renderer and final assembly, incl. AI output).
2. ACL block-skip boundary: when an ACL is rejected because one entry fails, EVERY line of the
   block (incl. the failing `deny ip any any log`) is locked out of hybrid AI gap-filling.
3. `snmp-server location <text>` <-> `snmp-agent sys-info location <text>` (rule, never AI);
   Cisco `ip routing` -> "ไม่ต้องใช้คำสั่งนี้".
4. No duplicate OSPF router-id inside `ospf <id> router-id <rid>`; no L2 port settings
   (`port link-type` / `port trunk pvid` / VLANs) on Eth-Trunk member ports.
"""

from __future__ import annotations

from app.core.engine import convert
from app.core.ir import ConversionMode, Provenance, RenderedLine
from app.core.renderers.huawei_vrp import (
    WHY_MEMBER_L2,
    WHY_OSPF_RID_DUPLICATE,
    dedupe_ospf_router_id,
    guard_eth_trunk_members,
    order_undo_portswitch,
)
from app.core.rules.base import LineKind, auto_ai_eligible
from app.core.rules.tier1_interface import REASON_MEMBER_L2_ON_TRUNK, REASON_MEMBER_L2_REDUNDANT
from app.core.rules.tier1_system import REASON_IP_ROUTING
from app.core.rules.tier3_bgp_acl import REASON_ACL_PARTIAL
from app.services.deploy_service import build_plan
from tests.helpers import C, H, block, c2h, cmd, commands, h2c, has_cmd

HYBRID, AI_ONLY = ConversionMode.HYBRID, ConversionMode.AI_ONLY
RULE, AI = Provenance.RULE, Provenance.AI


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return [c.strip() for c in build_plan(lines, result.target_vendor).commands]


def _reasons(result) -> dict[int, str]:
    return {i.line_no: i.reason for i in result.unconverted_items}


class NoAI:
    """Hybrid translator that fails the test if the rules leave anything for AI."""

    def translate_items(self, items, source, target):  # pragma: no cover
        raise AssertionError(f"rules should cover every line, AI got {[i.lines for i in items]}")


class Recorder:
    """Hybrid translator that records what it was asked and answers fixed lines per item."""

    def __init__(self, answer: list[str] | None = None):
        self.sent: list[list[str]] = []
        self.answer = answer or ["# review"]

    def translate_items(self, items, source, target):
        self.sent.extend(i.lines for i in items)
        return {i.id: list(self.answer) for i in items}


class WholeFile:
    """ai_only translator returning a fixed Huawei answer."""

    def __init__(self, answer: list[str]):
        self.answer = answer

    def translate_config(self, text, source, target):
        return list(self.answer)


def _lines(*texts: str) -> list[RenderedLine]:
    return [RenderedLine(text=t, provenance=Provenance.RULE, is_comment=t.startswith("#")) for t in texts]


# =========================================================================== 1. undo portswitch


class TestUndoPortswitch:
    SRC = (
        "interface GigabitEthernet0/0/3\n"
        " description TO-CORE\n"
        " ip address 10.0.0.1 255.255.255.252\n"
        " ip ospf network point-to-point\n"
        " no switchport\n"
    )

    def test_no_switchport_is_a_rule(self):
        result = c2h(self.SRC)
        line = cmd(result, "undo portswitch")
        assert line.provenance is RULE and line.source_line == 5
        assert 5 not in _reasons(result)

    def test_undo_portswitch_is_first_line_of_interface(self):
        result = c2h(self.SRC)
        assert block(result, "interface GigabitEthernet0/0/3") == [
            "interface GigabitEthernet0/0/3",
            " undo portswitch",
            " description TO-CORE",
            " ip address 10.0.0.1 255.255.255.252",
            " ospf network-type p2p",
        ]

    def test_hybrid_never_sends_no_switchport_to_ai(self):
        result = convert(self.SRC, C, H, HYBRID, translator=NoAI())
        assert has_cmd(result, "undo portswitch")

    def test_deployed_in_first_position(self):
        plan = _deploy(c2h(self.SRC))
        assert plan.index("interface GigabitEthernet0/0/3") + 1 == plan.index("undo portswitch")

    def test_huawei_to_cisco(self):
        result = h2c("interface GigabitEthernet0/0/3\n ip address 10.0.0.1 255.255.255.252\n undo portswitch\n")
        assert block(result, "interface GigabitEthernet0/0/3")[:2] == [
            "interface GigabitEthernet0/0/3", " no switchport"]
        assert cmd(result, "no switchport").provenance is RULE

    def test_final_assembly_moves_ai_undo_portswitch_first(self):
        lines = _lines("interface GigabitEthernet0/0/3", " ip address 10.0.0.1 255.255.255.252",
                       " ospf network-type p2p", " undo portswitch", "#", "interface GigabitEthernet0/0/4",
                       " undo portswitch", " ip address 10.0.1.1 255.255.255.252", "#")
        out = [l.text for l in order_undo_portswitch(lines)]
        assert out == ["interface GigabitEthernet0/0/3", " undo portswitch", " ip address 10.0.0.1 255.255.255.252",
                       " ospf network-type p2p", "#", "interface GigabitEthernet0/0/4", " undo portswitch",
                       " ip address 10.0.1.1 255.255.255.252", "#"]

    def test_ai_only_output_is_reordered(self):
        fake = WholeFile(["system-view", "interface GigabitEthernet0/0/3", " ip address 10.0.0.1 255.255.255.252",
                          " undo portswitch", "quit", "return"])
        result = convert(self.SRC, C, H, AI_ONLY, translator=fake)
        out = commands(result)
        assert out[out.index("interface GigabitEthernet0/0/3") + 1] == " undo portswitch"

    def test_hybrid_gap_fill_is_reordered(self):
        # `ip mtu` has no rule -> AI fills it inside the interface; `undo portswitch` stays first.
        src = "interface GigabitEthernet0/0/3\n ip mtu 1400\n no switchport\n ip address 10.0.0.1 255.255.255.252\n"
        result = convert(src, C, H, HYBRID, translator=Recorder([" undo portswitch", " mtu 1400"]))
        out = commands(result)
        assert out[out.index("interface GigabitEthernet0/0/3") + 1] == " undo portswitch"


# =========================================================================== 2. ACL block-skip boundary


class TestAclBlockSkip:
    NAMED = (
        "hostname EDGE\n"
        "ip access-list extended EDGE-IN\n"
        " permit tcp any host 10.1.1.1 eq 443\n"
        " permit udp any any eq 53\n"
        " deny ip any any log\n"
        "interface GigabitEthernet0/0/1\n"
        " ip access-group EDGE-IN in\n"
    )

    def test_every_line_of_rejected_acl_is_unconverted_and_locked(self):
        result = c2h(self.NAMED)
        reasons = _reasons(result)
        for no in (2, 3, 4, 5, 7):
            assert no in reasons, f"line {no} must be 'แปลงไม่ได้'"
            assert reasons[no].startswith(REASON_ACL_PARTIAL) or not auto_ai_eligible(reasons[no])
            assert not auto_ai_eligible(reasons[no])

    def test_failing_deny_log_line_keeps_its_cause(self):
        reason = _reasons(c2h(self.NAMED))[5]
        assert reason.startswith(REASON_ACL_PARTIAL) and "(" in reason

    def test_hybrid_sends_nothing_from_the_acl(self):
        rec = Recorder(["rule 5 deny ip"])
        result = convert(self.NAMED, C, H, HYBRID, translator=rec)
        sent = [l.strip() for item in rec.sent for l in item]
        assert not any("deny" in l or "permit" in l or "access-list" in l for l in sent)
        assert not any(l.text.strip().startswith("rule ") for l in result.lines if not l.is_comment)
        assert not any(l.text.strip().startswith("acl ") for l in result.lines if not l.is_comment)

    def test_numbered_acl_with_log_is_locked(self):
        src = "access-list 101 permit tcp any any eq 22\naccess-list 101 deny ip any any log\n"
        rec = Recorder(["rule 10 deny ip"])
        result = convert(src, C, H, HYBRID, translator=rec)
        assert rec.sent == []
        reasons = _reasons(result)
        assert set(reasons) == {1, 2} and not any(auto_ai_eligible(r) for r in reasons.values())

    def test_huawei_partial_acl_is_locked(self):
        src = "acl number 3000\n rule 5 permit tcp destination-port eq 22\n rule 10 deny ip logging\n"
        rec = Recorder(["access-list 100 deny ip any any"])
        result = convert(src, H, C, HYBRID, translator=rec)
        assert rec.sent == []
        assert all(not auto_ai_eligible(r) for r in _reasons(result).values())

    def test_user_can_still_send_the_acl_manually(self):
        from app.core.engine import convert_selected

        rec = Recorder(["acl name EDGE-IN advance"])
        convert_selected(self.NAMED, C, H, [2, 3, 4, 5], rec)
        assert rec.sent, "manual selection must still be possible"

    def test_complete_acl_still_converts(self):
        src = "ip access-list extended OK\n permit tcp any host 10.1.1.1 eq 443\n deny ip any any\n"
        result = c2h(src)
        assert has_cmd(result, "acl name OK advance")
        assert has_cmd(result, "rule 10 deny ip")


# =========================================================================== 3. SNMP location / ip routing


class TestSnmpLocationAndIpRouting:
    SRC = "hostname CORE-SW1\nip routing\nsnmp-server location DC1 Building-A Rack 4\n"

    def test_snmp_location_rule(self):
        result = c2h(self.SRC)
        line = cmd(result, "snmp-agent sys-info location DC1 Building-A Rack 4")
        assert line.provenance is RULE and line.source_line == 3

    def test_sysname_is_untouched(self):
        result = c2h(self.SRC)
        assert cmd(result, "sysname CORE-SW1").provenance is RULE
        assert sum(1 for c in commands(result) if c.startswith("sysname")) == 1

    def test_ip_routing_is_not_needed(self):
        result = c2h(self.SRC)
        assert not has_cmd(result, "ip routing")
        notes = [l for l in result.lines if l.source_line == 2]
        assert notes and all(l.provenance is Provenance.NOT_NEEDED and l.is_comment for l in notes)
        assert REASON_IP_ROUTING in notes[0].text
        assert 2 not in _reasons(result)

    def test_hybrid_sends_nothing(self):
        result = convert(self.SRC, C, H, HYBRID, translator=NoAI())
        assert has_cmd(result, "snmp-agent sys-info location DC1 Building-A Rack 4")

    def test_deploy_plan(self):
        plan = _deploy(c2h(self.SRC))
        assert "snmp-agent sys-info location DC1 Building-A Rack 4" in plan
        assert "ip routing" not in plan

    def test_location_free_text_is_not_out_of_scope(self):
        result = c2h("snmp-server location vrf-lab ipv6 room\n")
        assert has_cmd(result, "snmp-agent sys-info location vrf-lab ipv6 room")

    def test_huawei_to_cisco(self):
        result = h2c("sysname R1\nsnmp-agent sys-info location DC1 Rack 4\n")
        assert cmd(result, "snmp-server location DC1 Rack 4").provenance is RULE

    def test_snmp_community_is_still_stripped(self):
        result = c2h("snmp-server community S3cr3t RO\nsnmp-server location DC1\n")
        assert "S3cr3t" not in result.text
        assert has_cmd(result, "snmp-agent sys-info location DC1")


# =========================================================================== 4a. OSPF router-id


class TestOspfRouterIdDuplicate:
    SRC = "router ospf 1\n router-id 1.1.1.1\n max-metric router-lsa\n network 10.0.0.0 0.0.0.255 area 0\n"

    def test_rule_puts_router_id_in_header_only(self):
        result = c2h("router ospf 1\n router-id 1.1.1.1\n network 10.0.0.0 0.0.0.255 area 0\n")
        assert has_cmd(result, "ospf 1 router-id 1.1.1.1")
        assert not any(c.strip().endswith("router-id 1.1.1.1") and c.startswith(" ") for c in commands(result))

    def test_hybrid_ai_duplicate_is_stripped(self):
        rec = Recorder([" ospf router-id 1.1.1.1", " stub-router"])
        result = convert(self.SRC, C, H, HYBRID, translator=rec)
        assert rec.sent, "the unknown OSPF line should go to AI"
        ospf = block(result, "ospf 1 router-id 1.1.1.1")
        assert not any("router-id" in l for l in ospf[1:])
        assert " stub-router" in ospf
        dropped = [l for l in result.lines if l.is_comment and WHY_OSPF_RID_DUPLICATE in l.text]
        assert len(dropped) == 1 and dropped[0].provenance is AI
        assert "router-id" not in " ".join(c for c in _deploy(result) if not c.startswith("ospf 1"))

    def test_ai_only_duplicate_is_stripped(self):
        fake = WholeFile(["system-view", "ospf 1 router-id 1.1.1.1", " router-id 1.1.1.1", " area 0.0.0.0",
                          "  network 10.0.0.0 0.0.0.255", "quit", "return"])
        result = convert(self.SRC, C, H, AI_ONLY, translator=fake)
        assert not any(c.strip() == "router-id 1.1.1.1" for c in commands(result))

    def test_unit_header_without_router_id_is_untouched(self):
        lines = _lines("ospf 1", " ospf router-id 2.2.2.2", "#")
        assert [l.text for l in dedupe_ospf_router_id(lines)] == ["ospf 1", " ospf router-id 2.2.2.2", "#"]

    def test_unit_other_ospf_block_untouched(self):
        lines = _lines("ospf 1 router-id 1.1.1.1", " area 0.0.0.0", "#", "bgp 65000", " router-id 1.1.1.1", "#")
        out = dedupe_ospf_router_id(lines)
        assert out[4].text == " router-id 1.1.1.1" and not out[4].is_comment


# =========================================================================== 4b. Eth-Trunk members


class TestEthTrunkMemberL2:
    SRC = (
        "interface Port-channel1\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan 10,20\n"
        "interface GigabitEthernet0/0/1\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 99\n"
        " switchport trunk allowed vlan 10,20,30\n"
        " channel-group 1 mode active\n"
    )

    def test_member_has_no_l2_commands(self):
        result = c2h(self.SRC)
        assert block(result, "interface GigabitEthernet0/0/1") == ["interface GigabitEthernet0/0/1", " eth-trunk 1"]
        assert block(result, "interface Eth-Trunk1") == [
            "interface Eth-Trunk1", " mode lacp-static", " port link-type trunk", " port trunk allow-pass vlan 10 20"]

    def test_same_value_as_trunk_is_not_needed(self):
        result = c2h(self.SRC)
        line5 = [l for l in result.lines if l.source_line == 5]
        assert line5 and line5[0].provenance is Provenance.NOT_NEEDED
        assert REASON_MEMBER_L2_REDUNDANT in line5[0].text

    def test_different_or_unknown_value_is_locked_unconverted(self):
        reasons = _reasons(c2h(self.SRC))
        assert reasons[6] == REASON_MEMBER_L2_ON_TRUNK  # native vlan / pvid
        assert reasons[7] == REASON_MEMBER_L2_ON_TRUNK  # allowed list differs from the Eth-Trunk
        assert not auto_ai_eligible(reasons[6]) and not auto_ai_eligible(reasons[7])

    def test_hybrid_sends_no_member_l2_line(self):
        result = convert(self.SRC, C, H, HYBRID, translator=NoAI())
        assert has_cmd(result, "eth-trunk 1")

    def test_member_order_independent(self):
        src = "interface GigabitEthernet0/0/2\n channel-group 2 mode on\n switchport mode trunk\n"
        result = c2h(src)
        assert block(result, "interface GigabitEthernet0/0/2") == ["interface GigabitEthernet0/0/2", " eth-trunk 2"]
        assert _reasons(result)[3] == REASON_MEMBER_L2_ON_TRUNK

    def test_ai_member_l2_lines_are_commented(self):
        fake = WholeFile(["system-view", "interface Eth-Trunk1", " mode lacp-static", " port link-type trunk", "quit",
                          "interface GigabitEthernet0/0/1", " eth-trunk 1", " port link-type trunk",
                          " port trunk pvid vlan 99", "quit", "return"])
        result = convert(self.SRC, C, H, AI_ONLY, translator=fake)
        member = block(result, "interface GigabitEthernet0/0/1")
        assert member == ["interface GigabitEthernet0/0/1", " eth-trunk 1"]
        assert has_cmd(result, "port link-type trunk")  # still on the Eth-Trunk itself
        assert len([l for l in result.lines if l.is_comment and WHY_MEMBER_L2 in l.text]) == 2
        plan = _deploy(result)
        assert "port trunk pvid vlan 99" not in plan

    def test_unit_non_member_interface_untouched(self):
        lines = [RenderedLine(text=t, provenance=AI) for t in ("interface GigabitEthernet0/0/5", " port link-type trunk")]
        out = guard_eth_trunk_members(lines)
        assert not out[1].is_comment

    def test_line_status_kinds(self):
        from app.core.engine import sanitize_and_parse

        _, parsed = sanitize_and_parse(self.SRC, C, H)
        assert parsed.line_status[5].kind is LineKind.NOT_NEEDED
        assert parsed.line_status[8].kind is LineKind.RULE


# =========================================================================== AI prompt (defence in depth)


def test_ai_prompt_states_new_huawei_constraints():
    from app.services.ai_translator import _system_prompt

    prompt = _system_prompt(C, H)
    assert "' undo portswitch', and it MUST be the FIRST command" in prompt
    assert "NEVER repeat 'router-id' or 'ospf router-id' inside the OSPF view" in prompt
    assert "NEVER put 'port link-type', 'port trunk pvid'" in prompt
