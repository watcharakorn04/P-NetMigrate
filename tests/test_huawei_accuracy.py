"""Regression tests for the Huawei VRP CLI-validation fixes.

1. `configure terminal` <-> `system-view` first; hybrid AI output merged in source order.
2. `exit` <-> `quit` (one view level), `end` <-> `return`; AI prompt says so explicitly.
3. `interface range` <-> `port-group group-member` — port numbers kept verbatim (§2.3.2 item 4).
4. Trunk without an allowed-VLAN list: `port trunk allow-pass vlan all` as a SYSTEM
   *comment advisory* only (§2.3.2 item 5: the BGP block is the only auto-filled command).
5. `line vty 0 15` -> `user-interface vty 0 4` + note; `no ip domain-lookup` not needed;
   `write memory` / `copy run start` -> `save force` + warning.
"""

from __future__ import annotations

from app.core.engine import convert
from app.core.hardware import classify_ports
from app.core.ir import ConversionMode, Provenance, Vendor
from app.core.parsers import parse_config
from app.core.rules.tier1_interface import REASON_BAD_RANGE
from app.core.rules.tier1_system import REASON_DOMAIN_LOOKUP
from app.services.ai_translator import AIItem, _system_prompt
from app.services.deploy_service import build_plan
from tests.helpers import C, H, block_result, c2h, cmd, commands, comments_with, h2c, has_cmd


def _index(result, text: str) -> int:
    for i, line in enumerate(result.lines):
        if not line.is_comment and line.text.strip() == text:
            return i
    raise AssertionError(f"{text!r} not found:\n{result.annotated_text}")


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return build_plan(lines, result.target_vendor).commands


# ----------------------------------------------------------------------------- 1. system-view + ordering


class TestSystemView:
    SRC = "hostname SW1\nvlan 10\n name USERS\ninterface Vlan10\n ip address 10.0.0.1 255.255.255.0\nconfigure terminal\n"

    def test_configure_terminal_maps_to_system_view(self):
        result = c2h("configure terminal\nhostname SW1\n")
        line = cmd(result, "system-view")
        assert line.provenance is Provenance.RULE and line.source_line == 1
        assert block_result(result, "configure terminal").complete

    def test_system_view_is_first_command_even_if_written_late(self):
        out = commands(c2h(self.SRC))
        assert out[0] == "system-view"
        assert out.index("system-view") < out.index("sysname SW1") < out.index("vlan 10") < out.index("interface Vlanif10")

    def test_abbreviations(self):
        for text in ("conf t", "config t", "configure term"):
            assert commands(c2h(f"{text}\nhostname R1\n"))[0] == "system-view", text
        for text in ("sys", "system", "system-view"):
            assert commands(h2c(f"{text}\nsysname R1\n"))[0] == "configure terminal", text

    def test_no_system_view_when_source_has_none(self):
        assert not has_cmd(c2h("hostname R1\n"), "system-view")

    def test_huawei_to_cisco(self):
        assert commands(h2c("system-view\nsysname R1\nreturn\n"))[:2] == ["configure terminal", "hostname R1"]

    def test_mode_entry_never_deployed(self):
        assert "system-view" not in _deploy(c2h("configure terminal\nhostname SW1\n"))
        assert "sysname SW1" in _deploy(c2h("configure terminal\nhostname SW1\n"))


class TestSourceOrder:
    # line 3 (no rule) sits between the hostname (1-2) and the interface (4-5) in the source.
    SRC = "configure terminal\nhostname SW1\nspanning-tree mode mst\ninterface Vlan10\n ip address 10.0.0.1 255.255.255.0\nend\n"

    def test_unconverted_top_level_line_stays_in_source_position(self):
        result = c2h(self.SRC)
        note = comments_with(result, "spanning-tree mode mst")[0]
        pos = result.lines.index(note)
        assert _index(result, "sysname SW1") < pos < _index(result, "interface Vlanif10")

    def test_hybrid_ai_lines_merge_in_source_order_not_appended(self):
        class Fake:
            def translate_items(self, items: list[AIItem], source, target):
                return {i.id: ["stp mode mstp"] for i in items}

            def translate_config(self, text, source, target):  # pragma: no cover
                raise AssertionError

        result = convert(self.SRC, C, H, ConversionMode.HYBRID, translator=Fake())
        ai = cmd(result, "stp mode mstp")
        assert ai.provenance is Provenance.AI and ai.source_line == 3
        pos = result.lines.index(ai)
        assert _index(result, "system-view") < _index(result, "sysname SW1") < pos < _index(result, "interface Vlanif10")
        assert commands(result)[-1] == "return"

    def test_notes_before_first_section_go_after_leading_comments(self):
        result = c2h("enable\nconfigure terminal\nhostname R1\n")
        note = comments_with(result, "enable")[0]
        assert result.lines.index(note) < _index(result, "system-view")


# ----------------------------------------------------------------------------- 2. exit / quit, end / return


class TestExitQuit:
    def test_indented_exit_maps_to_quit(self):
        result = c2h("interface GigabitEthernet0/0/1\n description up\n exit\n")
        assert commands(result) == ["interface GigabitEthernet0/0/1", " description up", "quit", "return"]
        assert cmd(result, "quit").provenance is Provenance.RULE
        assert block_result(result, "interface").complete

    def test_unindented_exit_closes_the_block_above(self):
        result = c2h("vlan 10\n name USERS\nexit\nline vty 0 4\n login local\nexit\n")
        out = commands(result)
        assert out.count("quit") == 2
        assert out.index("quit") == out.index(" description USERS") + 1
        assert not result.unconverted_items

    def test_exit_is_never_return(self):
        out = commands(c2h("interface GigabitEthernet0/0/1\n shutdown\nexit\nend\n"))
        assert out.count("return") == 1 and out[-1] == "return"
        assert "quit" in out

    def test_end_maps_to_return(self):
        assert commands(c2h("hostname R1\nend\n"))[-1] == "return"
        assert commands(h2c("sysname R1\nreturn\n"))[-1] == "end"

    def test_top_level_exit_without_view_is_not_needed(self):
        result = c2h("hostname R1\nexit\n")
        assert comments_with(result, "exit")[0].provenance is Provenance.NOT_NEEDED
        assert not has_cmd(result, "quit")

    def test_nested_huawei_views_get_one_quit_per_level(self):
        ospf = commands(c2h("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\nexit\n"))
        assert ospf[ospf.index("  network 10.0.0.0 0.0.0.255") + 1 :][:2] == [" quit", "quit"]
        bgp = commands(c2h("router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\nexit\n"))
        assert bgp[bgp.index("  peer 10.0.0.2 enable") + 1 :][:2] == [" quit", "quit"]

    def test_named_acl_exit_keeps_acl_converted(self):
        result = c2h("ip access-list standard MGMT\n permit 10.0.0.0 0.0.0.255\nexit\n")
        assert has_cmd(result, "acl name MGMT basic") and has_cmd(result, "rule 5 permit source 10.0.0.0 0.0.0.255")
        assert "quit" in commands(result)

    def test_huawei_quit_maps_to_exit(self):
        result = h2c("interface GigabitEthernet0/0/1\n undo shutdown\nquit\nospf 1\n area 0.0.0.0\n  network 10.0.0.0 0.0.0.255\n  quit\n quit\n")
        out = commands(result)
        assert out.count("exit") == 2
        assert not result.unconverted_items

    def test_exit_quit_round_trip_keeps_ir(self):
        src = "interface GigabitEthernet0/0/1\n description up\n exit\nvlan 20\n name V20\nexit\n"
        a = c2h(src)
        b = h2c(a.text)
        assert a.ir.intent() == b.ir.intent()
        assert commands(b).count("exit") == 2


class TestAiPrompt:
    def test_huawei_prompt_says_exit_is_quit_never_return(self):
        prompt = _system_prompt(C, H)
        assert "'exit' becomes 'quit'" in prompt and "never translate 'exit' as 'return'" in prompt
        assert "'configure terminal' becomes 'system-view'" in prompt and "'end' becomes 'return'" in prompt

    def test_cisco_prompt_mirrors_it(self):
        prompt = _system_prompt(H, C)
        assert "'quit' becomes 'exit'" in prompt and "'return' becomes 'end'" in prompt

    def test_prompt_keeps_port_numbers_and_order(self):
        prompt = _system_prompt(C, H)
        assert "slot/port number exactly as in the source" in prompt
        assert "same order as the source lines" in prompt


# ----------------------------------------------------------------------------- 3. interface range <-> port-group


class TestPortRange:
    def test_interface_range_maps_to_port_group_numbers_verbatim(self):
        result = c2h("interface range GigabitEthernet0/1 - 4\n switchport mode access\n switchport access vlan 10\n")
        line = cmd(result, "port-group group-member GigabitEthernet0/1 to GigabitEthernet0/4")
        assert line.provenance is Provenance.RULE
        assert has_cmd(result, "port link-type access") and has_cmd(result, "port default vlan 10")
        assert block_result(result, "interface range").complete

    def test_fastethernet_and_three_part_numbers(self):
        assert has_cmd(c2h("interface range fa0/1-8\n shutdown\n"), "port-group group-member Ethernet0/1 to Ethernet0/8")
        assert has_cmd(
            c2h("interface range GigabitEthernet1/0/1 - 24\n shutdown\n"),
            "port-group group-member GigabitEthernet1/0/1 to GigabitEthernet1/0/24",
        )

    def test_port_numbers_are_never_renumbered(self):
        out = c2h("interface GigabitEthernet0/1\n shutdown\n").text
        assert "interface GigabitEthernet0/1\n" in out and "0/0/1" not in out

    def test_huawei_port_group_back_to_cisco_range(self):
        result = h2c("port-group group-member GigabitEthernet0/0/1 to GigabitEthernet0/0/4\n port link-type trunk\n port trunk allow-pass vlan 10 20\n")
        assert has_cmd(result, "interface range GigabitEthernet0/0/1 - 4")
        assert has_cmd(result, "switchport trunk allowed vlan 10,20")

    def test_round_trip_ir(self):
        a = c2h("interface range GigabitEthernet0/1 - 4\n switchport mode access\n")
        b = h2c(a.text)
        assert a.ir.intent() == b.ir.intent()
        assert a.ir.interfaces[0].range_end == "0/4"

    def test_invalid_ranges_stay_unconverted(self):
        for src in ("interface range GigabitEthernet0/4 - 1\n", "interface range Vlan10 - 20\n"):
            result = c2h(src + " shutdown\n")
            assert result.unconverted_items and result.unconverted_items[0].reason == REASON_BAD_RANGE, src
        mixed = c2h("port-group group-member GigabitEthernet0/0/1 to Ethernet0/0/4\n")  # wrong direction
        assert mixed.unconverted_items
        h_mixed = h2c("port-group group-member GigabitEthernet0/0/1 to Ethernet0/0/4\n shutdown\n")
        assert h_mixed.unconverted_items[0].reason == REASON_BAD_RANGE

    def test_comma_list_left_for_ai(self):
        result = c2h("interface range Gi0/1 - 2 , Gi0/5 - 6\n shutdown\n")
        assert result.unconverted_items and result.unconverted_items[0].reason != REASON_BAD_RANGE

    def test_hardware_counts_every_member_port(self):
        ports = classify_ports("interface range GigabitEthernet0/1 - 4\n no shutdown\n", C)
        assert [p["number"] for p in ports] == ["0/1", "0/2", "0/3", "0/4"]
        assert all(p["state"] == "active" for p in ports)


# ----------------------------------------------------------------------------- 4. trunk default VLANs


class TestTrunkAllowAll:
    SRC = "interface GigabitEthernet0/0/24\n switchport mode trunk\n"

    def test_advisory_comment_right_after_link_type(self):
        result = c2h(self.SRC)
        i = _index(result, "port link-type trunk")
        advisory = result.lines[i + 1]
        assert advisory.is_comment and advisory.provenance is Provenance.SYSTEM
        assert "port trunk allow-pass vlan all" in advisory.text and advisory.text.startswith("#")

    def test_never_emitted_as_command_or_deployed(self):
        result = c2h(self.SRC)
        assert not has_cmd(result, "port trunk allow-pass vlan all")
        assert not any("allow-pass" in c for c in _deploy(result))
        assert cmd(result, "port link-type trunk").warning  # existing "ไม่เดาค่าให้" warning kept

    def test_no_advisory_with_explicit_list_or_access_port(self):
        explicit = c2h(self.SRC + " switchport trunk allowed vlan 10,20\n")
        assert has_cmd(explicit, "port trunk allow-pass vlan 10 20")
        assert not comments_with(explicit, "allow-pass vlan all")
        assert not comments_with(c2h("interface GigabitEthernet0/0/2\n switchport mode access\n"), "allow-pass")

    def test_huawei_allow_all_still_intentionally_unconverted(self):
        result = h2c("interface GigabitEthernet0/0/1\n port link-type trunk\n port trunk allow-pass vlan all\n")
        assert comments_with(result, "allow-pass vlan all")[0].provenance is Provenance.UNCONVERTED


# ----------------------------------------------------------------------------- 5. VTY, domain-lookup, save


class TestHuaweiPractical:
    def test_vty_0_15_becomes_0_4_with_note(self):
        result = c2h("line vty 0 15\n login local\n transport input ssh\n")
        line = cmd(result, "user-interface vty 0 4")
        assert line.provenance is Provenance.RULE and "0–4" in line.warning
        assert not has_cmd(result, "user-interface vty 0 15")
        assert line.warning in result.warnings

    def test_vty_within_range_unchanged(self):
        line = cmd(c2h("line vty 0 4\n login local\n"), "user-interface vty 0 4")
        assert line.warning is None

    def test_vty_starting_above_4_kept_with_warning(self):
        assert cmd(c2h("line vty 5 15\n login local\n"), "user-interface vty 5 15").warning

    def test_no_ip_domain_lookup_not_needed(self):
        for text in ("no ip domain-lookup", "no ip domain lookup"):
            result = c2h(f"{text}\n")
            note = comments_with(result, text)[0]
            assert note.provenance is Provenance.NOT_NEEDED and REASON_DOMAIN_LOOKUP in note.text
            assert not result.unconverted_items
            assert parse_config(f"{text}\n", C).blocks[0].complete

    def test_write_memory_maps_to_save_force(self):
        for text in ("write memory", "write", "wr", "copy running-config startup-config", "copy run start"):
            result = c2h(f"hostname R1\nend\n{text}\n")
            out = commands(result)
            assert out[-2:] == ["return", "save force"], text
            assert "ถามยืนยัน" in cmd(result, "save force").warning

    def test_huawei_save_maps_to_write_memory(self):
        out = commands(h2c("sysname R1\nreturn\nsave\n"))
        assert out[-2:] == ["end", "write memory"]

    def test_save_never_deployed(self):
        cmds = _deploy(c2h("hostname R1\nend\nwrite memory\n"))
        assert "save force" not in cmds and cmds == ["sysname R1"]


def test_full_switch_script_has_no_unconverted_lines():
    src = (
        "configure terminal\n"
        "hostname SW1\n"
        "no ip domain-lookup\n"
        "vlan 10\n name USERS\nexit\n"
        "interface range GigabitEthernet0/1 - 4\n switchport mode access\n switchport access vlan 10\nexit\n"
        "interface GigabitEthernet0/24\n switchport mode trunk\nexit\n"
        "line vty 0 15\n login local\n transport input ssh\nexit\n"
        "end\n"
        "write memory\n"
    )
    result = c2h(src)
    assert not result.unconverted_items
    out = commands(result)
    assert out[0] == "system-view" and out[-2:] == ["return", "save force"]
    assert "port-group group-member GigabitEthernet0/1 to GigabitEthernet0/4" in out
    assert "user-interface vty 0 4" in out
    assert out.count("quit") == 4
