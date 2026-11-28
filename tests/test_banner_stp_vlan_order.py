"""Regression tests for the remaining Hybrid-verification fixes (after commit c9582be).

1. Banners: Cisco `banner login <d>..<d>` <-> Huawei `header login information <d>..<d>`,
   Cisco `banner motd <d>..<d>` <-> Huawei `header shell information <d>..<d>`
   (never `header banner ...`), single- and multi-line, both directions; AI prompt agrees.
2. Global `dhcp snooping enable` (and its `dhcp enable` advisory) always comes before any
   interface / port-group block containing `dhcp snooping trusted`, in every mode.
3. Global STP: `spanning-tree mode rapid-pvst` <-> `stp mode rstp`,
   `spanning-tree portfast default` <-> `stp edged-port default`; AI prompt agrees.
4. Every Huawei `vlan <id>` block ends with `quit`.
"""

from __future__ import annotations

import re

import pytest

from app.core.engine import convert, convert_selected
from app.core.ir import ConversionMode, Provenance, RenderedLine
from app.core.parsers import parse_config
from app.core.prescan import prescan_config
from app.core.renderers.common import (
    ADVISORY_DHCP_ENABLE,
    WARN_BANNER_DELIMITER,
    WARN_BANNER_MOTD_SHELL,
    WARN_STP_EDGE_DEFAULT,
    WARN_STP_RSTP,
)
from app.core.renderers.huawei_vrp import order_global_dhcp_snooping
from app.core.rules.base import REASON_BAD_VALUE
from app.i18n import translate_message
from app.services.ai_translator import AIItem, _system_prompt
from app.services.deploy_service import build_plan
from tests.helpers import C, H, c2h, cmd, commands, comments_with, h2c, has_cmd

HYBRID, AI_ONLY = ConversionMode.HYBRID, ConversionMode.AI_ONLY


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return build_plan(lines, result.target_vendor).commands


def _index(result, text: str) -> int:
    return next(i for i, l in enumerate(result.lines) if not l.is_comment and l.text.strip() == text)


# ----------------------------------------------------------------------------- 1. banners


class TestBanner:
    def test_single_line_login_and_motd_cisco_to_huawei(self):
        result = c2h("banner login %Authorized users only%\nbanner motd %Maintenance tonight%\n")
        login = cmd(result, "header login information %Authorized users only%")
        motd = cmd(result, "header shell information %Maintenance tonight%")
        assert login.provenance is motd.provenance is Provenance.RULE
        assert login.source_line == 1 and motd.source_line == 2
        assert not result.unconverted_items

    def test_never_header_banner(self):
        result = c2h("banner login #Hello#\nbanner motd ^C Hi ^C\n")
        assert not any("header banner" in l.text for l in result.lines)

    def test_caret_c_delimiter(self):
        result = c2h("banner motd ^C Authorized access only ^C\n")
        assert has_cmd(result, 'header shell information " Authorized access only"')

    def test_source_delimiter_kept_when_safe(self):
        assert has_cmd(c2h("banner login $Welcome$\n"), "header login information $Welcome$")

    def test_comment_marker_delimiter_replaced_with_warning(self):
        # `#` is the Huawei comment marker: a closing `#` line would read as a comment.
        result = c2h("banner login #Login here#\n")
        line = cmd(result, 'header login information "Login here"')
        assert WARN_BANNER_DELIMITER in line.warning

    def test_fallback_delimiter_skips_characters_in_the_text(self):
        # `#` is unsafe on Huawei and `"` appears in the text -> next safe choice `%`.
        line = cmd(c2h('banner login #Say "hi"#\n'), 'header login information %Say "hi"%')
        assert WARN_BANNER_DELIMITER in line.warning

    def test_motd_warns_about_display_timing(self):
        result = c2h("banner motd %Hi%\n")
        assert WARN_BANNER_MOTD_SHELL in result.warnings
        assert WARN_BANNER_MOTD_SHELL not in c2h("banner login %Hi%\n").warnings

    def test_multi_line_banner_keeps_comment_like_text(self):
        src = (
            "hostname SW1\n"
            "banner motd ^C\n"
            "!!! WARNING !!!\n"
            "  Unauthorized access is prohibited\n"
            "\n"
            "interface GigabitEthernet0/1\n"
            "^C\n"
            "interface GigabitEthernet0/2\n"
            " description UPLINK\n"
        )
        result = c2h(src)
        out = commands(result)
        start = out.index('header shell information "!!! WARNING !!!')
        assert out[start + 1:start + 4] == ["  Unauthorized access is prohibited", "", 'interface GigabitEthernet0/1"']
        # The text line that looks like an interface header is banner text, not a block.
        assert out.count("interface GigabitEthernet0/1") == 0
        assert has_cmd(result, "interface GigabitEthernet0/2")
        assert not result.unconverted_items
        for no in (2, 3, 4, 6, 7):
            assert parse_config(src, C).line_status[no].supported, no

    def test_unterminated_banner_does_not_swallow_the_file(self):
        src = "banner motd ^C\nNo closing delimiter\nhostname SW1\n"
        result = c2h(src)
        assert has_cmd(result, "sysname SW1")
        assert any(i.line_no == 1 and i.reason == REASON_BAD_VALUE for i in result.unconverted_items)
        assert not any(l.text.startswith("header") for l in result.lines if not l.is_comment)

    def test_trailing_exit_is_not_banner_text(self):
        result = c2h("banner motd ^C\nHello\n^C\nexit\n")
        assert has_cmd(result, 'header shell information "Hello"')

    def test_huawei_to_cisco(self):
        result = h2c('header login information "Authorized only"\nheader shell information "Line one\nLine two"\n')
        assert has_cmd(result, 'banner login "Authorized only"')
        out = commands(result)
        i = out.index('banner motd "Line one')
        assert out[i + 1] == 'Line two"'
        assert not result.unconverted_items

    def test_round_trip_intent(self):
        src = "banner login #Login here#\nbanner motd ^C\nLine one\n  Line two\n^C\n"
        first = parse_config(src, C).ir
        huawei = "\n".join(l.text for l in c2h(src).lines)
        again = parse_config(huawei, H).ir
        assert first.intent()["banners"] == again.intent()["banners"]
        assert [b.lines for b in first.banners] == [["Login here"], ["Line one", "  Line two"]]

    def test_banner_lines_are_deployed(self):
        result = c2h("banner login %Authorized only%\n")
        assert "header login information %Authorized only%" in _deploy(result)

    def test_hybrid_never_sends_banner_to_ai(self):
        class Fake:
            sent: list[str] = []

            def translate_items(self, items: list[AIItem], source, target):  # pragma: no cover
                Fake.sent += [l for i in items for l in i.lines]
                return {}

            def translate_config(self, text, source, target):  # pragma: no cover
                raise AssertionError

        convert("banner motd ^C\nHello\n^C\nbanner login %Hi%\n", C, H, HYBRID, translator=Fake())
        assert not Fake.sent

    def test_ai_prompt_states_banner_syntax(self):
        prompt = _system_prompt(C, H)
        assert "'banner login <d>text<d>' -> 'header login information <d>text<d>'" in prompt
        assert "'banner motd <d>text<d>' -> 'header shell information <d>text<d>'" in prompt
        assert "Never emit 'header banner ...'" in prompt


# ----------------------------------------------------------------------------- 2. DHCP snooping order


TRUSTED_FIRST = (
    "interface GigabitEthernet0/1\n"
    " ip dhcp snooping trust\n"
    "interface range GigabitEthernet0/2 - 3\n"
    " ip dhcp snooping trust\n"
    "ip dhcp snooping vlan 10\n"
    "ip dhcp snooping\n"
)


def _first_iface(result) -> int:
    return next(
        i for i, l in enumerate(result.lines)
        if not l.is_comment and re.match(r"^(interface|port-group)\b", l.text)
    )


class TestDhcpSnoopingOrder:
    def test_rule_output_puts_global_enable_before_trusted_ports(self):
        result = c2h(TRUSTED_FIRST)
        glob = _index(result, "dhcp snooping enable")
        advisory = result.lines.index(comments_with(result, ADVISORY_DHCP_ENABLE)[0])
        assert advisory < glob < _first_iface(result)
        assert result.lines[glob].text == "dhcp snooping enable"  # global, not the per-VLAN one

    def test_ai_only_output_is_reordered(self):
        answer = [
            "system-view",
            "interface GigabitEthernet0/1",
            " dhcp snooping trusted",
            "quit",
            "port-group group-member GigabitEthernet0/2 to GigabitEthernet0/3",
            " dhcp snooping trusted",
            "quit",
            "vlan 10",
            " dhcp snooping enable",
            "quit",
            "# dhcp enable is required first",
            "dhcp snooping enable",
            "return",
        ]

        class Fake:
            def translate_items(self, items, source, target):  # pragma: no cover
                raise AssertionError

            def translate_config(self, text, source, target):
                return list(answer)

        result = convert(TRUSTED_FIRST, C, H, AI_ONLY, translator=Fake())
        texts = [l.text for l in result.lines]
        glob = texts.index("dhcp snooping enable")
        assert texts[glob - 1] == "# dhcp enable is required first"
        assert glob < texts.index("interface GigabitEthernet0/1")
        assert texts.index("system-view") < glob
        # The per-VLAN enable stays inside its VLAN view.
        v = texts.index("vlan 10")
        assert texts[v + 1:v + 3] == [" dhcp snooping enable", "quit"]
        assert texts.count("dhcp snooping enable") == 1

    def test_unindented_per_vlan_enable_is_not_moved(self):
        lines = [
            RenderedLine(text=t, provenance=Provenance.AI)
            for t in ("interface GigabitEthernet0/1", " dhcp snooping trusted", "quit",
                      "vlan 10", "dhcp snooping enable", "quit")
        ]
        assert order_global_dhcp_snooping(lines) == lines

    def test_without_trusted_ports_nothing_moves(self):
        lines = [
            RenderedLine(text=t, provenance=Provenance.AI)
            for t in ("interface GigabitEthernet0/1", " port link-type access", "quit", "dhcp snooping enable")
        ]
        assert order_global_dhcp_snooping(lines) == lines

    def test_hybrid_ai_gap_fill_is_reordered(self):
        # A global line the rules do not know, answered by AI with `dhcp snooping enable`,
        # is placed in source order (after the interface) and must then be moved forward.
        src = "interface GigabitEthernet0/1\n ip dhcp snooping trust\nip dhcp snooping information option\n"

        class Fake:
            def translate_items(self, items, source, target):
                return {i.id: ["dhcp snooping enable"] for i in items}

            def translate_config(self, text, source, target):  # pragma: no cover
                raise AssertionError

        result = convert(src, C, H, HYBRID, translator=Fake())
        glob = _index(result, "dhcp snooping enable")
        assert glob < _first_iface(result)
        assert result.lines[glob].provenance is Provenance.AI

    def test_user_selected_send_is_reordered(self):
        src = "interface GigabitEthernet0/1\n ip dhcp snooping trust\nip dhcp snooping information option\n"

        class Fake:
            def translate_items(self, items, source, target):
                return {i.id: ["dhcp snooping enable"] for i in items}

        result = convert_selected(src, C, H, [3], Fake())
        assert _index(result, "dhcp snooping enable") < _first_iface(result)

    def test_ai_prompt_states_ordering(self):
        assert "BEFORE any 'interface' or 'port-group' block that contains 'dhcp snooping trusted'" in _system_prompt(C, H)


# ----------------------------------------------------------------------------- 3. global STP


class TestGlobalStp:
    SRC = "hostname SW1\nspanning-tree mode rapid-pvst\nspanning-tree portfast default\n"

    def test_cisco_to_huawei(self):
        result = c2h(self.SRC)
        mode = cmd(result, "stp mode rstp")
        edge = cmd(result, "stp edged-port default")
        assert mode.provenance is edge.provenance is Provenance.RULE
        assert mode.warning == WARN_STP_RSTP and edge.warning == WARN_STP_EDGE_DEFAULT
        assert mode.text == "stp mode rstp" and edge.text == "stp edged-port default"  # system view
        assert not result.unconverted_items
        assert {"stp mode rstp", "stp edged-port default"} <= set(_deploy(result))

    def test_portfast_edge_default_variant(self):
        assert has_cmd(c2h("spanning-tree portfast edge default\n"), "stp edged-port default")

    def test_huawei_to_cisco(self):
        result = h2c("sysname SW1\nstp mode rstp\nstp edged-port default\n")
        assert cmd(result, "spanning-tree mode rapid-pvst").provenance is Provenance.RULE
        assert cmd(result, "spanning-tree portfast default").provenance is Provenance.RULE

    def test_other_modes_stay_unconverted(self):
        result = c2h("spanning-tree mode mst\nspanning-tree mode pvst\n")
        assert {i.line_no for i in result.unconverted_items} == {1, 2}
        assert not has_cmd(result, "stp mode rstp")

    def test_round_trip_intent(self):
        first = parse_config(self.SRC, C).ir
        again = parse_config("\n".join(l.text for l in c2h(self.SRC).lines), H).ir
        assert (first.stp_mode, first.stp_edge_default) == ("rstp", True)
        assert first.intent() == again.intent()

    def test_hybrid_does_not_send_to_ai(self):
        class Fake:
            def translate_items(self, items, source, target):  # pragma: no cover
                raise AssertionError("rules cover every line")

            def translate_config(self, text, source, target):  # pragma: no cover
                raise AssertionError

        result = convert(self.SRC, C, H, HYBRID, translator=Fake())
        assert has_cmd(result, "stp mode rstp") and has_cmd(result, "stp edged-port default")

    def test_prescan_full_coverage(self):
        assert prescan_config(self.SRC, C, H).coverage_percent == 100

    def test_ai_prompt_states_stp_rules(self):
        prompt = _system_prompt(C, H)
        assert "'spanning-tree mode rapid-pvst' -> 'stp mode rstp'" in prompt
        assert "'spanning-tree portfast default' -> 'stp edged-port default'" in prompt


# ----------------------------------------------------------------------------- 4. VLAN quit


class TestVlanQuit:
    def test_every_vlan_block_ends_with_quit(self):
        src = "vlan 10\n name USERS\nvlan 20\n name SERVERS\nvlan 99\n name MGMT\n exit\n"
        out = commands(c2h(src))
        for vid, name in ((10, "USERS"), (20, "SERVERS"), (99, "MGMT")):
            i = out.index(f"vlan {vid}")
            assert out[i + 1:i + 3] == [f" description {name}", "quit"], vid
        assert out.count("quit") == 3  # the explicit `exit` of vlan 99 is not doubled

    def test_vlan_without_name(self):
        out = commands(c2h("vlan 30\nvlan 40\n"))
        assert out == ["vlan 30", "quit", "vlan 40", "quit", "return"]

    def test_quit_comes_after_unconverted_child_note(self):
        result = c2h("vlan 10\n name USERS\n state suspend\n")
        texts = [l.text for l in result.lines]
        note = next(i for i, t in enumerate(texts) if "state suspend" in t)
        assert texts[note + 1] == "quit"

    def test_quit_is_deployed_and_rule_labelled(self):
        result = c2h("vlan 10\nvlan 20\n")
        assert all(l.provenance is Provenance.RULE for l in result.lines if l.text == "quit")
        assert _deploy(result) == ["vlan 10", "quit", "vlan 20", "quit"]


# ----------------------------------------------------------------------------- i18n


@pytest.mark.parametrize(
    "message", [WARN_BANNER_DELIMITER, WARN_BANNER_MOTD_SHELL, WARN_STP_RSTP, WARN_STP_EDGE_DEFAULT]
)
def test_new_warnings_have_english(message):
    english = translate_message(message, "en")
    assert english != message and not re.search("[฀-๿]", english)
    assert translate_message(message, "th") == message
