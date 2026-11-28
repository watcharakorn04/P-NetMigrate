"""Regression tests from the Hybrid-mode output verification (Cisco -> Huawei).

1. No duplicate `system-view` / `return`: the AI prompt limits `system-view` to full-file
   (AI-only) translation, and partial AI answers (hybrid / user-selected) merged into a
   rule result that already enters system view / closes with `return` are stripped of them.
2. `logging synchronous` -> "ไม่ต้องใช้คำสั่งนี้" (VRP does not interrupt typed CLI input),
   at top level, inside `line vty` and inside unclaimed blocks such as `line con 0`.
3. Bare `enable` and `service password-encryption` -> "ไม่ต้องใช้คำสั่งนี้".

None of these lines may ever be sent to AI in hybrid mode.
"""

from __future__ import annotations

import pytest

from app.core.engine import convert, convert_selected
from app.core.ir import ConversionMode, Provenance
from app.core.parsers import parse_config
from app.core.rules import tier1_system
from app.core.rules.tier1_system import REASON_LOGGING_SYNCHRONOUS
from app.services.ai_translator import AIItem, _system_prompt
from app.services.deploy_service import build_plan
from tests.helpers import C, H, block_result, c2h, cmd, commands, comments_with, has_cmd

HYBRID, AI_ONLY = ConversionMode.HYBRID, ConversionMode.AI_ONLY


def _index(result, text: str) -> int:
    for i, line in enumerate(result.lines):
        if not line.is_comment and line.text.strip() == text:
            return i
    raise AssertionError(f"{text!r} not found:\n{result.annotated_text}")


def _deploy(result) -> list[str]:
    lines = [{"text": l.text, "provenance": l.provenance.name, "is_comment": l.is_comment} for l in result.lines]
    return build_plan(lines, result.target_vendor).commands


class FakeAI:
    """Partial-job translator: answers every item with the same fixed lines."""

    def __init__(self, answer: list[str]):
        self.answer = answer
        self.sent: list[str] = []

    def translate_items(self, items: list[AIItem], source, target):
        self.sent += [l.strip() for i in items for l in i.lines]
        return {i.id: list(self.answer) for i in items}

    def translate_config(self, text, source, target):  # pragma: no cover
        raise AssertionError("partial jobs only")


# ----------------------------------------------------------------------------- 1. system-view


class TestNoDuplicateSystemView:
    SRC = "configure terminal\nhostname SW1\nspanning-tree mode rapid-pvst\nend\n"

    def test_prompt_limits_system_view_to_full_file(self):
        prompt = _system_prompt(C, H)
        assert "Only when translating a complete configuration file (AI-only mode)" in prompt
        assert "partial or selected blocks/items" in prompt
        assert "MUST NOT emit 'system-view' or 'return'" in prompt
        assert "MUST NOT emit" not in _system_prompt(H, C)

    @pytest.mark.parametrize(
        "answer",
        [
            ["system-view", "stp mode rstp", "return"],
            ["sys", "stp mode rstp", "Return"],
        ],
    )
    def test_hybrid_strips_ai_system_view_and_return(self, answer):
        result = convert(self.SRC, C, H, HYBRID, translator=FakeAI(answer))
        out = commands(result)
        assert out[0] == "system-view"
        assert sum(1 for c in out if c in ("system-view", "sys")) == 1
        assert [c.lower() for c in out].count("return") == 1 and out[-1] == "return"
        ai = cmd(result, "stp mode rstp")
        assert ai.provenance is Provenance.AI
        assert _index(result, "sysname SW1") < result.lines.index(ai) < _index(result, "return")

    def test_selected_lines_are_stripped_too(self):
        result = convert_selected(self.SRC, C, H, [3], FakeAI(["system-view", "stp mode rstp", "return"]))
        out = commands(result)
        assert out.count("system-view") == 1 and out.count("return") == 1 and out[-1] == "return"
        assert has_cmd(result, "stp mode rstp")

    def test_answer_left_empty_keeps_unconverted_label(self):
        result = convert(self.SRC, C, H, HYBRID, translator=FakeAI(["system-view", "return"]))
        note = comments_with(result, "spanning-tree mode rapid-pvst")[0]
        assert note.provenance is Provenance.UNCONVERTED
        assert [i.line_no for i in result.unconverted_items] == [3]
        assert not any(l.provenance is Provenance.AI for l in result.lines)

    def test_return_stripped_even_without_system_view_in_source(self):
        result = convert("hostname SW1\nspanning-tree mode rapid-pvst\n", C, H, HYBRID,
                         translator=FakeAI(["stp mode rstp", "return"]))
        out = commands(result)
        assert out.count("return") == 1 and out[-1] == "return"

    def test_ai_only_full_file_keeps_its_system_view(self):
        class Full:
            def translate_config(self, text, source, target):
                return ["system-view", "sysname SW1", "return"]

        result = convert(self.SRC, C, H, AI_ONLY, translator=Full())
        assert commands(result) == ["system-view", "sysname SW1", "return"]

    def test_cisco_target_is_not_filtered(self):
        src = "system-view\nsysname R1\nstp mode rstp\nreturn\n"
        result = convert(src, H, C, HYBRID, translator=FakeAI(["spanning-tree mode rapid-pvst"]))
        assert has_cmd(result, "spanning-tree mode rapid-pvst")


# ----------------------------------------------------------------------------- 2. logging synchronous


class TestLoggingSynchronousNotNeeded:
    @staticmethod
    def _assert_not_needed(result, text="logging synchronous"):
        note = comments_with(result, text)[0]
        assert note.provenance is Provenance.NOT_NEEDED and REASON_LOGGING_SYNCHRONOUS in note.text
        assert text not in [i.command.strip() for i in result.unconverted_items]

    def test_reason_explains_huawei_default(self):
        assert "console/VTY" in REASON_LOGGING_SYNCHRONOUS

    def test_inside_vty(self):
        result = c2h("line vty 0 4\n login local\n logging synchronous\n")
        self._assert_not_needed(result)
        assert not result.unconverted_items
        assert parse_config("line vty 0 4\n login local\n logging synchronous\n", C).blocks[0].complete

    def test_inside_unclaimed_console_block(self):
        result = c2h("line con 0\n logging synchronous\n")
        self._assert_not_needed(result)
        assert [i.command.strip() for i in result.unconverted_items] == ["line con 0"]

    def test_with_arguments(self):
        self._assert_not_needed(c2h("line vty 0 4\n logging synchronous level all\n"), "logging synchronous level all")

    def test_top_level(self):
        result = c2h("logging synchronous\n")
        self._assert_not_needed(result)
        assert not result.unconverted_items

    def test_never_mapped_to_idle_timeout(self):
        assert "idle-timeout" not in c2h("line con 0\n logging synchronous\n").text

    def test_hybrid_never_sends_it_to_ai(self):
        fake = FakeAI(["user-interface console 0"])
        src = "line con 0\n logging synchronous\nline vty 0 4\n login local\n logging synchronous\n"
        result = convert(src, C, H, HYBRID, translator=fake)
        assert fake.sent == ["line con 0"]
        assert result.ai_sent_line_numbers == [1]
        self._assert_not_needed(result)

    def test_not_deployed(self):
        cmds = _deploy(c2h("line vty 0 4\n login local\n logging synchronous\n"))
        assert not any("logging" in c for c in cmds)

    def test_cisco_vty_block_marked_complete(self):
        assert block_result(c2h("line vty 0 4\n login local\n logging synchronous\n"), "line vty 0 4").complete


# ----------------------------------------------------------------------------- 3. enable / service password-encryption


class TestEnableAndPasswordEncryptionNotNeeded:
    @pytest.mark.parametrize(
        "text, reason",
        [("enable", "REASON_ENABLE"), ("service password-encryption", "REASON_SERVICE_PASSWORD_ENCRYPTION")],
    )
    def test_not_needed_with_reason(self, text, reason):
        result = c2h(f"{text}\nhostname R1\n")
        note = comments_with(result, text)[0]
        assert note.provenance is Provenance.NOT_NEEDED and getattr(tier1_system, reason) in note.text
        assert not result.unconverted_items
        assert parse_config(f"{text}\n", C).blocks[0].complete
        assert _deploy(result) == ["sysname R1"]

    def test_reasons_explain_huawei_behaviour(self):
        assert "user privilege level" in tier1_system.REASON_ENABLE
        assert "cipher" in tier1_system.REASON_SERVICE_PASSWORD_ENCRYPTION

    def test_hybrid_never_sends_them_to_ai(self):
        fake = FakeAI(["x"])
        result = convert("enable\nservice password-encryption\nhostname R1\n", C, H, HYBRID, translator=fake)
        assert fake.sent == [] and result.ai_sent_line_numbers == []

    @pytest.mark.parametrize("text, secret", [("enable secret 9 $9$abcHash", "abcHash"),
                                              ("enable password PlainPw1", "PlainPw1")])
    def test_enable_credentials_still_stripped(self, text, secret):
        result = c2h(f"{text}\n")
        assert result.secret_stripped_count == 1
        assert not any(l.provenance is Provenance.NOT_NEEDED for l in result.lines)
        assert secret not in result.annotated_text

    def test_enable_with_other_arguments_not_claimed(self):
        result = c2h("enable view\n")
        assert [i.command.strip() for i in result.unconverted_items] == ["enable view"]
