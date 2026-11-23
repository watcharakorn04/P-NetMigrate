"""AI / Hybrid translation engine (proposal §2.3.1 item 1.2, CLAUDE.md §2 and §4).

The LLM is never called for real: `httpx.MockTransport` plays the OpenAI-compatible
Chat Completions endpoint and records every request body, so the tests can assert that
no secret ever leaves the machine (Security Non-Negotiable #1 — never weaken these).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.config import Settings
from app.core.engine import (
    NOTICE_AI_FAILED,
    NOTICE_AI_REVIEW,
    NOTICE_AI_UNAVAILABLE,
    NOTICE_HYBRID_NOTHING_TO_SEND,
    NOTICE_NO_SELECTION,
    convert,
    convert_selected,
)
from app.core.ir import ConversionMode, Provenance, Vendor
from app.services.ai_translator import AIError, AIItem, AITranslator

FIXTURES = Path(__file__).parent / "fixtures"
C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP
HYBRID, RULE_ONLY, AI_ONLY = ConversionMode.HYBRID, ConversionMode.RULE_ONLY, ConversionMode.AI_ONLY
API_KEY = "sk-test-NeverLeakThisKey"

CISCO_SECRETS = ["$9$CiscoEnableHashXyZ", "PlainEnablePw1", "netadmin", "$9$UserHashAbC123", "OspfMd5Key77",
                 "BgpNeighPw99", "PubCommRO", "PrivCommRW", "TacacsKey55", "RadiusKey66", "VtyLinePw42",
                 "ConsoleSecret8"]
HUAWEI_SECRETS = ["SuperCipherQwE", "huaadmin", "$1a$LocalUserHashZz$", "OspfHuaKey33", "HuaBgpPw88",
                  "HuaPubComm", "HuaVtyPw21"]

# Line 2: no rule (eligible). Line 5: interface child, no rule (eligible, block incomplete).
# Line 6: "not supported" OSPF timers, line 7: out of scope, line 8: intentionally not converted.
MIXED = (
    "hostname R1\n"                                              # 1
    "ip http server\n"                                           # 2
    "interface GigabitEthernet0/0/1\n"                           # 3
    " ip address 10.0.0.1 255.255.255.0\n"                       # 4
    " speed 100\n"                                               # 5
    " ip ospf hello-interval 5\n"                                # 6
    "ipv6 unicast-routing\n"                                     # 7
    "ip route 10.9.0.0 255.255.0.0 10.0.0.2 name BACKUP\n"       # 8
)


class FakeLLM:
    """Records requests; answers with `reply(payload) -> dict | httpx.Response`."""

    def __init__(self, reply):
        self.reply = reply
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        out = self.reply(self.user_payload(request))
        if isinstance(out, httpx.Response):
            return out
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(out)}}]})

    @staticmethod
    def user_payload(request: httpx.Request):
        body = json.loads(request.content)
        user = body["messages"][-1]["content"]
        if '"items"' in user:
            return json.loads(user[user.index("{\"source_vendor\""):])
        return user

    @property
    def sent(self) -> str:
        """Everything that left the machine, as text."""
        return "\n".join(r.content.decode("utf-8") for r in self.requests)

    def translator(self) -> AITranslator:
        return AITranslator(api_key=API_KEY, client=httpx.Client(transport=httpx.MockTransport(self)))


def echo_items(prefix: str = "AI-"):
    """Answer every item with one line per source line: '<prefix><stripped source>'."""

    def reply(payload):
        return {
            "translations": [
                {"id": item["id"], "lines": [(" " if l[:1].isspace() else "") + prefix + l.strip() for l in item["lines"]]}
                for item in payload["items"]
            ]
        }

    return reply


def ai_cmds(result) -> list[str]:
    return [l.text for l in result.lines if l.provenance is Provenance.AI and not l.is_comment]


# ----------------------------------------------------------------------------- security gate


class TestNoSecretReachesAI:
    """Non-Negotiable #1: strip_secrets runs before any request is assembled. Never weaken."""

    @pytest.mark.parametrize("mode", [HYBRID, AI_ONLY])
    @pytest.mark.parametrize(
        "fixture, vendor, secrets",
        [("cisco_with_secrets.txt", C, CISCO_SECRETS), ("huawei_with_secrets.txt", H, HUAWEI_SECRETS)],
    )
    def test_request_body_holds_zero_secrets(self, mode, fixture, vendor, secrets):
        text = (FIXTURES / fixture).read_text(encoding="utf-8") + "\nip http server\nsnmp-agent sys-info version v3\n"
        llm = FakeLLM(echo_items() if mode is HYBRID else (lambda p: {"lines": ["hostname X"]}))
        result = convert(text, vendor, H if vendor is C else C, mode=mode, translator=llm.translator())
        assert llm.requests, "AI was expected to be called"
        for secret in secrets:
            assert secret not in llm.sent, secret
        assert API_KEY not in llm.sent  # key travels only in the Authorization header
        assert llm.requests[0].headers["Authorization"] == f"Bearer {API_KEY}"
        everything = result.text + result.annotated_text + "\n".join(result.warnings + result.notices)
        for secret in secrets:
            assert secret not in everything, secret

    def test_selected_lines_never_include_credentials_even_if_picked(self):
        text = (FIXTURES / "cisco_with_secrets.txt").read_text(encoding="utf-8") + "ip http server\n"
        llm = FakeLLM(echo_items())
        lines = list(range(1, len(text.splitlines()) + 1))  # user ticks EVERYTHING
        convert_selected(text, C, H, lines, llm.translator())
        for secret in CISCO_SECRETS:
            assert secret not in llm.sent, secret

    def test_client_strips_secrets_even_if_caller_forgets(self):
        llm = FakeLLM(lambda p: {"lines": ["sysname R1"]})
        llm.translator().translate_config("hostname R1\nenable secret 9 $9$Leak\nusername bob secret x\n", C, H)
        assert "$9$Leak" not in llm.sent and "bob" not in llm.sent
        llm2 = FakeLLM(echo_items())
        llm2.translator().translate_items([AIItem(id=1, lines=["enable password Leak2", "ip http server"])], C, H)
        assert "Leak2" not in llm2.sent and "ip http server" in llm2.sent

    def test_secret_in_ai_answer_never_reaches_output(self):
        llm = FakeLLM(lambda p: {"translations": [{"id": 2, "lines": ["local-user admin password cipher Hallucinated1"]}]})
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        assert "Hallucinated1" not in result.text + result.annotated_text
        assert any(l.provenance is Provenance.SYSTEM and "ข้อมูลลับ" in l.text for l in result.lines)


# ----------------------------------------------------------------------------- hybrid


class TestHybrid:
    def test_sends_only_eligible_unconverted_lines(self):
        llm = FakeLLM(echo_items())
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        assert len(llm.requests) == 1  # batched: one call per conversion
        payload = FakeLLM.user_payload(llm.requests[0])
        sent = [l.strip() for item in payload["items"] for l in item["lines"]]
        assert sent == ["ip http server", "speed 100"]
        # converted / not-supported / out-of-scope / intentional lines are NOT sent
        for never in ("hostname", "ip address", "hello-interval", "ipv6", "BACKUP"):
            assert never not in llm.sent
        assert result.ai_sent_line_numbers == [2, 5]
        assert result.effective_mode is HYBRID

    def test_child_lines_carry_parent_context(self):
        llm = FakeLLM(echo_items())
        convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        items = {i["id"]: i for i in FakeLLM.user_payload(llm.requests[0])["items"]}
        assert items[5]["parent_source"] == "interface GigabitEthernet0/0/1"
        assert items[5]["parent_target"] == "interface GigabitEthernet0/0/1"
        assert "parent_source" not in items[2]

    def test_merges_rule_and_ai_lines_with_correct_labels(self):
        llm = FakeLLM(echo_items())
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        by_text = {l.text: l for l in result.lines}
        assert by_text["sysname R1"].provenance is Provenance.RULE
        assert by_text["AI-ip http server"].provenance is Provenance.AI_REVIEW
        assert by_text[" AI-speed 100"].provenance is Provenance.AI
        # AI sub-command stays inside its interface block, after the rule-converted address
        texts = [l.text for l in result.lines]
        assert texts.index("interface GigabitEthernet0/0/1") < texts.index(" ip address 10.0.0.1 255.255.255.0") \
            < texts.index(" AI-speed 100")
        # translated lines lose their "แปลงไม่ได้" comment; ineligible ones keep it
        unconverted = [l.text for l in result.lines if l.provenance is Provenance.UNCONVERTED]
        assert not any("speed 100" in t or "ip http server" in t for t in unconverted)
        assert any("hello-interval" in t for t in unconverted)
        assert any("ipv6 unicast-routing" in t for t in unconverted)
        assert any("BACKUP" in t for t in unconverted)
        assert [i.line_no for i in result.unconverted_items] == [6, 7, 8]
        assert NOTICE_AI_REVIEW in result.notices
        assert result.ai_line_count == 2

    def test_ai_lines_are_marked_review_required_in_plain_text(self):
        llm = FakeLLM(echo_items())
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        marks = [l for l in result.lines if l.provenance is Provenance.AI and l.is_comment]
        assert marks and all(l.text.startswith("# [มาจาก AI ต้องตรวจสอบก่อนใช้]") for l in marks)
        assert not any(l.provenance.deployable for l in result.lines if l.provenance is Provenance.AI)

    def test_repeated_parent_header_is_dropped_and_children_indented(self):
        llm = FakeLLM(lambda p: {"translations": [
            {"id": 5, "lines": ["interface GigabitEthernet0/0/1", "speed 100"]}]})
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        assert ai_cmds(result) == [" speed 100"]
        assert sum(1 for l in result.lines if l.text == "interface GigabitEthernet0/0/1") == 1

    def test_unanswered_items_stay_unconverted(self):
        llm = FakeLLM(lambda p: {"translations": [{"id": 2, "lines": ["http server enable"]}]})
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        assert ai_cmds(result) == ["http server enable"]
        assert 5 in [i.line_no for i in result.unconverted_items]

    def test_fully_converted_file_makes_no_ai_call(self):
        llm = FakeLLM(echo_items())
        result = convert("hostname R1\n", C, H, mode=HYBRID, translator=llm.translator())
        assert llm.requests == []
        assert NOTICE_HYBRID_NOTHING_TO_SEND in result.notices
        assert result.effective_mode is HYBRID

    def test_complex_command_block_goes_to_ai_even_if_rules_converted_it(self):
        text = "hostname R1\nrouter bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n"
        llm = FakeLLM(lambda p: {"translations": [{"id": 2, "lines": [
            "bgp 65001", " peer 10.0.0.2 as-number 65002", " ipv4-family unicast", "  peer 10.0.0.2 enable"]}]})
        result = convert(text, C, H, mode=HYBRID, translator=llm.translator(), complex_commands=["router bgp"])
        assert "neighbor 10.0.0.2 remote-as 65002" in llm.sent
        assert "hostname" not in llm.sent
        assert "bgp 65001" in ai_cmds(result)
        rule_bgp = [l for l in result.lines if l.provenance in (Provenance.RULE, Provenance.SYSTEM) and "65001" in l.text]
        assert rule_bgp == []

    def test_huawei_to_cisco(self):
        text = "sysname R2\nlldp enable\n"
        llm = FakeLLM(lambda p: {"translations": [{"id": 2, "lines": ["lldp run"]}]})
        result = convert(text, H, C, mode=HYBRID, translator=llm.translator())
        assert "lldp enable" in llm.sent
        line = next(l for l in result.lines if l.text == "lldp run")
        assert line.provenance is Provenance.AI
        assert any(l.is_comment and l.text.startswith("! [มาจาก AI") for l in result.lines)


# ----------------------------------------------------------------------------- ai_only


class TestAiOnly:
    def test_whole_sanitized_config_goes_to_ai_and_every_line_is_ai(self):
        llm = FakeLLM(lambda p: {"lines": ["sysname R1", "interface GigabitEthernet0/0/1", " ip address 10.0.0.1 255.255.255.0"]})
        result = convert(MIXED, C, H, mode=AI_ONLY, translator=llm.translator())
        assert "ipv6 unicast-routing" in llm.sent and "hostname R1" in llm.sent  # everything (sanitized)
        assert result.effective_mode is AI_ONLY
        assert all(l.provenance is Provenance.AI for l in result.lines)
        assert ai_cmds(result) == ["sysname R1", "interface GigabitEthernet0/0/1", " ip address 10.0.0.1 255.255.255.0"]
        assert result.unconverted_items == []
        assert NOTICE_AI_REVIEW in result.notices

    def test_secret_advisories_are_kept(self):
        text = (FIXTURES / "cisco_with_secrets.txt").read_text(encoding="utf-8")
        llm = FakeLLM(lambda p: {"lines": ["sysname R1-CORE"]})
        result = convert(text, C, H, mode=AI_ONLY, translator=llm.translator())
        advisories = [l for l in result.lines if l.provenance is Provenance.SYSTEM]
        assert len(advisories) == result.secret_stripped_count > 0
        assert all(l.text.startswith("#") for l in advisories)

    def test_code_fenced_json_is_accepted(self):
        fenced = httpx.Response(200, json={"choices": [{"message": {"content": '```json\n{"lines": ["sysname R1"]}\n```'}}]})
        llm = FakeLLM(lambda p: fenced)
        result = convert("hostname R1\n", C, H, mode=AI_ONLY, translator=llm.translator())
        assert ai_cmds(result) == ["sysname R1"]


# ----------------------------------------------------------------------------- rule_only + manual selection


class TestSelectiveAi:
    def test_rule_only_never_calls_ai(self):
        llm = FakeLLM(echo_items())
        result = convert(MIXED, C, H, mode=RULE_ONLY, translator=llm.translator())
        assert llm.requests == []
        assert result.effective_mode is RULE_ONLY
        assert [i.line_no for i in result.unconverted_items] == [2, 5, 6, 7, 8]

    def test_only_selected_lines_are_sent(self):
        llm = FakeLLM(echo_items())
        result = convert_selected(MIXED, C, H, [8], llm.translator())
        payload = FakeLLM.user_payload(llm.requests[0])
        assert [l for i in payload["items"] for l in i["lines"]] == ["ip route 10.9.0.0 255.255.0.0 10.0.0.2 name BACKUP"]
        assert "ip http server" not in llm.sent
        assert ai_cmds(result) == ["AI-ip route 10.9.0.0 255.255.0.0 10.0.0.2 name BACKUP"]
        assert [i.line_no for i in result.unconverted_items] == [2, 5, 6, 7]
        assert result.ai_sent_line_numbers == [8]
        assert result.effective_mode is RULE_ONLY

    def test_user_may_send_lines_hybrid_would_not(self):
        llm = FakeLLM(echo_items())
        convert_selected(MIXED, C, H, [6, 7], llm.translator())
        assert "hello-interval" in llm.sent and "ipv6 unicast-routing" in llm.sent

    def test_selecting_converted_lines_sends_nothing(self):
        llm = FakeLLM(echo_items())
        result = convert_selected(MIXED, C, H, [1, 4], llm.translator())
        assert llm.requests == []
        assert NOTICE_NO_SELECTION in result.notices

    def test_without_translator_returns_rule_result_with_notice(self):
        result = convert_selected(MIXED, C, H, [2], None)
        assert NOTICE_AI_UNAVAILABLE in result.notices
        assert 2 in [i.line_no for i in result.unconverted_items]


# ----------------------------------------------------------------------------- graceful fallback


def _boom(request):
    raise httpx.ConnectError("no route to host")


class TestGracefulFallback:
    @pytest.mark.parametrize(
        "reply",
        [
            lambda p: httpx.Response(500, json={"error": "server"}),
            lambda p: httpx.Response(429, json={"error": "rate limited"}),
            lambda p: httpx.Response(200, json={"choices": [{"message": {"content": "not json at all"}}]}),
            lambda p: httpx.Response(200, json={"unexpected": True}),
            lambda p: {"translations": "oops"},
            lambda p: {"translations": [{"id": 2, "lines": "not a list"}]},
        ],
        ids=["http500", "http429", "non-json", "no-choices", "bad-shape", "bad-lines"],
    )
    def test_hybrid_falls_back_to_rule_output(self, reply):
        llm = FakeLLM(reply)
        result = convert(MIXED, C, H, mode=HYBRID, translator=llm.translator())
        rule_only = convert(MIXED, C, H, mode=RULE_ONLY)
        assert [l.text for l in result.lines] == [l.text for l in rule_only.lines]
        assert result.effective_mode is RULE_ONLY
        assert NOTICE_AI_FAILED in result.notices
        assert [i.line_no for i in result.unconverted_items] == [2, 5, 6, 7, 8]

    def test_network_error_does_not_crash(self):
        translator = AITranslator(api_key=API_KEY, client=httpx.Client(transport=httpx.MockTransport(_boom)))
        result = convert(MIXED, C, H, mode=HYBRID, translator=translator)
        assert NOTICE_AI_FAILED in result.notices
        result = convert(MIXED, C, H, mode=AI_ONLY, translator=translator)
        assert NOTICE_AI_FAILED in result.notices
        assert any(l.text == "sysname R1" and l.provenance is Provenance.RULE for l in result.lines)
        result = convert_selected(MIXED, C, H, [2], translator)
        assert NOTICE_AI_FAILED in result.notices

    def test_ai_only_empty_answer_falls_back(self):
        llm = FakeLLM(lambda p: {"lines": []})
        result = convert(MIXED, C, H, mode=AI_ONLY, translator=llm.translator())
        assert NOTICE_AI_FAILED in result.notices
        assert result.effective_mode is RULE_ONLY

    @pytest.mark.parametrize("mode", [HYBRID, AI_ONLY])
    def test_no_translator_means_rule_only_and_notice(self, mode):
        result = convert(MIXED, C, H, mode=mode)
        assert result.effective_mode is RULE_ONLY
        assert NOTICE_AI_UNAVAILABLE in result.notices

    def test_errors_raise_aierror_from_client(self):
        llm = FakeLLM(lambda p: httpx.Response(503))
        with pytest.raises(AIError):
            llm.translator().translate_config("hostname R1\n", C, H)


class TestSettings:
    def test_defaults(self):
        s = Settings(_env_file=None)
        assert s.llm_api_base_url == "https://api.openai.com/v1"
        assert s.llm_model == "gpt-4o-mini"

    def test_from_settings_without_key_is_none(self):
        assert AITranslator.from_settings(Settings(llm_api_key="  ", _env_file=None)) is None

    def test_from_settings_with_key(self):
        t = AITranslator.from_settings(
            Settings(llm_api_key=API_KEY, llm_api_base_url="https://llm.example/v1/", llm_model="m1", _env_file=None)
        )
        assert t is not None and t.model == "m1" and t.base_url == "https://llm.example/v1"

    def test_request_targets_configured_endpoint_and_model(self):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"lines": ["sysname R1"]}'}}]})

        t = AITranslator(api_key=API_KEY, base_url="https://llm.example/v1", model="m1",
                         client=httpx.Client(transport=httpx.MockTransport(handler)))
        t.translate_config("hostname R1\n", C, H)
        assert str(seen[0].url) == "https://llm.example/v1/chat/completions"
        assert json.loads(seen[0].content)["model"] == "m1"
