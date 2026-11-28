"""AI client transport tests: native Gemini REST vs OpenAI-compatible, error diagnostics,
and the fallback reason shown in the conversion notice banner.

All HTTP traffic goes to httpx.MockTransport; no real LLM endpoint is ever called.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from app.config import Settings
from app.core.engine import (
    AI_FAILURE_LABELS,
    NOTICE_AI_FAILED,
    NOTICE_AI_FAILED_REASON_PREFIX,
    convert,
    convert_selected,
)
from app.core.ir import ConversionMode, Provenance, Vendor
from app.i18n import translate_message
from app.services.ai_translator import (
    GEMINI_API_ROOT,
    AIError,
    AIItem,
    AITranslator,
    _system_prompt,
    gemini_thinking_config,
    is_gemini_endpoint,
)

C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP
HYBRID, RULE_ONLY, AI_ONLY = ConversionMode.HYBRID, ConversionMode.RULE_ONLY, ConversionMode.AI_ONLY
GEMINI_KEY = "AIzaSyTEST-NeverLeakThisGeminiKey000"
AQ_KEY = "AQ.TestKeyNeverLeak1234567890abcdef"
OPENAI_KEY = "sk-test-NeverLeakThisKey"
AI_STUDIO_COMPAT = "https://generativelanguage.googleapis.com/v1beta/openai/"
MIXED = "hostname R1\nip http server\n"  # line 2 has no rule -> hybrid sends it


def gemini_reply(obj: dict, **extra) -> httpx.Response:
    return httpx.Response(200, json={"candidates": [{"content": {"role": "model", "parts": [
        {"text": json.dumps(obj)}]}, "finishReason": "STOP", **extra}]})


class Recorder:
    def __init__(self, reply):
        self.reply = reply
        self.requests: list[httpx.Request] = []
        self.sleeps: list[float] = []  # retry backoff delays; recorded, never actually slept

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        out = self.reply(request)
        if isinstance(out, Exception):
            raise out
        return out

    def translator(self, key=GEMINI_KEY, base_url=AI_STUDIO_COMPAT, model="gemini-2.5-flash") -> AITranslator:
        return AITranslator(api_key=key, base_url=base_url, model=model,
                            client=httpx.Client(transport=httpx.MockTransport(self)),
                            sleep=self.sleeps.append)


# ----------------------------------------------------------------------------- endpoint selection


class TestEndpointSelection:
    @pytest.mark.parametrize(
        "base_url,model,expected",
        [
            (AI_STUDIO_COMPAT, "gemini-2.5-flash", True),
            ("https://generativelanguage.googleapis.com/v1beta", "some-model", True),
            ("https://api.openai.com/v1", "gemini-2.5-pro", True),
            ("https://api.openai.com/v1", "models/gemini-2.5-pro", True),
            ("https://api.openai.com/v1", "gpt-4o-mini", False),
            ("https://openrouter.ai/api/v1", "google/gemini-2.5-flash", False),
            ("http://localhost:11434/v1", "llama3", False),
        ],
    )
    def test_detection(self, base_url, model, expected):
        assert is_gemini_endpoint(base_url, model) is expected

    def test_from_settings_with_ai_studio_uses_gemini(self):
        t = AITranslator.from_settings(Settings(llm_api_key=AQ_KEY, llm_api_base_url=AI_STUDIO_COMPAT,
                                                llm_model="gemini-2.5-flash", _env_file=None))
        assert t is not None and t.use_gemini and t.provider == "gemini"


# ----------------------------------------------------------------------------- system prompt constraints


class TestSystemPromptConstraints:
    def test_huawei_target_has_extra_constraints(self):
        prompt = _system_prompt(C, H)
        assert "very first output line must be 'system-view'" in prompt
        assert "'undo ip domain lookup'" in prompt and "Never invent hybrid" in prompt
        assert "'no ip domain-lookup' is not needed" in prompt and "ไม่ต้องใช้คำสั่งนี้" in prompt
        assert "'line console 0'" in prompt and "'line vty" in prompt
        assert "'authentication-mode password'" in prompt and "'login local'" in prompt
        assert ("configure the mode only, without adding any secret value" in prompt
                and "never the password itself" not in prompt)

    def test_huawei_interface_range_becomes_port_group(self):
        prompt = _system_prompt(C, H)
        assert "'interface range <type><start> - <end>'" in prompt
        assert "'port-group group-member <type><start> to <type><end>'" in prompt
        assert "'0/2' stays '0/2'" in prompt
        assert "never turn a 2-part number into a 3-part one" in prompt

    def test_huawei_trunk_without_allowed_list_gets_advisory_only(self):
        prompt = _system_prompt(C, H)
        assert "'switchport mode trunk'" in prompt and "'port link-type trunk'" in prompt
        assert "'# แนะนำ: port trunk allow-pass vlan all'" in prompt
        assert "Never emit 'port trunk allow-pass vlan all' as an active command" in prompt
        assert "never guess VLAN numbers" in prompt

    def test_huawei_logging_synchronous_is_not_idle_timeout(self):
        prompt = _system_prompt(C, H)
        assert "Never translate 'logging synchronous' into 'undo idle-timeout'" in prompt
        assert "Return no command for 'logging synchronous'" in prompt
        assert "does not interrupt typed CLI input by default" in prompt

    def test_huawei_stp_mapping_is_strict(self):
        prompt = _system_prompt(C, H)
        assert "'spanning-tree portfast' (with or without 'edge') strictly to 'stp edged-port enable'" in prompt
        assert "'spanning-tree bpduguard enable' strictly to 'stp bpdu-protection'" not in prompt
        assert "Emit 'stp bpdu-protection' ONLY at global system-view level" in prompt
        assert "never invent non-existent ones such as 'stp sock-type'" in prompt

    def test_cisco_target_has_no_huawei_constraints(self):
        prompt = _system_prompt(H, C)
        assert "authentication-mode password" not in prompt
        assert "undo ip domain lookup" not in prompt
        assert "very first output line" not in prompt
        assert "port-group group-member" not in prompt
        assert "allow-pass vlan all" not in prompt
        assert "undo idle-timeout" not in prompt
        assert "stp edged-port enable" not in prompt
        assert "stp sock-type" not in prompt

    @pytest.mark.parametrize("call", ["config", "items"])
    def test_constraints_reach_the_request(self, call):
        rec = Recorder(lambda r: gemini_reply({"lines": ["system-view"], "translations": []}))
        t = rec.translator()
        if call == "config":
            t.translate_config("no ip domain-lookup\n", C, H)
        else:
            t.translate_items([AIItem(id=1, lines=["no ip domain-lookup"])], C, H)
        system = json.loads(rec.requests[0].content)["systemInstruction"]["parts"][0]["text"]
        assert "'system-view'" in system and "authentication-mode password" in system
        assert "undo ip domain lookup" in system
        assert "port-group group-member" in system
        assert "# แนะนำ: port trunk allow-pass vlan all" in system
        assert "'logging synchronous'" in system


# ----------------------------------------------------------------------------- native Gemini payload


class TestGeminiNative:
    @pytest.mark.parametrize("key", [GEMINI_KEY, AQ_KEY])
    def test_url_header_and_payload(self, key):
        rec = Recorder(lambda r: gemini_reply({"lines": ["sysname R1"]}))
        assert rec.translator(key=key).translate_config("hostname R1\n", C, H) == ["sysname R1"]
        req = rec.requests[0]
        assert str(req.url) == f"{GEMINI_API_ROOT}/models/gemini-2.5-flash:generateContent"
        assert str(req.url).startswith("https://generativelanguage.googleapis.com/v1beta/models/")
        assert req.headers["x-goog-api-key"] == key
        assert "authorization" not in req.headers
        assert key not in str(req.url)  # never in the query string
        body = json.loads(req.content)
        assert body["generationConfig"]["responseMimeType"] == "application/json"
        assert body["generationConfig"]["temperature"] == 0
        assert body["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}
        assert "Huawei" in body["systemInstruction"]["parts"][0]["text"]
        assert body["contents"][0]["role"] == "user"
        assert "hostname R1" in body["contents"][0]["parts"][0]["text"]
        assert "messages" not in body and "model" not in body

    @pytest.mark.parametrize("model,expected", [
        ("gemini-3.5-flash-lite", {"thinkingLevel": "low"}),
        ("gemini-3-pro-preview", {"thinkingLevel": "low"}),
        ("models/gemini-3.5-flash", {"thinkingLevel": "low"}),
        ("gemini-2.5-flash", {"thinkingBudget": 0}),
        ("gemini-2.5-flash-lite", {"thinkingBudget": 0}),
        ("gemini-2.5-pro", None),
        ("gemini-2.0-flash", None),
        ("gemini-1.5-flash", None),
        ("some-model", None),
    ])
    def test_thinking_config_per_model(self, model, expected):
        assert gemini_thinking_config(model) == expected

    def test_ai_only_payload_schema_for_gemini_3_large_config(self):
        """ai_only sends the whole file: the body must contain only valid generateContent fields,
        and Gemini 3.x must never get the legacy thinkingBudget."""
        config = "\n".join(
            [f"interface GigabitEthernet0/0/{i}\n description port {i}\n shutdown" for i in range(12)]
        )  # ~36 lines
        rec = Recorder(lambda r: gemini_reply({"lines": ["system-view"]}))
        result = convert(config, C, H, mode=AI_ONLY, translator=rec.translator(model="gemini-3.5-flash-lite"))
        assert result.effective_mode is AI_ONLY and NOTICE_AI_FAILED not in result.notices
        assert len(rec.requests) == 1
        req = rec.requests[0]
        assert str(req.url) == f"{GEMINI_API_ROOT}/models/gemini-3.5-flash-lite:generateContent"
        body = json.loads(req.content)
        assert set(body) == {"systemInstruction", "contents", "generationConfig"}
        assert set(body["systemInstruction"]) == {"parts"}  # no "role" inside systemInstruction
        assert body["contents"] == [{"role": "user", "parts": [{"text": body["contents"][0]["parts"][0]["text"]}]}]
        assert "GigabitEthernet0/0/11" in body["contents"][0]["parts"][0]["text"]
        cfg = body["generationConfig"]
        assert set(cfg) <= {"temperature", "responseMimeType", "thinkingConfig"}
        assert cfg["responseMimeType"] == "application/json"
        assert cfg["thinkingConfig"] == {"thinkingLevel": "low"}
        assert "thinkingBudget" not in cfg["thinkingConfig"]
        assert "responseSchema" not in cfg and "safetySettings" not in body

    def test_invalid_argument_retries_once_with_minimal_body(self):
        replies = iter([google_error(400, "INVALID_ARGUMENT", "Request contains an invalid argument."),
                        gemini_reply({"lines": ["sysname R1"]})])
        rec = Recorder(lambda r: next(replies))
        t = rec.translator(model="gemini-3.5-flash-lite")
        assert t.translate_config("hostname R1\n", C, H) == ["sysname R1"]
        assert len(rec.requests) == 2 and t.last_error is None
        retry = json.loads(rec.requests[1].content)
        assert retry["generationConfig"] == {"responseMimeType": "application/json"}
        assert retry["systemInstruction"] == json.loads(rec.requests[0].content)["systemInstruction"]

    def test_invalid_argument_twice_still_fails_as_bad_request(self):
        rec = Recorder(lambda r: google_error(400, "INVALID_ARGUMENT", "Request contains an invalid argument."))
        with pytest.raises(AIError) as info:
            rec.translator().translate_config("hostname R1\n", C, H)
        assert info.value.reason == "bad_request" and len(rec.requests) == 2

    def test_auth_400_is_not_retried(self):
        rec = Recorder(lambda r: google_error(400, "INVALID_ARGUMENT", "API key not valid."))
        with pytest.raises(AIError):
            rec.translator().translate_config("hostname R1\n", C, H)
        assert len(rec.requests) == 1

    def test_models_prefix_is_not_doubled(self):
        rec = Recorder(lambda r: gemini_reply({"lines": ["sysname R1"]}))
        rec.translator(model="models/gemini-2.5-pro").translate_config("hostname R1\n", C, H)
        assert str(rec.requests[0].url).endswith("/v1beta/models/gemini-2.5-pro:generateContent")

    def test_thought_parts_are_ignored_and_text_parts_joined(self):
        resp = httpx.Response(200, json={"candidates": [{"content": {"parts": [
            {"text": "thinking about it...", "thought": True},
            {"text": '{"lines": ['}, {"text": '"sysname R1"]}'},
        ]}}]})
        rec = Recorder(lambda r: resp)
        assert rec.translator().translate_config("hostname R1\n", C, H) == ["sysname R1"]

    def test_hybrid_end_to_end_labels_ai_lines(self):
        def reply(request):
            user = json.loads(request.content)["contents"][0]["parts"][0]["text"]
            items = json.loads(user[user.index('{"source_vendor"'):])["items"]
            return gemini_reply({"translations": [{"id": i["id"], "lines": ["http server enable"]} for i in items]})

        rec = Recorder(reply)
        result = convert(MIXED, C, H, mode=HYBRID, translator=rec.translator())
        assert result.effective_mode is HYBRID
        assert any(l.text == "http server enable" and l.provenance is Provenance.AI for l in result.lines)
        assert NOTICE_AI_FAILED not in result.notices

    def test_secrets_never_sent_to_gemini(self):
        rec = Recorder(lambda r: gemini_reply({"lines": ["sysname R1"]}))
        rec.translator().translate_config("hostname R1\nenable secret 0 PlainEnablePw1\n", C, H)
        assert "PlainEnablePw1" not in rec.requests[0].content.decode()

    @pytest.mark.parametrize(
        "payload,needle",
        [
            ({"promptFeedback": {"blockReason": "SAFETY"}}, "blockReason=SAFETY"),
            ({"candidates": [{"finishReason": "MAX_TOKENS", "content": {"parts": []}}]}, "finishReason=MAX_TOKENS"),
            ({"candidates": [{"content": {"parts": [{"text": "not json"}]}}]}, "not valid JSON"),
        ],
    )
    def test_unusable_gemini_answers_are_bad_answer(self, payload, needle):
        rec = Recorder(lambda r: httpx.Response(200, json=payload))
        with pytest.raises(AIError) as info:
            rec.translator().translate_config("hostname R1\n", C, H)
        assert info.value.reason == "bad_answer"
        assert needle in info.value.detail


class TestOpenAICompatibleUnchanged:
    def test_other_providers_still_use_chat_completions(self):
        rec = Recorder(lambda r: httpx.Response(
            200, json={"choices": [{"message": {"content": '{"lines": ["sysname R1"]}'}}]}))
        t = rec.translator(key=OPENAI_KEY, base_url="https://api.openai.com/v1", model="gpt-4o-mini")
        assert not t.use_gemini
        assert t.translate_config("hostname R1\n", C, H) == ["sysname R1"]
        req = rec.requests[0]
        assert str(req.url) == "https://api.openai.com/v1/chat/completions"
        assert req.headers["authorization"] == f"Bearer {OPENAI_KEY}"
        assert "x-goog-api-key" not in req.headers
        body = json.loads(req.content)
        assert body["model"] == "gpt-4o-mini" and body["response_format"] == {"type": "json_object"}


# ----------------------------------------------------------------------------- error classification


def google_error(status: int, code: str, message: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"code": status, "message": message, "status": code}})


ERROR_CASES = [
    (lambda r: google_error(400, "INVALID_ARGUMENT", "API key not valid. Please pass a valid API key."),
     "auth", 400, "API key not valid"),
    (lambda r: google_error(403, "PERMISSION_DENIED", "Permission denied"), "auth", 403, "PERMISSION_DENIED"),
    (lambda r: google_error(404, "NOT_FOUND", "models/gemini-9 is not found for API version v1beta"),
     "model", 404, "models/gemini-9 is not found"),
    (lambda r: google_error(429, "RESOURCE_EXHAUSTED", "Quota exceeded"), "rate_limit", 429, "Quota exceeded"),
    (lambda r: google_error(503, "UNAVAILABLE", "The model is overloaded"), "server", 503, "overloaded"),
    (lambda r: google_error(400, "INVALID_ARGUMENT", "Invalid JSON payload"), "bad_request", 400, "Invalid JSON"),
    (lambda r: httpx.ReadTimeout("timed out"), "timeout", None, "ReadTimeout"),
    (lambda r: httpx.ConnectError("no route to host"), "network", None, "ConnectError"),
]


class TestErrorDiagnostics:
    @pytest.mark.parametrize("reply,reason,status,needle", ERROR_CASES)
    def test_reason_status_and_detail(self, reply, reason, status, needle):
        t = Recorder(reply).translator()
        with pytest.raises(AIError) as info:
            t.translate_config("hostname R1\n", C, H)
        assert (info.value.reason, info.value.status) == (reason, status)
        assert needle in info.value.detail
        assert t.last_error is not None and t.last_error.startswith(reason + ": ")

    def test_openai_style_list_wrapped_error_is_parsed(self):
        resp = httpx.Response(404, json=[{"error": {"code": 404, "message": "model xyz does not exist",
                                                    "status": "NOT_FOUND"}}])
        t = Recorder(lambda r: resp).translator(base_url="https://llm.example/v1", model="xyz", key=OPENAI_KEY)
        with pytest.raises(AIError) as info:
            t.translate_config("hostname R1\n", C, H)
        assert info.value.reason == "model" and "does not exist" in info.value.detail

    def test_failure_is_logged_without_the_api_key(self, caplog):
        # Even a provider that echoes the key back must not get it into logs / notices.
        resp = google_error(400, "INVALID_ARGUMENT", f"API key not valid: {GEMINI_KEY}")
        t = Recorder(lambda r: resp).translator()
        with caplog.at_level(logging.WARNING, logger="app.services.ai_translator"):
            result = convert(MIXED, C, H, mode=HYBRID, translator=t)
        assert "status=400" in caplog.text and "reason=auth" in caplog.text
        assert "API key not valid" in caplog.text
        assert GEMINI_KEY not in caplog.text
        assert all(GEMINI_KEY not in n for n in result.notices)
        assert GEMINI_KEY not in (t.last_error or "")

    def test_http_400_logs_full_error_message_and_details(self, caplog):
        long_msg = "Request contains an invalid argument. " + "x" * 400 + " END-OF-MESSAGE"
        resp = httpx.Response(400, json={"error": {
            "code": 400, "status": "INVALID_ARGUMENT", "message": long_msg,
            "details": [{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [
                {"field": "contents[0].parts[0]", "description": "Unsupported content"}]}],
        }})
        t = Recorder(lambda r: resp).translator()
        with caplog.at_level(logging.WARNING, logger="app.services.ai_translator"):
            with pytest.raises(AIError) as info:
                t.translate_config("hostname R1\n", C, H)
        assert info.value.reason == "bad_request" and info.value.status == 400
        assert "END-OF-MESSAGE" in caplog.text  # not truncated in the log
        assert "contents[0].parts[0] Unsupported content" in caplog.text
        assert len(t.last_error or "") < 300  # notice text stays short

    def test_success_clears_last_error(self):
        replies = iter([google_error(404, "NOT_FOUND", "models/gemini-9 is not found"),
                        gemini_reply({"lines": ["sysname R1"]})])
        t = Recorder(lambda r: next(replies)).translator()
        with pytest.raises(AIError):
            t.translate_config("hostname R1\n", C, H)
        assert t.last_error
        t.translate_config("hostname R1\n", C, H)
        assert t.last_error is None


# ----------------------------------------------------------------------------- transient retry


class TestTransientRetry:
    def test_503_retries_then_succeeds(self):
        replies = iter([google_error(503, "UNAVAILABLE", "The model is overloaded"),
                        gemini_reply({"lines": ["sysname R1"]})])
        rec = Recorder(lambda r: next(replies))
        t = rec.translator()
        assert t.translate_config("hostname R1\n", C, H) == ["sysname R1"]
        assert len(rec.requests) == 2
        assert rec.sleeps == [2.0]
        assert t.last_error is None

    def test_hybrid_uses_ai_after_transient_503(self):
        replies = iter([google_error(503, "UNAVAILABLE", "high demand"),
                        google_error(503, "UNAVAILABLE", "high demand")])

        def reply(request):
            try:
                return next(replies)
            except StopIteration:
                return gemini_reply({"translations": [{"id": 2, "lines": ["http server enable"]}]})

        rec = Recorder(reply)
        result = convert(MIXED, C, H, mode=HYBRID, translator=rec.translator())
        assert result.effective_mode is HYBRID
        assert NOTICE_AI_FAILED not in result.notices
        assert any(l.text == "http server enable" and l.provenance is Provenance.AI for l in result.lines)
        assert rec.sleeps == [2.0, 4.0]

    @pytest.mark.parametrize("status,code", [(503, "UNAVAILABLE"), (429, "RESOURCE_EXHAUSTED")])
    def test_gives_up_after_three_retries(self, status, code):
        rec = Recorder(lambda r: google_error(status, code, "still busy"))
        with pytest.raises(AIError) as info:
            rec.translator().translate_config("hostname R1\n", C, H)
        assert info.value.status == status
        assert len(rec.requests) == 4  # 1 attempt + 3 retries
        assert rec.sleeps == [2.0, 4.0, 6.0]

    @pytest.mark.parametrize("reply", [
        lambda r: google_error(400, "INVALID_ARGUMENT", "API key not valid"),
        lambda r: google_error(404, "NOT_FOUND", "model not found"),
        lambda r: google_error(500, "INTERNAL", "boom"),
    ])
    def test_non_transient_errors_are_not_retried(self, reply):
        rec = Recorder(reply)
        with pytest.raises(AIError):
            rec.translator().translate_config("hostname R1\n", C, H)
        assert len(rec.requests) == 1 and rec.sleeps == []


# ----------------------------------------------------------------------------- fallback banner


def reason_notice(result) -> str:
    found = [n for n in result.notices if n.startswith(NOTICE_AI_FAILED_REASON_PREFIX)]
    assert len(found) == 1, result.notices
    return found[0]


class TestFallbackReasonInBanner:
    @pytest.mark.parametrize("reply,reason,status,needle", ERROR_CASES)
    def test_hybrid_fallback_shows_reason(self, reply, reason, status, needle):
        t = Recorder(reply).translator()
        result = convert(MIXED, C, H, mode=HYBRID, translator=t)
        rule_only = convert(MIXED, C, H, mode=RULE_ONLY)
        assert [l.text for l in result.lines] == [l.text for l in rule_only.lines]
        assert result.effective_mode is RULE_ONLY
        assert NOTICE_AI_FAILED in result.notices
        notice = reason_notice(result)
        assert AI_FAILURE_LABELS[reason] in notice
        assert needle in notice

    def test_ai_only_and_selected_also_show_reason(self):
        t = Recorder(lambda r: google_error(404, "NOT_FOUND", "models/gemini-9 is not found")).translator()
        for result in (convert(MIXED, C, H, mode=AI_ONLY, translator=t), convert_selected(MIXED, C, H, [2], t)):
            assert NOTICE_AI_FAILED in result.notices
            assert AI_FAILURE_LABELS["model"] in reason_notice(result)

    def test_reason_notice_is_translated_to_english(self):
        t = Recorder(lambda r: google_error(429, "RESOURCE_EXHAUSTED", "Quota exceeded")).translator()
        notice = reason_notice(convert(MIXED, C, H, mode=HYBRID, translator=t))
        en = translate_message(notice, "en")
        assert en.startswith("AI failure reason: quota exceeded or too many requests (rate limit) — ")
        assert "HTTP 429" in en and "Quota exceeded" in en
        assert translate_message(notice, "th") == notice

    def test_api_convert_returns_reason_notice(self):
        from fastapi.testclient import TestClient

        from app.deps import get_translator
        from app.main import app

        t = Recorder(lambda r: google_error(401, "UNAUTHENTICATED", "Request had invalid credentials")).translator()
        app.dependency_overrides[get_translator] = lambda: t
        try:
            client = TestClient(app)
            r = client.post("/api/convert", data={"direction": "c2h", "mode": "hybrid", "config": MIXED,
                                                  "lang": "en"})
        finally:
            app.dependency_overrides.pop(get_translator, None)
        assert r.status_code == 200, r.text
        notices = r.json()["notices"]
        assert any(n.startswith("AI failure reason: invalid API key") and "HTTP 401" in n for n in notices)
