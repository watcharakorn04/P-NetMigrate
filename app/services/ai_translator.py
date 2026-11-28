"""External LLM client over httpx.

Two transports, chosen automatically from the settings:
- OpenAI-compatible Chat Completions (`{base}/chat/completions`, `Authorization: Bearer`) for
  every provider except Google;
- the native Google Gemini REST API (`.../v1beta/models/{model}:generateContent`,
  `x-goog-api-key` header, `responseMimeType: application/json`) when the base URL points at
  Google AI Studio (`generativelanguage.googleapis.com`) or the model name starts with
  `gemini-`. AI Studio keys (`AIza...` / `AQ....`) work there.

Security Non-Negotiable #1 (CLAUDE.md §5): the conversion engine runs `strip_secrets()`
before it builds anything for this client. This client applies the SAME deterministic
filter again to every line just before the request body is serialised (defence in
depth), so even a caller bug cannot send a credential line out. Prompt instructions are
never relied on to hide secrets.

AI self-reported confidence is never requested or used (proposal §2.3.2 item 9). Every
line returned here is labelled "มาจาก AI ต้องตรวจสอบก่อนใช้" by the engine.

Transient HTTP 503 (UNAVAILABLE / high demand) and 429 (RESOURCE_EXHAUSTED) answers are retried
up to 3 times with 2 s / 4 s / 6 s backoff before they count as a failure.

Any failure (network, timeout, HTTP status, malformed JSON, wrong shape) raises `AIError`
carrying a `reason` category and a scrubbed `detail`; the engine catches it, falls back to
rule-only output and shows the reason — the service never stops. Failures are logged with
the HTTP status and provider message. The API key is never logged: it is not part of any
logged value and is redacted from any provider text that echoes it.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol, Sequence
from urllib.parse import quote

import httpx

from app.config import Settings
from app.core.ir import Vendor
from app.core.secret_stripper import contains_secret, strip_secrets

MAX_LINES_PER_ITEM = 60
MAX_OUTPUT_LINES = 5000
MAX_DETAIL_CHARS = 200
# HTTP 400 validation errors are logged in full (still scrubbed) so the exact API complaint is visible.
MAX_LOG_DETAIL_CHARS = 4000

GEMINI_HOST = "generativelanguage.googleapis.com"
GEMINI_API_ROOT = f"https://{GEMINI_HOST}/v1beta"

# Transient HTTP statuses retried with backoff before the request is treated as failed:
# 503 UNAVAILABLE (model overloaded / high demand) and 429 RESOURCE_EXHAUSTED (rate limit).
RETRY_STATUSES = frozenset({429, 503})
RETRY_DELAYS: tuple[float, ...] = (2.0, 4.0, 6.0)  # seconds before retry 1, 2, 3

logger = logging.getLogger(__name__)

# AIError.reason categories (the engine maps each one to a TH/EN label for the notice banner).
REASON_AUTH = "auth"                # invalid / missing / unauthorised API key
REASON_MODEL = "model"              # model name not found / not supported
REASON_RATE_LIMIT = "rate_limit"    # HTTP 429, quota exhausted
REASON_TIMEOUT = "timeout"          # request timed out
REASON_NETWORK = "network"          # DNS / connection failure
REASON_SERVER = "server"            # HTTP 5xx
REASON_BAD_REQUEST = "bad_request"  # any other HTTP 4xx
REASON_BAD_ANSWER = "bad_answer"    # HTTP 200 but the content is unusable


class AIError(Exception):
    """The AI service could not produce a usable answer.

    reason — one of the REASON_* categories
    status — HTTP status code when the provider answered, else None
    detail — short diagnostic text, already scrubbed of the API key and credential-like text
    """

    def __init__(self, message: str, reason: str = REASON_BAD_ANSWER, status: Optional[int] = None,
                 detail: str = ""):
        super().__init__(message)
        self.reason = reason
        self.status = status
        self.detail = detail or message


@dataclass
class AIItem:
    """One unit of work for the LLM.

    id            — original line number of the first line (stable key for the answer)
    lines         — sanitized SOURCE lines to translate, original indentation kept
    parent_source — sanitized source header of the enclosing block when `lines` are only
                    some sub-commands of it (context, not to be translated)
    parent_target — the rule-rendered target header of that block, if any
    """

    id: int
    lines: list[str]
    parent_source: Optional[str] = None
    parent_target: Optional[str] = None


class Translator(Protocol):
    def translate_items(self, items: list[AIItem], source: Vendor, target: Vendor) -> dict[int, list[str]]: ...

    def translate_config(self, text: str, source: Vendor, target: Vendor) -> list[str]: ...


_NAVIGATION_RULES = {
    Vendor.HUAWEI_VRP: (
        "- Mode navigation: 'configure terminal' becomes 'system-view' and must come before every other "
        "command; 'exit' becomes 'quit' (it steps back ONE view level, so never translate 'exit' as 'return'); "
        "'end' becomes 'return' (back to user view).\n"
    ),
    Vendor.CISCO_IOS_XE: (
        "- Mode navigation: 'system-view' becomes 'configure terminal' and must come before every other "
        "command; 'quit' becomes 'exit' (it steps back ONE level, so never translate 'quit' as 'end'); "
        "'return' becomes 'end'.\n"
    ),
}


# Extra target-specific constraints (mainly for ai_only, where the whole file goes to the AI).
_TARGET_EXTRA_RULES = {
    Vendor.HUAWEI_VRP: (
        "- Only when translating a complete configuration file (AI-only mode), the very first output "
        "line must be 'system-view'. When translating partial or selected blocks/items (hybrid mode or "
        "user-selected lines), the result is merged into a file that already starts with 'system-view' "
        "and ends with 'return', so you MUST NOT emit 'system-view' or 'return' in those answers.\n"
        "- Never invent hybrid Cisco/Huawei commands such as 'undo ip domain lookup'. "
        "'no ip domain-lookup' is not needed (ไม่ต้องใช้คำสั่งนี้) because Huawei VRP disables DNS lookup "
        "by default, so return no command for it.\n"
        "- When translating 'line console 0' or 'line vty' with 'login' (without 'login local'), "
        "include 'authentication-mode password' inside the 'user-interface' block "
        "(configure the mode only, without adding any secret value).\n"
        "- Translate Cisco 'interface range <type><start> - <end>' to "
        "'port-group group-member <type><start> to <type><end>', keeping the port numbering "
        "exactly as in the source (e.g. '0/2' stays '0/2'; never turn a 2-part number into a 3-part one).\n"
        "- Trunk VLAN lists, two distinct cases: (a) when the Cisco source specifies VLANs "
        "('switchport trunk allowed vlan 10,20,99'), ALWAYS translate it directly to "
        "'port trunk allow-pass vlan 10 20 99' (space-separated; a range 'a-b' becomes 'a to b'); "
        "(b) ONLY when a Cisco trunk port has NO 'switchport trunk allowed vlan' line at all, translate "
        "'switchport mode trunk' to 'port link-type trunk' followed by the advisory comment "
        "'# แนะนำ: port trunk allow-pass vlan all'. "
        "Never emit 'port trunk allow-pass vlan all' as an active command and never guess VLAN numbers.\n"
        "- 'switchport nonegotiate' is not needed (ไม่ต้องใช้คำสั่งนี้) because Huawei VRP has no DTP: "
        "omit it or write it only as a '#' comment. NEVER emit 'undo negotiation auto' for it (that "
        "disables Ethernet speed/duplex auto-negotiation and can break the physical link).\n"
        "- Never translate 'logging synchronous' into 'undo idle-timeout' (that disables the session "
        "timeout, a completely different meaning). Return no command for 'logging synchronous', because "
        "Huawei VRP does not interrupt typed CLI input by default.\n"
        "- Translate 'spanning-tree portfast' (with or without 'edge') strictly to "
        "'stp edged-port enable'. Emit 'stp bpdu-protection' ONLY at global system-view level (it is a "
        "system-view command on Huawei S-series that protects every port with 'stp edged-port enable'), "
        "NEVER inside an 'interface' or 'port-group' block: Cisco 'spanning-tree portfast bpduguard default' "
        "becomes global 'stp bpdu-protection', and an interface-level 'spanning-tree bpduguard enable' "
        "returns no command inside the interface/port-group. "
        "Use only these standard VRP STP commands and never invent non-existent ones such as "
        "'stp sock-type'.\n"
        "- Never emit 'rsa local-key-pair create' (or any other key-pair generation command): it prompts "
        "interactively ([Y/N] and modulus size) and hangs scripted CLI pushes. Keys are created by the "
        "administrator on the device.\n"
        "- Translate 'clock timezone <tz> <hours> [<minutes>]' to 'clock timezone <tz> add HH:MM:SS' "
        "(use 'minus' for a negative offset), e.g. 'clock timezone ICT 7 0' -> "
        "'clock timezone ICT add 07:00:00'.\n"
        "- SSH server: 'ip ssh version 2' -> 'ssh server compatible-ssh1x disable'; "
        "'ip ssh time-out <sec>' -> 'ssh server timeout <sec>' (never 'ssh client timeout'); "
        "'ip ssh authentication-retries <n>' -> 'ssh server authentication-retries <n>' "
        "(never 'ssh server retry'). Do not add 'stelnet server enable' on your own.\n"
        "- 'login local' inside 'line vty' or 'line con' -> 'authentication-mode aaa' inside the "
        "'user-interface' block (never 'authentication-mode local').\n"
        "- DHCP snooping is enabled per VLAN: translate 'ip dhcp snooping vlan <list>' to one block per "
        "VLAN ('vlan <id>', then ' dhcp snooping enable', then 'quit'). Never emit the global form "
        "'dhcp snooping enable vlan ...'.\n"
        "- 'switchport port-security maximum <n>' -> 'port-security max-mac-num <n>' "
        "(never 'port-security max-mac-number').\n"
        "- Emit the global 'dhcp snooping enable' (system view, together with the 'dhcp enable' advice) "
        "BEFORE any 'interface' or 'port-group' block that contains 'dhcp snooping trusted'; Huawei VRP "
        "rejects 'dhcp snooping trusted' while global DHCP snooping is not enabled yet.\n"
        "- Banners: 'banner login <d>text<d>' -> 'header login information <d>text<d>' and "
        "'banner motd <d>text<d>' -> 'header shell information <d>text<d>', keeping the text unchanged. "
        "Never emit 'header banner ...' (it does not exist on Huawei VRP).\n"
        "- Banner delimiter: if the Cisco delimiter is '#' or '^C', ALWAYS replace it with '\"' "
        "(e.g. 'header shell information \" ... \"'), because '#' starts a comment in Huawei VRP.\n"
        "- Global STP: 'spanning-tree mode rapid-pvst' -> 'stp mode rstp'; "
        "'spanning-tree portfast default' -> 'stp edged-port default' (both in system view).\n"
        "- Close every 'vlan <id>' block with 'quit'.\n"
        "- Inside a 'vlan <id>' block ALWAYS use 'description <NAME>' for the VLAN name; "
        "NEVER emit Cisco's 'name <NAME>'.\n"
        "- Translate a non-zero 'exec-timeout <min> <sec>' (e.g. 'exec-timeout 10 0') strictly to "
        "'idle-timeout <min> <sec>'. Use 'undo idle-timeout' ONLY for 'exec-timeout 0 0', never for a "
        "non-zero value.\n"
        "- Translate 'switchport port-security violation {protect|restrict|shutdown}' strictly to "
        "'port-security protect-action {protect|restrict|shutdown}' (NEVER 'port-security trap ...').\n"
        "- Translate 'ip domain-name <domain>' strictly to 'dns domain <domain>' "
        "(NEVER emit a duplicate 'sysname' for it).\n"
        "- No auto-filling: NEVER invent or auto-add 'stelnet server enable' unless that exact command "
        "is explicitly present in the source.\n"
    ),
    Vendor.CISCO_IOS_XE: "",
}


def _system_prompt(source: Vendor, target: Vendor) -> str:
    return (
        f"You are a senior network engineer translating device configuration from {source.display_name} "
        f"to {target.display_name}. IPv4 only.\n"
        "Rules:\n"
        f"- Output only valid {target.display_name} configuration commands, in the target vendor's syntax.\n"
        "- Keep every interface slot/port number exactly as in the source; change only the interface type name.\n"
        "- Never invent values (passwords, keys, metrics, timers, preferences) that are not in the source.\n"
        "- Never output passwords, usernames, keys or community strings.\n"
        "- Do not add commands that the source lines do not express.\n"
        "- Keep the commands in the same order as the source lines.\n"
        f"{_NAVIGATION_RULES[target]}"
        f"{_TARGET_EXTRA_RULES[target]}"
        f"- If a line has no {target.display_name} equivalent, return no command for it.\n"
        f"- Comment lines, if any, must start with '{target.comment_marker}'.\n"
        "- Do not report confidence scores.\n"
        "Answer with a single JSON object and nothing else."
    )


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def _clean_lines(value: object, limit: int) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise AIError("AI answer has an invalid 'lines' field", REASON_BAD_ANSWER)
    out: list[str] = []
    for entry in value:
        for line in entry.splitlines():
            line = line.rstrip()
            if line.strip():
                out.append(line)
    return out[:limit]


def _safe(lines: list[str]) -> list[str]:
    """Last deterministic gate before anything leaves the machine."""
    return [l for l in lines if not contains_secret(l)]


def is_gemini_endpoint(base_url: str, model: str) -> bool:
    """True when requests should use the native Gemini REST API instead of /chat/completions."""
    model_name = model.strip().lower().removeprefix("models/")
    return GEMINI_HOST in base_url.lower() or model_name.startswith("gemini-")


_GEMINI_VERSION = re.compile(r"gemini-(\d+)(?:\.(\d+))?")


def gemini_thinking_config(model: str) -> Optional[dict]:
    """Model-appropriate ``generationConfig.thinkingConfig`` (None = omit the field).

    - Gemini 3.x and later: ``thinkingBudget`` is replaced by ``thinkingLevel``; "low" is
      accepted by every Gemini 3 model (flash, flash-lite, pro). A budget of 0 is rejected.
    - Gemini 2.5 Flash / Flash-Lite: ``thinkingBudget: 0`` turns thinking off (fast answers).
    - Gemini 2.5 Pro cannot disable thinking (budget 0 -> INVALID_ARGUMENT): omit.
    - Gemini 2.0 / 1.x have no thinking support: omit (the field is rejected there).
    - Unknown names: omit (safest).
    """
    name = model.strip().lower().removeprefix("models/")
    m = _GEMINI_VERSION.search(name)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2) or 0)
    if major >= 3:
        return {"thinkingLevel": "low"}
    if (major, minor) == (2, 5) and "pro" not in name:
        return {"thinkingBudget": 0}
    return None


def _error_details(err: dict) -> str:
    """Google-style ``error.details`` (e.g. BadRequest fieldViolations) flattened to text."""
    details = err.get("details")
    if not isinstance(details, list):
        return ""
    parts: list[str] = []
    for d in details:
        if not isinstance(d, dict):
            continue
        violations = d.get("fieldViolations")
        if isinstance(violations, list):
            for v in violations:
                if isinstance(v, dict):
                    text = " ".join(str(v[k]) for k in ("field", "description") if v.get(k))
                    if text:
                        parts.append(text)
        elif d.get("reason") or d.get("message"):
            parts.append(" ".join(str(d[k]) for k in ("reason", "message") if d.get(k)))
    return "; ".join(parts)


def _provider_message(response: httpx.Response, with_details: bool = False) -> str:
    """Best-effort error text from an OpenAI- or Google-style error body.

    ``with_details`` also appends Google's ``error.details`` entries (used when logging HTTP 400).
    """
    try:
        body = response.json()
    except ValueError:
        return response.text.strip()
    if isinstance(body, list) and body:  # Google sometimes wraps the error object in a list
        body = body[0]
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            parts = [str(err[k]) for k in ("status", "message") if err.get(k)]
            if parts:
                text = ": ".join(parts)
                extra = _error_details(err) if with_details else ""
                return f"{text} [details: {extra}]" if extra else text
        elif isinstance(err, str):
            return err
    return json.dumps(body, ensure_ascii=False)


def _classify_http(status: int, message: str) -> str:
    low = message.lower()
    # Google answers an invalid key with HTTP 400 "API key not valid", so look at the text too.
    if status in (401, 403) or "api key" in low or "api_key" in low or "unauthenticated" in low:
        return REASON_AUTH
    if status == 429 or "resource_exhausted" in low or "quota" in low:
        return REASON_RATE_LIMIT
    if status == 404 or ("model" in low and any(w in low for w in ("not found", "not supported", "unknown"))):
        return REASON_MODEL
    if status in (408, 504):
        return REASON_TIMEOUT
    if status >= 500:
        return REASON_SERVER
    return REASON_BAD_REQUEST


class AITranslator:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout: float = 60.0,
        client: Optional[httpx.Client] = None,
        retry_delays: Sequence[float] = RETRY_DELAYS,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not api_key.strip():
            raise ValueError("LLM API key is empty")
        self._api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.model = model.strip()
        self.use_gemini = is_gemini_endpoint(self.base_url, self.model)
        self.last_error: Optional[str] = None  # "<reason>: <scrubbed detail>" of the latest failure
        self._client = client or httpx.Client(timeout=timeout)
        self._retry_delays = tuple(retry_delays)
        self._sleep = sleep

    @classmethod
    def from_settings(cls, settings: Settings) -> Optional["AITranslator"]:
        """None when no API key is configured (caller then runs rule_only and says so)."""
        if not settings.llm_api_key_configured:
            return None
        return cls(
            api_key=settings.llm_api_key,
            base_url=settings.llm_api_base_url,
            model=settings.llm_model,
            timeout=settings.llm_timeout_seconds,
        )

    def close(self) -> None:
        self._client.close()

    @property
    def provider(self) -> str:
        return "gemini" if self.use_gemini else "openai-compatible"

    # ------------------------------------------------------------------ diagnostics

    def _scrub(self, text: str, limit: int = MAX_DETAIL_CHARS) -> str:
        """Diagnostic text safe for logs and notices: no API key, no credential-like text."""
        text = " ".join(text.replace(self._api_key, "***").split()).replace(" | ", " / ")
        if contains_secret(text):
            return "(provider message withheld: it looked like it contained credentials)"
        return text[:limit]

    def _fail(self, message: str, reason: str, status: Optional[int] = None, detail: str = "",
              log_detail: str = "") -> AIError:
        detail = self._scrub(detail or message)
        self.last_error = f"{reason}: {detail}"
        # The log may carry a fuller message (HTTP 400 validation details); notices stay short.
        logged = self._scrub(log_detail, MAX_LOG_DETAIL_CHARS) if log_detail else detail
        logger.warning(
            "AI request failed: provider=%s model=%s reason=%s status=%s message=%s",
            self.provider, self.model, reason, status if status is not None else "-", logged,
        )
        return AIError(message, reason=reason, status=status, detail=detail)

    # ------------------------------------------------------------------ transport

    def _post(self, url: str, body: dict, headers: dict) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = self._client.post(url, json=body, headers=headers)
            except httpx.TimeoutException as exc:
                raise self._fail(f"AI request timed out: {type(exc).__name__}", REASON_TIMEOUT) from exc
            except httpx.HTTPError as exc:
                raise self._fail(f"AI service unreachable: {type(exc).__name__}", REASON_NETWORK,
                                 detail=f"{type(exc).__name__}: {exc}") from exc
            # Transient overload (503 UNAVAILABLE / 429 RESOURCE_EXHAUSTED): back off and retry
            # before giving up; the engine then falls back to rule_only as usual.
            if response.status_code in RETRY_STATUSES and attempt < len(self._retry_delays):
                delay = self._retry_delays[attempt]
                attempt += 1
                logger.info(
                    "AI request got HTTP %s: provider=%s model=%s retry %d/%d in %.0fs",
                    response.status_code, self.provider, self.model, attempt, len(self._retry_delays), delay,
                )
                self._sleep(delay)
                continue
            break
        if response.status_code != 200:
            message = _provider_message(response)
            status = response.status_code
            log_detail = ""
            if status == 400:
                full = _provider_message(response, with_details=True)
                log_detail = f"HTTP {status}: {full}" if full else ""
            raise self._fail(f"AI service returned HTTP {status}", _classify_http(status, message), status,
                             f"HTTP {status}: {message}" if message else f"HTTP {status}",
                             log_detail=log_detail)
        return response

    def _openai_content(self, system: str, user: str) -> str:
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        response = self._post(f"{self.base_url}/chat/completions", body,
                              {"Authorization": f"Bearer {self._api_key}"})
        try:
            return response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise self._fail("AI answer is not valid JSON", REASON_BAD_ANSWER,
                             detail="response has no choices[0].message.content") from exc

    def _gemini_url(self) -> str:
        model = self.model.removeprefix("models/")
        return f"{GEMINI_API_ROOT}/models/{quote(model, safe='.-_')}:generateContent"

    def _gemini_body(self, system: str, user: str, minimal: bool = False) -> dict:
        """generateContent request body.

        ``minimal`` drops every optional, model-dependent generationConfig field (thinking
        control, temperature); it is the retry body after an HTTP 400 INVALID_ARGUMENT.
        """
        config: dict[str, object] = {"responseMimeType": "application/json"}
        if not minimal:
            config["temperature"] = 0
            thinking = gemini_thinking_config(self.model)
            if thinking is not None:
                config["thinkingConfig"] = thinking
        return {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": config,
        }

    def _gemini_content(self, system: str, user: str) -> str:
        headers = {"x-goog-api-key": self._api_key}
        try:
            response = self._post(self._gemini_url(), self._gemini_body(system, user), headers)
        except AIError as exc:
            # A model that rejects an optional generationConfig field answers 400 INVALID_ARGUMENT.
            # Retry once with the minimal body instead of failing the whole conversion.
            if exc.status != 400 or exc.reason != REASON_BAD_REQUEST:
                raise
            logger.info("Gemini rejected the request (HTTP 400): model=%s retrying with minimal "
                        "generationConfig", self.model)
            response = self._post(self._gemini_url(), self._gemini_body(system, user, minimal=True), headers)
        try:
            data = response.json()
        except ValueError as exc:
            raise self._fail("AI answer is not valid JSON", REASON_BAD_ANSWER,
                             detail="Gemini response is not JSON") from exc
        candidates = data.get("candidates") if isinstance(data, dict) else None
        if not candidates or not isinstance(candidates, list):
            feedback = data.get("promptFeedback") if isinstance(data, dict) else None
            block = feedback.get("blockReason") if isinstance(feedback, dict) else None
            raise self._fail("AI answer has no candidates", REASON_BAD_ANSWER,
                             detail=f"Gemini returned no candidates (blockReason={block})" if block
                             else "Gemini returned no candidates")
        first = candidates[0] if isinstance(candidates[0], dict) else {}
        content = first.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        # Thinking models may add parts flagged "thought": those are not the answer.
        text = "".join(
            p["text"] for p in (parts or [])
            if isinstance(p, dict) and isinstance(p.get("text"), str) and not p.get("thought")
        )
        if not text.strip():
            raise self._fail("AI answer is empty", REASON_BAD_ANSWER,
                             detail=f"Gemini returned no text (finishReason={first.get('finishReason')})")
        return text

    def _chat_json(self, system: str, user: str) -> dict:
        content = self._gemini_content(system, user) if self.use_gemini else self._openai_content(system, user)
        try:
            data = json.loads(_FENCE.sub("", content.strip()))
        except (ValueError, AttributeError, TypeError) as exc:
            raise self._fail("AI answer is not valid JSON", REASON_BAD_ANSWER,
                             detail="model output is not valid JSON") from exc
        if not isinstance(data, dict):
            raise self._fail("AI answer is not a JSON object", REASON_BAD_ANSWER)
        self.last_error = None
        return data

    # ------------------------------------------------------------------ API

    def translate_items(self, items: list[AIItem], source: Vendor, target: Vendor) -> dict[int, list[str]]:
        """Translate selected lines/blocks. Returns {item id: target lines}; ids the AI
        skipped or answered with nothing are simply absent."""
        payload_items = []
        for item in items:
            lines = _safe(item.lines)
            if not lines:
                continue
            entry: dict[str, object] = {"id": item.id, "lines": lines}
            if item.parent_source and not contains_secret(item.parent_source):
                entry["parent_source"] = item.parent_source
            if item.parent_target and not contains_secret(item.parent_target):
                entry["parent_target"] = item.parent_target
            payload_items.append(entry)
        if not payload_items:
            return {}

        instructions = (
            "Translate each item's 'lines'. When an item has 'parent_source', its lines are sub-commands "
            "inside that block (already converted as 'parent_target' when given): return them as "
            "sub-commands indented with one space and do NOT repeat the parent header. Otherwise return "
            "complete top-level commands/blocks with normal indentation.\n"
            'Reply exactly as {"translations": [{"id": <id>, "lines": ["<target line>", ...]}]}.'
        )
        user = instructions + "\n\n" + json.dumps(
            {"source_vendor": source.display_name, "target_vendor": target.display_name, "items": payload_items},
            ensure_ascii=False,
        )
        data = self._chat_json(_system_prompt(source, target), user)
        translations = data.get("translations")
        if not isinstance(translations, list):
            raise self._fail("AI answer has no 'translations' list", REASON_BAD_ANSWER)
        wanted = {e["id"] for e in payload_items}
        out: dict[int, list[str]] = {}
        for entry in translations:
            if not isinstance(entry, dict) or entry.get("id") not in wanted:
                continue
            try:
                lines = _clean_lines(entry.get("lines"), MAX_LINES_PER_ITEM)
            except AIError as exc:
                raise self._fail(str(exc), REASON_BAD_ANSWER) from exc
            if lines:
                out[int(entry["id"])] = lines
        return out

    def translate_config(self, text: str, source: Vendor, target: Vendor) -> list[str]:
        """AI-only mode: translate a whole (already sanitized) configuration."""
        sanitized = strip_secrets(text, source).sanitized_text  # idempotent second pass
        lines = _safe(sanitized.splitlines())
        if not any(l.strip() for l in lines):
            return []
        user = (
            f"Translate this complete {source.display_name} configuration to {target.display_name}.\n"
            'Reply exactly as {"lines": ["<target line>", ...]}.\n\n' + "\n".join(lines)
        )
        data = self._chat_json(_system_prompt(source, target), user)
        try:
            result = _clean_lines(data.get("lines"), MAX_OUTPUT_LINES)
        except AIError as exc:
            raise self._fail(str(exc), REASON_BAD_ANSWER) from exc
        if not result:
            raise self._fail("AI answer is empty", REASON_BAD_ANSWER)
        return result

    def describe_topology(self, summary: dict, lang: str = "th") -> str:
        """Module 7.2: device roles, unresolved links and a readable explanation.

        `summary` is derived from the IR (never raw text), so it holds no credentials; every
        string is still re-checked before sending (defence in depth).
        """
        payload = json.dumps(summary, ensure_ascii=False)
        if contains_secret(payload):
            raise AIError("topology summary unexpectedly contains credential-like text", REASON_BAD_REQUEST)
        language = "Thai" if lang == "th" else "English"
        system = (
            "You are a senior network engineer. You receive a JSON topology extracted by deterministic rules "
            "from Cisco IOS-XE / Huawei VRP configurations. Describe each device's likely role, suggest how "
            "unresolved trunk ports are probably connected, and explain the topology concisely. Never invent "
            f"IP addresses. Answer in {language}."
        )
        user = 'Reply exactly as {"text": "<explanation>"}.\n\n' + payload
        data = self._chat_json(system, user)
        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            raise self._fail("AI answer is empty", REASON_BAD_ANSWER)
        return "\n".join(l for l in text.strip().splitlines()[:200] if not contains_secret(l))
