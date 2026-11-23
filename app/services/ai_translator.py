"""External LLM client (OpenAI-compatible Chat Completions over httpx).

Security Non-Negotiable #1 (CLAUDE.md §4): the conversion engine runs `strip_secrets()`
before it builds anything for this client. This client applies the SAME deterministic
filter again to every line just before the request body is serialised (defence in
depth), so even a caller bug cannot send a credential line out. Prompt instructions are
never relied on to hide secrets.

AI self-reported confidence is never requested or used (proposal §2.3.2 item 9). Every
line returned here is labelled "มาจาก AI ต้องตรวจสอบก่อนใช้" by the engine.

Any failure (network, HTTP status, malformed JSON, wrong shape) raises `AIError`; the
engine catches it and falls back to rule-only output — the service never stops.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional, Protocol

import httpx

from app.config import Settings
from app.core.ir import Vendor
from app.core.secret_stripper import contains_secret, strip_secrets

MAX_LINES_PER_ITEM = 60
MAX_OUTPUT_LINES = 5000


class AIError(Exception):
    """The AI service could not produce a usable answer."""


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
        f"- If a line has no {target.display_name} equivalent, return no command for it.\n"
        f"- Comment lines, if any, must start with '{target.comment_marker}'.\n"
        "- Do not report confidence scores.\n"
        "Answer with a single JSON object and nothing else."
    )


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def _clean_lines(value: object, limit: int) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise AIError("AI answer has an invalid 'lines' field")
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


class AITranslator:
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout: float = 60.0,
        client: Optional[httpx.Client] = None,
    ):
        if not api_key.strip():
            raise ValueError("LLM API key is empty")
        self._api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = client or httpx.Client(timeout=timeout)

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

    # ------------------------------------------------------------------ transport

    def _chat_json(self, system: str, user: str) -> dict:
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        try:
            response = self._client.post(
                f"{self.base_url}/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
        except httpx.HTTPError as exc:
            raise AIError(f"AI service unreachable: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise AIError(f"AI service returned HTTP {response.status_code}")
        try:
            content = response.json()["choices"][0]["message"]["content"]
            data = json.loads(_FENCE.sub("", content.strip()))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIError("AI answer is not valid JSON") from exc
        if not isinstance(data, dict):
            raise AIError("AI answer is not a JSON object")
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
            raise AIError("AI answer has no 'translations' list")
        wanted = {e["id"] for e in payload_items}
        out: dict[int, list[str]] = {}
        for entry in translations:
            if not isinstance(entry, dict) or entry.get("id") not in wanted:
                continue
            lines = _clean_lines(entry.get("lines"), MAX_LINES_PER_ITEM)
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
        result = _clean_lines(data.get("lines"), MAX_OUTPUT_LINES)
        if not result:
            raise AIError("AI answer is empty")
        return result

    def describe_topology(self, summary: dict, lang: str = "th") -> str:
        """Module 7.2: device roles, unresolved links and a readable explanation.

        `summary` is derived from the IR (never raw text), so it holds no credentials; every
        string is still re-checked before sending (defence in depth).
        """
        payload = json.dumps(summary, ensure_ascii=False)
        if contains_secret(payload):
            raise AIError("topology summary unexpectedly contains credential-like text")
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
            raise AIError("AI answer is empty")
        return "\n".join(l for l in text.strip().splitlines()[:200] if not contains_secret(l))
