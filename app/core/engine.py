"""Conversion pipeline entrypoint.

    raw text -> strip_secrets -> Parser -> IR -> Renderer -> labelled lines

Milestone 2 implements the rule-only path, which is also the fallback whenever the AI
service is unavailable (proposal §2.3.2 item 11: the service never stops).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import BaseModel

from app.core.ir import ConversionMode, DeviceConfigIR, Provenance, RenderedLine, Vendor
from app.core.parsers import ParseResult, parse_config
from app.core.renderers import render_config
from app.core.rules.base import BlockResult, LineKind
from app.core.secret_stripper import SanitizedResult, strip_secrets
from app.services.mode_selector import resolve_mode

NOTICE_AI_UNAVAILABLE = (
    "บริการ AI ไม่พร้อมใช้งาน ระบบจึงแปลงแบบกฎอย่างเดียว (rule_only) "
    "บรรทัดที่กฎแปลงไม่ได้ถูกคงไว้พร้อมป้าย \"แปลงไม่ได้\" และเลือกส่งให้ AI ภายหลังได้"
)


class UnsupportedItem(BaseModel):
    """A source line the rules do not convert. `command` is post-strip_secrets text."""

    line_no: int
    command: str
    reason: str


@dataclass
class ConversionResult:
    source_vendor: Vendor
    target_vendor: Vendor
    requested_mode: ConversionMode
    effective_mode: ConversionMode
    lines: list[RenderedLine]
    ir: DeviceConfigIR
    blocks: list[BlockResult]
    warnings: list[str] = field(default_factory=list)
    # Rule-only mode: the list the user picks from to send selected lines to AI (§2.3.1 1.2.5).
    unconverted_items: list[UnsupportedItem] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    secret_stripped_count: int = 0

    @property
    def text(self) -> str:
        """Plain target-vendor config (comments included, labels only inside comments)."""
        return "\n".join(l.text for l in self.lines) + "\n"

    @property
    def annotated_text(self) -> str:
        """Every line prefixed with its provenance label — for review and download."""
        return "\n".join(f"[{l.provenance.value}] {l.text}" for l in self.lines) + "\n"


def check_vendor_pair(source: Vendor, target: Vendor) -> None:
    if source is target:
        raise ValueError("ต้นทางและปลายทางต้องเป็นคนละยี่ห้อ (Cisco IOS-XE <-> Huawei VRP)")


def sanitize_and_parse(raw: str, source: Vendor, target: Vendor) -> tuple[SanitizedResult, ParseResult]:
    """Security gate first, then parse the remaining lines keeping ORIGINAL line numbers."""
    check_vendor_pair(source, target)
    sanitized = strip_secrets(raw, source, advisory_vendor=target)
    stripped = set(sanitized.stripped_line_numbers)
    kept = [(no, line) for no, line in enumerate(raw.splitlines(), start=1) if no not in stripped]
    return sanitized, parse_config(kept, source)


def unsupported_items(parsed: ParseResult) -> list[UnsupportedItem]:
    return [
        UnsupportedItem(line_no=no, command=s.body, reason=s.reason or "")
        for no, s in parsed.line_status.items()
        if s.kind is LineKind.UNCONVERTED
    ]


def convert(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    mode: ConversionMode = ConversionMode.RULE_ONLY,
    ai_available: bool = False,
) -> ConversionResult:
    check_vendor_pair(source_vendor, target_vendor)
    effective = resolve_mode(mode, ai_available)
    notices = [NOTICE_AI_UNAVAILABLE] if effective is not mode else []
    if effective.requires_ai:
        raise NotImplementedError("AI-assisted modes are not implemented yet; use rule_only")

    sanitized, parsed = sanitize_and_parse(raw, source_vendor, target_vendor)

    advisories = [
        RenderedLine(text=text, provenance=Provenance.SYSTEM, source_line=no, is_comment=True)
        for no, text in zip(sanitized.stripped_line_numbers, sanitized.advisory_lines)
    ]
    lines = advisories + render_config(parsed.ir, target_vendor)

    # The rule that parsed a source line knows its D/T/S class best (e.g. "ip address x 24"
    # is T, "ip address x 255.255.255.0" is D); prefer it over the renderer's default.
    for line in lines:
        status = parsed.line_status.get(line.source_line) if line.source_line else None
        if not line.is_comment and status and status.kind is LineKind.RULE and status.category:
            line.category = status.category

    warnings: list[str] = []
    for line in lines:
        if line.warning and line.provenance in (Provenance.RULE, Provenance.SYSTEM) and line.warning not in warnings:
            warnings.append(line.warning)

    return ConversionResult(
        source_vendor=source_vendor,
        target_vendor=target_vendor,
        requested_mode=mode,
        effective_mode=effective,
        lines=lines,
        ir=parsed.ir,
        blocks=parsed.blocks,
        warnings=warnings,
        unconverted_items=unsupported_items(parsed),
        notices=notices,
        secret_stripped_count=len(sanitized.stripped_line_numbers),
    )
