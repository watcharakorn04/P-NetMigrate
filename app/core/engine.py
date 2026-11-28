"""Conversion pipeline entrypoint (proposal §2.3.1 item 1.2).

    raw text -> strip_secrets -> Parser -> IR -> Renderer -> labelled lines
                     |
                     +-> (hybrid / ai_only / user-selected) sanitized lines -> AI
                         -> lines labelled "มาจาก AI ต้องตรวจสอบก่อนใช้"

Security gate: `strip_secrets()` ALWAYS runs first, so nothing that reaches the AI client
was ever a credential line; the client re-applies the same filter (defence in depth) and
every AI answer line is checked again before it can reach the output.

Fallback: when no translator is available, or the AI call fails or answers garbage, the
result is exactly the rule_only result plus a notice (§2.3.2 item 11: never stop).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from pydantic import BaseModel

from app.core.ir import ConversionMode, DeviceConfigIR, Provenance, RenderedLine, Vendor
from app.core.parsers import ParseResult, parse_config
from app.core.renderers import render_config
from app.core.renderers.common import WARN_TWO_TUPLE_PORTS
from app.core.renderers.huawei_vrp import (
    dedupe_ospf_router_id,
    guard_eth_trunk_members,
    order_eth_trunk,
    order_global_dhcp_snooping,
    order_undo_portswitch,
)
from app.core.rules.interface_names import is_virtual
from app.core.rules.base import BlockResult, LineKind, LineStatus, auto_ai_eligible
from app.core.rules.tier1_system import is_huawei_system_view
from app.core.secret_stripper import SanitizedResult, contains_secret, is_interactive_command, strip_secrets
from app.services import ai_translator as _ai
from app.services.ai_translator import AIError, AIItem, Translator
from app.services.mode_selector import resolve_mode

NOTICE_AI_UNAVAILABLE = (
    "บริการ AI ไม่พร้อมใช้งาน ระบบจึงแปลงแบบกฎอย่างเดียว (rule_only) "
    "บรรทัดที่กฎแปลงไม่ได้ถูกคงไว้พร้อมป้าย \"แปลงไม่ได้\" และเลือกส่งให้ AI ภายหลังได้"
)
NOTICE_AI_FAILED = (
    "เรียกใช้บริการ AI ไม่สำเร็จหรือ AI ตอบกลับในรูปแบบที่ใช้ไม่ได้ ระบบจึงแสดงผลแบบกฎอย่างเดียว (rule_only) "
    "บรรทัดที่กฎแปลงไม่ได้ยังคงป้าย \"แปลงไม่ได้\""
)
# Shown next to NOTICE_AI_FAILED: "<prefix><reason label> — <scrubbed diagnostic detail>".
NOTICE_AI_FAILED_REASON_PREFIX = "สาเหตุที่เรียก AI ไม่สำเร็จ: "
AI_FAILURE_LABELS = {
    _ai.REASON_AUTH: "API key ไม่ถูกต้องหรือไม่มีสิทธิ์ใช้งาน (Auth error)",
    _ai.REASON_MODEL: "ไม่พบชื่อโมเดลหรือโมเดลไม่รองรับ (Invalid model name)",
    _ai.REASON_RATE_LIMIT: "เรียกใช้เกินโควตาหรือถี่เกินไป (Rate limit)",
    _ai.REASON_TIMEOUT: "หมดเวลารอคำตอบ (Timeout)",
    _ai.REASON_NETWORK: "เชื่อมต่อบริการ AI ไม่ได้ (Network error)",
    _ai.REASON_SERVER: "บริการ AI ขัดข้องฝั่งผู้ให้บริการ (Server error)",
    _ai.REASON_BAD_REQUEST: "ผู้ให้บริการปฏิเสธคำขอ (Bad request)",
    _ai.REASON_BAD_ANSWER: "AI ตอบกลับในรูปแบบที่ใช้ไม่ได้ (Unusable answer)",
}


def ai_failure_notice(exc: AIError) -> str:
    """User-facing reason line for an AI failure (detail is already scrubbed by the client)."""
    label = AI_FAILURE_LABELS.get(getattr(exc, "reason", ""), AI_FAILURE_LABELS[_ai.REASON_BAD_ANSWER])
    detail = (getattr(exc, "detail", "") or str(exc)).replace(" | ", " / ").strip() or "-"
    if contains_secret(detail):
        detail = "-"
    return f"{NOTICE_AI_FAILED_REASON_PREFIX}{label} — {detail}"


NOTICE_AI_REVIEW = (
    "มีบรรทัดที่ AI แปลให้ ซึ่งติดป้าย \"มาจาก AI ต้องตรวจสอบก่อนใช้\" "
    "กรุณาตรวจสอบกับเอกสารของผู้ผลิตก่อนนำไปใช้ (ระบบไม่ใช้ค่าความมั่นใจที่ AI รายงานเอง)"
)
NOTICE_HYBRID_NOTHING_TO_SEND = "กฎแปลงได้ครบทุกบรรทัดที่ระบบอนุญาตให้ส่ง AI จึงไม่ได้เรียกใช้ AI"
NOTICE_NO_SELECTION = "ไม่มีบรรทัดที่เลือกซึ่งมีป้าย \"แปลงไม่ได้\" จึงไม่ได้ส่งข้อมูลให้ AI"
ADVISORY_AI_SECRET = (
    "บรรทัดที่ AI ตอบกลับมีลักษณะเป็นข้อมูลลับ (รหัสผ่าน/บัญชีผู้ใช้/คีย์) ระบบจึงตัดออก "
    "กรุณาตั้งค่าส่วนนี้เองบนอุปกรณ์ปลายทาง"
)

ADVISORY_AI_INTERACTIVE = (
    "ตัดข้อมูลลับออก: บรรทัดที่ AI ตอบกลับเป็นคำสั่งสร้างคีย์แบบโต้ตอบ (rsa local-key-pair create) "
    "ซึ่งจะถามยืนยัน [Y/N] และขนาดคีย์ ทำให้สคริปต์ค้าง ระบบจึงตัดออกและไม่ส่งไปอุปกรณ์ "
    "กรุณาสร้างคีย์เองบนอุปกรณ์ปลายทาง"
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
    # Source line numbers whose (sanitized) text was sent to the AI service in this run.
    ai_sent_line_numbers: list[int] = field(default_factory=list)

    @property
    def ai_line_count(self) -> int:
        return sum(1 for l in self.lines if l.provenance is Provenance.AI and not l.is_comment)

    @property
    def provenance_counts(self) -> dict[str, int]:
        counts = {p.name: 0 for p in Provenance}
        for l in self.lines:
            counts[l.provenance.name] += 1
        return counts

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


def _collect_warnings(lines: Iterable[RenderedLine]) -> list[str]:
    warnings: list[str] = []
    for line in lines:
        if line.warning and line.provenance in (Provenance.RULE, Provenance.SYSTEM) and line.warning not in warnings:
            warnings.append(line.warning)
    return warnings


def _is_two_tuple(number: Optional[str]) -> bool:
    """"0/1" (or sub-interface "0/1.100") is 2-tuple <slot>/<port>; "0/0/1" is 3-tuple."""
    if not number:
        return False
    parts = number.split(".", 1)[0].split("/")
    return len(parts) == 2 and all(p.isdigit() for p in parts)


def _has_two_tuple_ports(ir: DeviceConfigIR) -> bool:
    """True when a physical interface rendered from the IR keeps 2-tuple numbering."""
    return any(
        not (iface.is_virtual or is_virtual(iface.if_type))
        and (_is_two_tuple(iface.number) or _is_two_tuple(iface.range_end))
        for iface in ir.interfaces
    )


def _rule_result(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    requested: ConversionMode,
    notices: Optional[list[str]] = None,
) -> tuple[ConversionResult, ParseResult, SanitizedResult]:
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

    result = ConversionResult(
        source_vendor=source_vendor,
        target_vendor=target_vendor,
        requested_mode=requested,
        effective_mode=ConversionMode.RULE_ONLY,
        lines=lines,
        ir=parsed.ir,
        blocks=parsed.blocks,
        warnings=_collect_warnings(lines),
        unconverted_items=unsupported_items(parsed),
        notices=list(notices or []),
        secret_stripped_count=len(sanitized.stripped_line_numbers),
    )
    # Port numbers are never translated (§6); a single, deduplicated advisory per conversion
    # flags 2-tuple names that 3-tuple Huawei models (S5700/S6700/AR) will not accept.
    if (
        source_vendor is Vendor.CISCO_IOS_XE
        and target_vendor is Vendor.HUAWEI_VRP
        and _has_two_tuple_ports(parsed.ir)
        and WARN_TWO_TUPLE_PORTS not in result.warnings
    ):
        result.warnings.append(WARN_TWO_TUPLE_PORTS)
    return result, parsed, sanitized


# ----------------------------------------------------------------------------- AI work units


@dataclass
class _Job:
    item: AIItem
    line_numbers: list[int]  # source lines this job translates
    replace_rule_lines: bool = False  # complex-command block: AI output replaces the rule output


# (block, line number, line status) -> send this unconverted line to AI?
Picker = Callable[[BlockResult, int, LineStatus], bool]


def _block_spans(parsed: ParseResult) -> list[tuple[BlockResult, list[int]]]:
    """Each top-level block with the effective source line numbers it contains."""
    starts = [b.line_no for b in parsed.blocks]
    spans: list[list[int]] = [[] for _ in parsed.blocks]
    for no, status in parsed.line_status.items():
        if not status.effective:
            continue
        idx = bisect.bisect_right(starts, no) - 1
        if idx >= 0:
            spans[idx].append(no)
    return list(zip(parsed.blocks, spans))


def _rendered_header(lines: list[RenderedLine], header_no: int) -> Optional[str]:
    for line in lines:
        if line.source_line == header_no and not line.is_comment and line.provenance is Provenance.RULE:
            return line.text.strip()
    return None


def _source_line(raw_lines: list[str], no: int) -> str:
    return raw_lines[no - 1].expandtabs(4).rstrip() if 0 < no <= len(raw_lines) else ""


def _build_jobs(
    raw: str,
    parsed: ParseResult,
    rendered: list[RenderedLine],
    pick: Picker,
    complex_prefixes: Sequence[str] = (),
) -> list[_Job]:
    """Group the lines to send into one job per top-level block (the block header is
    passed as context when only some sub-commands are sent)."""
    raw_lines = raw.splitlines()
    jobs: list[_Job] = []
    for block, numbers in _block_spans(parsed):
        if not numbers:
            continue
        header_lower = block.header.lower()
        if any(header_lower.startswith(p) for p in complex_prefixes):
            # Proposal §2.3.1 item 1.2.2, case 3: configured complex command -> whole block to AI.
            text = [_source_line(raw_lines, n) for n in numbers]
            jobs.append(_Job(AIItem(id=numbers[0], lines=text), numbers, replace_rule_lines=True))
            continue
        status = parsed.line_status
        chosen = [n for n in numbers if status[n].kind is LineKind.UNCONVERTED and pick(block, n, status[n])]
        if not chosen:
            continue
        item = AIItem(id=chosen[0], lines=[_source_line(raw_lines, n) for n in chosen])
        if block.line_no not in chosen:
            item.parent_source = block.header
            item.parent_target = _rendered_header(rendered, block.line_no)
            item.lines = [l if l[:1].isspace() else " " + l.strip() for l in item.lines]
        jobs.append(_Job(item, chosen))
    # Defence in depth: never hand a credential-looking line to the client.
    for job in jobs:
        job.item.lines = [l for l in job.item.lines if l.strip() and not contains_secret(l)]
    return [j for j in jobs if j.item.lines]


def _hybrid_pick(block: BlockResult, no: int, status: LineStatus) -> bool:
    # Proposal §2.3.1 item 1.2.2 cases 1 and 2: no rule matched / rule reported incomplete.
    return (block.rule is None or not block.complete) and auto_ai_eligible(status.reason)


def _ai_lines(answer: list[str], job: _Job, target: Vendor, header: Optional[str] = None) -> list[RenderedLine]:
    marker = target.comment_marker
    first = job.line_numbers[0]
    if header is None:
        numbers = ", ".join(str(n) for n in job.line_numbers)
        header = f"แปลโดย AI จากบรรทัดต้นทาง {numbers}"
    out = [
        RenderedLine(
            text=f"{marker} [{Provenance.AI.value}] {header}",
            provenance=Provenance.AI,
            source_line=first,
            is_comment=True,
        )
    ]
    parent = (job.item.parent_target or "").strip()
    for text in answer:
        if job.item.parent_source:
            if parent and text.strip() == parent:
                continue  # AI repeated the already-converted parent header
            if not text[:1].isspace() and not text.startswith(marker):
                text = " " + text
        if is_interactive_command(text):
            # Interactive key generation hangs scripted pushes (and is key material): never
            # output it, even when the source line was already stripped before the AI call.
            out.append(
                RenderedLine(
                    text=f"{marker} [{Provenance.SYSTEM.value}] {ADVISORY_AI_INTERACTIVE}",
                    provenance=Provenance.SYSTEM,
                    source_line=first,
                    is_comment=True,
                )
            )
            continue
        if contains_secret(text):
            # Non-Negotiable #2: never output a secret, even one the AI made up.
            out.append(
                RenderedLine(
                    text=f"{marker} [{Provenance.SYSTEM.value}] {ADVISORY_AI_SECRET}",
                    provenance=Provenance.SYSTEM,
                    source_line=first,
                    is_comment=True,
                )
            )
            continue
        out.append(
            RenderedLine(
                text=text,
                provenance=Provenance.AI,
                source_line=first,
                is_comment=text.lstrip().startswith(marker),
            )
        )
    return out


def _apply_ai(
    lines: list[RenderedLine], jobs: list[_Job], answers: dict[int, list[str]], target: Vendor
) -> tuple[list[RenderedLine], set[int]]:
    """Replace the "แปลงไม่ได้" comments (or, for complex blocks, the rule output) of every
    answered job with the AI lines, at the position of the first replaced line. Jobs the
    AI did not answer keep their "แปลงไม่ได้" comments."""
    remove: set[int] = set()
    insert: dict[int, list[RenderedLine]] = {}
    tail: list[tuple[int, list[RenderedLine]]] = []  # (first source line, AI lines)
    translated: set[int] = set()
    for job in jobs:
        answer = answers.get(job.item.id)
        if not answer:
            continue
        wanted = set(job.line_numbers)
        idxs = [
            i
            for i, l in enumerate(lines)
            if l.source_line in wanted
            and (job.replace_rule_lines or l.provenance is Provenance.UNCONVERTED)
            and i not in remove
        ]
        new = _ai_lines(answer, job, target)
        if idxs:
            remove.update(idxs)
            insert.setdefault(idxs[0], []).extend(new)
        else:
            tail.append((job.line_numbers[0], new))
        translated.update(wanted)

    out: list[RenderedLine] = []
    for i, line in enumerate(lines):
        out.extend(insert.get(i, []))
        if i not in remove:
            out.append(line)
    # Jobs with no rendered line to replace: place them by ORIGINAL line number (after the
    # last rendered line from an earlier source line), never appended out of order at the
    # end; they always stay before the closing end/return.
    for first, new in sorted(tail, key=lambda t: t[0]):
        terminator = next(
            (i for i in range(len(out) - 1, -1, -1)
             if not out[i].is_comment and out[i].text.strip() in ("return", "end")),
            len(out),
        )
        pos = 0
        for i, line in enumerate(out[:terminator]):
            if line.source_line is not None and line.source_line < first:
                pos = i + 1
        out[pos:pos] = new
    return out, translated


def _strip_partial_navigation(
    answers: dict[int, list[str]], rendered: list[RenderedLine], target: Vendor
) -> dict[int, list[str]]:
    """Defence in depth for partial AI answers (hybrid / user-selected) merged into a Huawei
    rule result: a standalone `system-view` is dropped when the output already enters the
    system view, and a standalone `return` when the output already closes with its own
    `return` (a mid-file `return` would leave system view). Answers left empty are dropped,
    so their lines keep the "แปลงไม่ได้" label."""
    if target is not Vendor.HUAWEI_VRP:
        return answers
    commands = [l.text.strip() for l in rendered if not l.is_comment and l.provenance is not Provenance.AI]
    has_system_view = any(is_huawei_system_view(c) for c in commands)
    has_return = "return" in commands
    out: dict[int, list[str]] = {}
    for item_id, lines in answers.items():
        kept = [
            l for l in lines
            if not (has_system_view and is_huawei_system_view(l.strip()))
            and not ((has_system_view or has_return) and l.strip().lower() == "return")
        ]
        if kept:
            out[item_id] = kept
    return out


def _run_jobs(result: ConversionResult, jobs: list[_Job], translator: Translator) -> ConversionResult:
    """Send jobs to AI and merge. On AIError the rule-only result is returned with a notice."""
    result.ai_sent_line_numbers = sorted(n for j in jobs for n in j.line_numbers)
    try:
        answers = translator.translate_items([j.item for j in jobs], result.source_vendor, result.target_vendor)
    except AIError as exc:
        result.effective_mode = ConversionMode.RULE_ONLY
        result.notices += [NOTICE_AI_FAILED, ai_failure_notice(exc)]
        return result
    answers = _strip_partial_navigation(answers, result.lines, result.target_vendor)
    result.lines, translated = _apply_ai(result.lines, jobs, answers, result.target_vendor)
    result.unconverted_items = [i for i in result.unconverted_items if i.line_no not in translated]
    if translated:
        result.notices.append(NOTICE_AI_REVIEW)
    return result


# ----------------------------------------------------------------------------- public API


def _convert(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    mode: ConversionMode = ConversionMode.RULE_ONLY,
    ai_available: Optional[bool] = None,
    translator: Optional[Translator] = None,
    complex_commands: Sequence[str] = (),
) -> ConversionResult:
    """Convert one configuration.

    translator        — AI client; None means AI is unavailable (-> rule_only + notice).
    ai_available      — False force-disables AI even with a translator; default: translator given.
    complex_commands  — block-header prefixes hybrid mode always sends to AI (§2.3.1 1.2.2).
    """
    check_vendor_pair(source_vendor, target_vendor)
    usable = translator is not None and ai_available is not False
    effective = resolve_mode(mode, usable)
    notices = [NOTICE_AI_UNAVAILABLE] if effective is not mode else []

    result, parsed, sanitized = _rule_result(raw, source_vendor, target_vendor, mode, notices)
    if effective is ConversionMode.RULE_ONLY or translator is None:
        return result

    if effective is ConversionMode.HYBRID:
        result.effective_mode = ConversionMode.HYBRID
        prefixes = [p.strip().lower() for p in complex_commands if p.strip()]
        jobs = _build_jobs(raw, parsed, result.lines, _hybrid_pick, prefixes)
        if not jobs:
            result.notices.append(NOTICE_HYBRID_NOTHING_TO_SEND)
            return result
        return _run_jobs(result, jobs, translator)

    # AI_ONLY: the whole SANITIZED file goes to AI (Non-Negotiable #1 — never the raw text).
    sent = [no for no, s in parsed.line_status.items() if s.effective]
    result.ai_sent_line_numbers = sent
    try:
        answer = translator.translate_config(sanitized.sanitized_text, source_vendor, target_vendor)
    except AIError as exc:
        result.notices += [NOTICE_AI_FAILED, ai_failure_notice(exc)]
        return result
    stripped = set(sanitized.stripped_line_numbers)
    advisories = [
        l for l in result.lines if l.provenance is Provenance.SYSTEM and l.is_comment and l.source_line in stripped
    ]
    job = _Job(AIItem(id=sent[0] if sent else 1, lines=[]), sent or [1])
    result.lines = advisories + _ai_lines(answer, job, target_vendor, header="แปลทั้งไฟล์โดย AI (โหมด AI อย่างเดียว)")
    result.effective_mode = ConversionMode.AI_ONLY
    result.warnings = []
    result.unconverted_items = []
    result.notices.append(NOTICE_AI_REVIEW)
    return result


def _convert_selected(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    line_numbers: Iterable[int],
    translator: Optional[Translator],
) -> ConversionResult:
    """Rule-only conversion, then send ONLY the user-picked "แปลงไม่ได้" lines to AI
    (proposal §2.3.1 item 1.2.5). Selected lines that are not unconverted are ignored."""
    check_vendor_pair(source_vendor, target_vendor)
    selected = set(line_numbers)
    notices = [] if translator is not None else [NOTICE_AI_UNAVAILABLE]
    result, parsed, _ = _rule_result(raw, source_vendor, target_vendor, ConversionMode.RULE_ONLY, notices)
    if translator is None:
        return result
    jobs = _build_jobs(raw, parsed, result.lines, lambda b, no, s: no in selected)
    if not jobs:
        result.notices.append(NOTICE_NO_SELECTION)
        return result
    return _run_jobs(result, jobs, translator)


def _finalize(result: ConversionResult) -> ConversionResult:
    """Final assembly checks that hold for every mode (rule, hybrid, ai_only, user-selected)."""
    if result.target_vendor is Vendor.HUAWEI_VRP:
        lines = order_eth_trunk(order_global_dhcp_snooping(result.lines))
        lines = guard_eth_trunk_members(dedupe_ospf_router_id(order_undo_portswitch(lines)))
        result.lines = lines
    return result


def convert(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    mode: ConversionMode = ConversionMode.RULE_ONLY,
    ai_available: Optional[bool] = None,
    translator: Optional[Translator] = None,
    complex_commands: Sequence[str] = (),
) -> ConversionResult:
    """Convert one configuration (see `_convert`), then apply the final assembly checks."""
    return _finalize(_convert(raw, source_vendor, target_vendor, mode, ai_available, translator, complex_commands))


def convert_selected(
    raw: str,
    source_vendor: Vendor,
    target_vendor: Vendor,
    line_numbers: Iterable[int],
    translator: Optional[Translator],
) -> ConversionResult:
    """Send only user-picked "แปลงไม่ได้" lines to AI (see `_convert_selected`), then apply the
    final assembly checks."""
    return _finalize(_convert_selected(raw, source_vendor, target_vendor, line_numbers, translator))
