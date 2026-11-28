"""Vendor-independent parsing pipeline: lines -> indentation tree -> rule handlers -> IR.

Parsers never emit target syntax. They return the IR plus a per-line status map, which
is what the pre-scan analyzer reports and what the mode engine uses for AI fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Union

from app.core.ir import DeviceConfigIR, NoteIR, Provenance, Vendor
from app.core.rules.base import (
    REASON_NO_RULE,
    REASON_ORPHAN,
    Block,
    BlockHandler,
    BlockResult,
    Line,
    LineKind,
    LineStatus,
    ParseContext,
    exit_word,
    out_of_scope_feature,
    reason_out_of_scope,
)
from app.core.rules.tier1_system import cisco_not_needed_reason, comment_body
from app.core.secret_stripper import contains_secret

# Either raw text, or (original_line_no, text) pairs left after strip_secrets.
Source = Union[str, Iterable[tuple[int, str]]]


@dataclass
class ParseResult:
    ir: DeviceConfigIR
    line_status: dict[int, LineStatus] = field(default_factory=dict)
    blocks: list[BlockResult] = field(default_factory=list)


def _numbered(source: Source) -> list[tuple[int, str]]:
    if isinstance(source, str):
        return list(enumerate(source.splitlines(), start=1))
    return list(source)


def _build_tree(source: Source, ctx: ParseContext) -> list[Block]:
    entries: list[tuple[int, str, int]] = []  # (line_no, body, indent)
    for no, raw in _numbered(source):
        text = raw.expandtabs(4).rstrip()
        body = text.strip()
        # Defence in depth: callers should strip_secrets first; a credential line that slips
        # through is never stored anywhere (not even as a note) so it cannot reach output.
        if not body or contains_secret(body):
            ctx.status[no] = LineStatus(LineKind.IGNORED, "")
            continue
        comment = comment_body(body, ctx.vendor)
        if comment is not None:
            ctx.status[no] = LineStatus(LineKind.IGNORED, body)
            if comment:
                ctx.ir.comments.append(
                    NoteIR(source_line=no, text=comment, provenance=Provenance.RULE, reason="comment")
                )
            continue
        entries.append((no, body, len(text) - len(text.lstrip())))

    base = min((indent for _, _, indent in entries), default=0)  # tolerate uniformly indented pastes
    roots: list[Block] = []
    stack: list[Block] = []
    for no, body, indent in entries:
        node = Block(Line(no=no, indent=indent - base, body=body))
        while stack and stack[-1].header.indent >= node.header.indent:
            stack.pop()
        (stack[-1].children if stack else roots).append(node)
        stack.append(node)
    return _attach_trailing_exits(roots, ctx.vendor)


def _attach_trailing_exits(roots: list[Block], vendor: Vendor) -> list[Block]:
    """Hand-written scripts often close a view with an UNindented `exit` (Cisco) / `quit`
    (Huawei). Read it as the last child of the block above, so it maps to the target's exit
    word for that block instead of becoming an orphan top-level line."""
    word = exit_word(vendor)
    out: list[Block] = []
    for root in roots:
        if out and out[-1].children and not root.children and root.header.body.lower() == word:
            root.header.indent = out[-1].children[0].header.indent
            out[-1].children.append(root)
        else:
            out.append(root)
    return out


def _relabel_not_needed_children(root: Block, ctx: ParseContext) -> None:
    """Cisco sub-commands that are redundant on Huawei wherever they appear (e.g.
    `logging synchronous` under `line con 0`, a block no rule claims): a line left
    "แปลงไม่ได้" only because no rule knew it becomes "ไม่ต้องใช้คำสั่งนี้", so hybrid never
    sends it to AI. Claimed blocks handle these lines with their own child rules."""
    if ctx.vendor is not Vendor.CISCO_IOS_XE:
        return
    for line in root.lines():
        if line is root.header:
            continue
        status = ctx.status.get(line.no)
        if status is None or status.kind is not LineKind.UNCONVERTED or status.reason != REASON_NO_RULE:
            continue
        reason = cisco_not_needed_reason(line.body)
        if reason is None:
            continue
        ctx.ir.notes = [n for n in ctx.ir.notes if n.source_line != line.no]
        ctx.not_needed(line, reason, ctx.ir.notes)


def parse(source: Source, vendor: Vendor, handlers: list[BlockHandler]) -> ParseResult:
    ctx = ParseContext(vendor)
    roots = _build_tree(source, ctx)
    claimed_by: dict[int, str | None] = {}

    for root in roots:
        claimed = None
        feature = out_of_scope_feature(root.header.body)
        if root.header.indent > 0:
            ctx.unconverted_block(root, REASON_ORPHAN, ctx.ir.notes)
        elif feature:
            ctx.unconverted_block(root, reason_out_of_scope(feature), ctx.ir.notes)
        else:
            for handler in handlers:
                ctx.current_rule = handler.__name__
                if handler(root, ctx):
                    claimed = handler.__name__
                    break
            else:
                ctx.current_rule = None
                ctx.unconverted_block(root, REASON_NO_RULE, ctx.ir.notes)
        ctx.current_rule = None
        # Safety net: a handler that forgot a line must not cause a silent drop.
        for line in root.lines():
            if line.no not in ctx.status:
                ctx.unconverted(line, REASON_NO_RULE, ctx.ir.notes)
        if claimed is None:
            _relabel_not_needed_children(root, ctx)
        claimed_by[root.header.no] = claimed

    for finalize in ctx.finalizers:
        finalize(ctx)

    # Completeness is computed after finalizers, which may demote lines of earlier blocks.
    blocks = [
        BlockResult(
            root.header.no,
            root.header.body,
            claimed_by[root.header.no],
            all(ctx.status[l.no].kind is not LineKind.UNCONVERTED for l in root.lines()),
        )
        for root in roots
    ]

    ir = ctx.ir
    ir.vlans.sort(key=lambda v: v.vlan_id)
    ir.notes.sort(key=lambda n: n.source_line)
    if ir.ospf is not None:
        ir.ospf.areas.sort(key=lambda a: a.area_id)
    return ParseResult(ir=ir, line_status=dict(sorted(ctx.status.items())), blocks=blocks)
