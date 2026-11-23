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
    out_of_scope_feature,
    reason_out_of_scope,
)
from app.core.rules.tier1_system import comment_body
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
    return roots


def parse(source: Source, vendor: Vendor, handlers: list[BlockHandler]) -> ParseResult:
    ctx = ParseContext(vendor)
    blocks: list[BlockResult] = []

    for root in _build_tree(source, ctx):
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
        complete = all(ctx.status[l.no].kind is not LineKind.UNCONVERTED for l in root.lines())
        blocks.append(BlockResult(root.header.no, root.header.body, claimed, complete))

    ir = ctx.ir
    ir.vlans.sort(key=lambda v: v.vlan_id)
    if ir.ospf is not None:
        ir.ospf.areas.sort(key=lambda a: a.area_id)
    return ParseResult(ir=ir, line_status=dict(sorted(ctx.status.items())), blocks=blocks)
