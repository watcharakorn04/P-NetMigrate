"""Rule framework shared by every tier.

A config is split into an indentation tree of `Block`s. Each top-level block is offered
to the vendor's block handlers (defined in the tier modules) in order; the first handler
that claims it fills the IR and marks EVERY line of the block as one of:

  * RULE        — converted by a rule                 (counts as supported)
  * NOT_NEEDED  — redundant on the target by default  (counts as supported)
  * UNCONVERTED — no rule / intentionally not converted / out of scope

A block is `complete` only if none of its lines is UNCONVERTED (proposal §2.3.1 item 1.2.3);
the hybrid mode engine uses that flag to decide whether the block must go to AI.
Lines nobody claims default to UNCONVERTED — nothing is ever silently dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from app.core.ir import DeviceConfigIR, NoteIR, Provenance, SyntaxCategory, Vendor

# ----------------------------------------------------------------------------- reasons (Thai, user-facing)

REASON_NO_RULE = "ยังไม่มีกฎรองรับคำสั่งนี้"
REASON_ORPHAN = "คำสั่งย่อยที่ไม่มีบล็อกหลักรองรับ"


def reason_out_of_scope(feature: str) -> str:
    return f"อยู่นอกขอบเขตของระบบ ({feature}) — ต้องตรวจสอบและตั้งค่าเอง"


def reason_not_supported(feature: str) -> str:
    return f"ยังไม่รองรับ: {feature} — ต้องตรวจสอบและตั้งค่าเอง"


def reason_intentional(why: str) -> str:
    return f"ระบบตั้งใจไม่แปลงคำสั่งนี้: {why}"


# Proposal §2.3.2 item 3: always out of scope, any vendor, any position.
_OUT_OF_SCOPE: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), feature)
    for p, feature in (
        (r"\b(ospfv3|ipv6\s+router\s+ospf)\b", "OSPFv3"),
        (r"\bripng\b|\bipv6\s+router\s+rip\b", "RIPng"),
        (r"^(router\s+)?isis\b|\bisis\s+enable\b|\bip\s+router\s+isis\b", "IS-IS"),
        (r"\bipv6\b", "IPv6"),
        (r"\broute-map\b|\broute-policy\b", "Route-Map/Route-Policy"),
        (r"\bvrf\b|\bvpn-instance\b", "VRF"),
        (r"^(policy-map|class-map|service-policy|qos|traffic\s+(classifier|behavior|policy)|traffic-policy)\b", "QoS Policy"),
    )
]


# Lines whose argument is free text (a description may legitimately say "vrf-core").
_FREE_TEXT = re.compile(r"^(description|name|hostname|sysname)", re.IGNORECASE)


def out_of_scope_feature(body: str) -> Optional[str]:
    if _FREE_TEXT.match(body):
        return None
    for pattern, feature in _OUT_OF_SCOPE:
        if pattern.search(body):
            return feature
    return None


# ----------------------------------------------------------------------------- source structure


@dataclass
class Line:
    no: int  # 1-based line number in the ORIGINAL uploaded file
    indent: int
    body: str  # stripped text


@dataclass
class Block:
    header: Line
    children: list["Block"] = field(default_factory=list)

    def lines(self) -> list[Line]:
        out = [self.header]
        for child in self.children:
            out.extend(child.lines())
        return out


class LineKind(str, Enum):
    RULE = "rule"
    NOT_NEEDED = "not_needed"
    UNCONVERTED = "unconverted"
    IGNORED = "ignored"  # blank / separator / free-text comment — not a config line


@dataclass
class LineStatus:
    kind: LineKind
    body: str
    category: Optional[SyntaxCategory] = None
    reason: Optional[str] = None
    rule: Optional[str] = None

    @property
    def effective(self) -> bool:
        return self.kind is not LineKind.IGNORED

    @property
    def supported(self) -> bool:
        return self.kind in (LineKind.RULE, LineKind.NOT_NEEDED)


@dataclass
class BlockResult:
    """Per-block rule outcome (`complete` drives the hybrid-mode AI fallback)."""

    line_no: int
    header: str
    rule: Optional[str]  # handler that claimed the block; None = no rule matched
    complete: bool


# ----------------------------------------------------------------------------- parse context


class ParseContext:
    def __init__(self, vendor: Vendor):
        self.vendor = vendor
        self.ir = DeviceConfigIR(source_vendor=vendor)
        self.status: dict[int, LineStatus] = {}
        self.current_rule: Optional[str] = None

    # -- marking
    def rule(self, line: Line, category: SyntaxCategory) -> None:
        self.status[line.no] = LineStatus(LineKind.RULE, line.body, category=category, rule=self.current_rule)

    def not_needed(self, line: Line, reason: str, notes: list[NoteIR]) -> None:
        self.status[line.no] = LineStatus(LineKind.NOT_NEEDED, line.body, reason=reason, rule=self.current_rule)
        notes.append(NoteIR(source_line=line.no, text=line.body, provenance=Provenance.NOT_NEEDED, reason=reason))

    def unconverted(self, line: Line, reason: str, notes: list[NoteIR]) -> None:
        self.status[line.no] = LineStatus(LineKind.UNCONVERTED, line.body, reason=reason, rule=self.current_rule)
        notes.append(NoteIR(source_line=line.no, text=line.body, provenance=Provenance.UNCONVERTED, reason=reason))

    def unconverted_block(self, block: Block, reason: str, notes: list[NoteIR]) -> None:
        for line in block.lines():
            self.unconverted(line, reason, notes)

    def unconverted_children(self, block: Block, reason: str, notes: list[NoteIR]) -> None:
        for child in block.children:
            self.unconverted_block(child, reason, notes)


# A block handler returns True when it claims the block (it must then mark every line).
BlockHandler = Callable[[Block, ParseContext], bool]

# A child-line rule: (regex, fn(match, line, ctx, target) -> None). The fn marks the line.
ChildRule = tuple[re.Pattern[str], Callable[..., None]]


def compile_rules(rules: list[tuple[str, Callable[..., None]]]) -> list[ChildRule]:
    return [(re.compile(p, re.IGNORECASE), fn) for p, fn in rules]


def apply_line_rules(
    child: Block,
    ctx: ParseContext,
    rules: list[ChildRule],
    target: object,
    notes: list[NoteIR],
) -> None:
    """Match one child line against flat rules; unmatched -> UNCONVERTED note.

    The matched rule marks the line itself. Grandchildren have no rule here, so they are
    marked unconverted (never dropped).
    """
    body = child.header.body
    feature = out_of_scope_feature(body)
    if feature:
        ctx.unconverted_block(child, reason_out_of_scope(feature), notes)
        return
    for pattern, fn in rules:
        m = pattern.match(body)
        if m:
            fn(m, child.header, ctx, target)
            break
    else:
        ctx.unconverted(child.header, REASON_NO_RULE, notes)
    for grandchild in child.children:
        ctx.unconverted_block(grandchild, REASON_NO_RULE, notes)


def apply_child_rules(
    block: Block,
    ctx: ParseContext,
    rules: list[ChildRule],
    target: object,
    notes: list[NoteIR],
) -> None:
    for child in block.children:
        apply_line_rules(child, ctx, rules, target, notes)
