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
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Callable, Optional

from app.core.ir import DeviceConfigIR, NoteIR, Provenance, SyntaxCategory, Vendor

# ----------------------------------------------------------------------------- reasons (Thai, user-facing)

REASON_NO_RULE = "ยังไม่มีกฎรองรับคำสั่งนี้"
REASON_ORPHAN = "คำสั่งย่อยที่ไม่มีบล็อกหลักรองรับ"
REASON_BAD_VALUE = "ค่าในคำสั่งไม่ถูกต้อง"
REASON_UNKNOWN_IF = "ไม่รู้จักชื่อ Interface ในคำสั่งนี้"


_PREFIX_OUT_OF_SCOPE = "อยู่นอกขอบเขตของระบบ"
_PREFIX_NOT_SUPPORTED = "ยังไม่รองรับ:"
_PREFIX_INTENTIONAL = "ระบบตั้งใจไม่แปลงคำสั่งนี้:"


def reason_out_of_scope(feature: str) -> str:
    return f"{_PREFIX_OUT_OF_SCOPE} ({feature}) — ต้องตรวจสอบและตั้งค่าเอง"


def reason_not_supported(feature: str) -> str:
    return f"{_PREFIX_NOT_SUPPORTED} {feature} — ต้องตรวจสอบและตั้งค่าเอง"


def reason_intentional(why: str) -> str:
    return f"{_PREFIX_INTENTIONAL} {why}"


def auto_ai_eligible(reason: str | None) -> bool:
    """May hybrid mode send this unconverted line to AI on its own?

    No for out-of-scope features, "not supported" features and intentionally-not-converted
    commands (proposal §2.3.2 items 3 and 7): stating "แปลงไม่ได้" is safer than a
    plausible-looking command with a shifted meaning. The user can still pick these lines
    manually from a rule_only result (§2.3.1 item 1.2.5).
    """
    text = reason or ""
    return not text.startswith((_PREFIX_OUT_OF_SCOPE, _PREFIX_NOT_SUPPORTED, _PREFIX_INTENTIONAL))


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
_FREE_TEXT = re.compile(
    r"^((description|name|hostname|sysname)\b|(neighbor|peer)\s+\S+\s+description\b"
    r"|(access-list\s+\d+\s+)?remark\b)",
    re.IGNORECASE,
)


def parse_ipv4(text: str) -> Optional[IPv4Address]:
    try:
        return IPv4Address(text)
    except (AddressValueError, ValueError):
        return None


def parse_mask(text: str, allow_prefix_len: bool) -> Optional[int]:
    """Dotted mask (or prefix length if allowed) -> prefix length; None if invalid/non-contiguous."""
    if allow_prefix_len and text.isdigit():
        n = int(text)
        return n if 0 <= n <= 32 else None
    if parse_ipv4(text) is None:
        return None
    try:
        return IPv4Network(f"0.0.0.0/{text}").prefixlen
    except ValueError:
        return None


def classful_prefix_len(address: IPv4Address) -> Optional[int]:
    """Class A/B/C natural mask length; None for class D/E (not a unicast network)."""
    first = int(address) >> 24
    if first < 128:
        return 8
    if first < 192:
        return 16
    if first < 224:
        return 24
    return None


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
        # Scratch state shared by one rule module across blocks (e.g. ACL entries spread over
        # many top-level `access-list` lines). Never part of the IR.
        self.data: dict[str, object] = {}
        # Run once after every block is parsed, before block completeness is computed. Used
        # when a decision needs the whole file (e.g. unconvert an ACL if any entry failed).
        self.finalizers: list[Callable[["ParseContext"], None]] = []

    def add_finalizer(self, fn: Callable[["ParseContext"], None]) -> None:
        if fn not in self.finalizers:
            self.finalizers.append(fn)

    def demote(self, line_no: int, reason: str, notes: list[NoteIR]) -> None:
        """Re-label an already-converted line as UNCONVERTED (finalizers only)."""
        status = self.status[line_no]
        self.status[line_no] = LineStatus(LineKind.UNCONVERTED, status.body, reason=reason, rule=status.rule)
        notes.append(NoteIR(source_line=line_no, text=status.body, provenance=Provenance.UNCONVERTED, reason=reason))

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


def unsupported_rule(feature: str) -> Callable[..., None]:
    """Child-rule fn: mark the line "แปลงไม่ได้" as a "not supported" feature (§2.3.2 item 3)."""
    reason = reason_not_supported(feature)

    def fn(m, line, ctx, target):
        ctx.unconverted(line, reason, target.notes)

    return fn


def unconverted_rule(reason: str) -> Callable[..., None]:
    def fn(m, line, ctx, target):
        ctx.unconverted(line, reason, target.notes)

    return fn


def not_needed_rule(reason: str) -> Callable[..., None]:
    def fn(m, line, ctx, target):
        ctx.not_needed(line, reason, target.notes)

    return fn


def view_exit(m, line, ctx, target) -> None:
    """Child-rule fn for an explicit view exit (Cisco `exit` <-> Huawei `quit`).

    It is navigation, not intent: the source line is recorded in the owner's `field_lines`
    (never compared at IR level) so the renderer writes the target's exit word for that block.
    """
    field_lines = getattr(target, "field_lines", None)
    if field_lines is not None:
        field_lines["exit"] = line.no
    ctx.rule(line, SyntaxCategory.DIRECT)


def exit_word(vendor: Vendor) -> str:
    """Command that steps back one view level: Cisco `exit`, Huawei `quit`."""
    return "exit" if vendor is Vendor.CISCO_IOS_XE else "quit"


CISCO_EXIT_RULES: list[ChildRule] = compile_rules([(r"^exit$", view_exit)])
HUAWEI_EXIT_RULES: list[ChildRule] = compile_rules([(r"^quit$", view_exit)])


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
