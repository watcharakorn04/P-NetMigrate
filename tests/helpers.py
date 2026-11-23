"""Shared assertion helpers for rule tests (Tier 2 / Tier 3)."""

from __future__ import annotations

from app.core.engine import ConversionResult, convert
from app.core.ir import RenderedLine, Vendor

C = Vendor.CISCO_IOS_XE
H = Vendor.HUAWEI_VRP


def c2h(text: str) -> ConversionResult:
    return convert(text, C, H)


def h2c(text: str) -> ConversionResult:
    return convert(text, H, C)


def cmd(result: ConversionResult, text: str) -> RenderedLine:
    """The single non-comment output line whose stripped text equals `text`."""
    found = [l for l in result.lines if not l.is_comment and l.text.strip() == text]
    assert len(found) == 1, f"expected exactly one {text!r}, got {len(found)}:\n{result.annotated_text}"
    return found[0]


def has_cmd(result: ConversionResult, text: str) -> bool:
    return any(not l.is_comment and l.text.strip() == text for l in result.lines)


def comments_with(result: ConversionResult, needle: str) -> list[RenderedLine]:
    return [l for l in result.lines if l.is_comment and needle in l.text]


def commands(result: ConversionResult) -> list[str]:
    return [l.text for l in result.lines if not l.is_comment]


def block(result: ConversionResult, header: str) -> list[str]:
    """Command lines of the block starting at `header` (header included), up to the next top-level line."""
    out = commands(result)
    start = out.index(header)
    lines = [out[start]]
    for line in out[start + 1 :]:
        if not line.startswith(" "):
            break
        lines.append(line)
    return lines


def block_result(result: ConversionResult, header_prefix: str):
    found = [b for b in result.blocks if b.header.startswith(header_prefix)]
    assert found, f"no block starting with {header_prefix!r}"
    return found[0]
