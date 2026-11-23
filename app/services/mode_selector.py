"""Conversion-mode resolution.

If the external AI service is unavailable, the system behaves like `rule_only` and tells
the user; it never stops serving (proposal §2.3.2 item 11).
"""

from app.core.ir import ConversionMode


def resolve_mode(requested: ConversionMode, ai_available: bool) -> ConversionMode:
    if requested.requires_ai and not ai_available:
        return ConversionMode.RULE_ONLY
    return requested


def mode_availability(ai_available: bool) -> dict[str, bool]:
    return {m.value: (ai_available or not m.requires_ai) for m in ConversionMode}
