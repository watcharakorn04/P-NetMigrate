"""Pre-scan analyzer (proposal §2.3.1 item 1.2.1).

Reads the file once WITHOUT converting, rendering or sending anything, and reports how
much of it the rules cover plus which lines they do not support, so the user can choose
a conversion mode. Uses the same parser as the engine, so the numbers always agree with
what a rule-only conversion will actually produce.

Counting:
  * effective line = non-blank, not a comment/separator, not a stripped credential line
  * supported      = converted by a rule, or "ไม่ต้องใช้คำสั่งนี้" (handled; needs no AI)
  * line numbers refer to the ORIGINAL uploaded file
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.core.engine import UnsupportedItem, sanitize_and_parse, unsupported_items
from app.core.ir import Vendor


class PrescanReport(BaseModel):
    source_vendor: Vendor
    target_vendor: Vendor
    total_lines: int
    supported_lines: int
    unsupported_lines: int
    coverage_percent: float = Field(ge=0.0, le=100.0)
    unsupported_items: list[UnsupportedItem]
    secret_stripped_count: int


def prescan_config(raw_config: str, source_vendor: Vendor, target_vendor: Vendor) -> PrescanReport:
    sanitized, parsed = sanitize_and_parse(raw_config, source_vendor, target_vendor)
    effective = [s for s in parsed.line_status.values() if s.effective]
    supported = sum(1 for s in effective if s.supported)
    total = len(effective)
    coverage = round(100.0 * supported / total, 2) if total else 100.0
    return PrescanReport(
        source_vendor=source_vendor,
        target_vendor=target_vendor,
        total_lines=total,
        supported_lines=supported,
        unsupported_lines=total - supported,
        coverage_percent=coverage,
        unsupported_items=unsupported_items(parsed),
        secret_stripped_count=len(sanitized.stripped_line_numbers),
    )
