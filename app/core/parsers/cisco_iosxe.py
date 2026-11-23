"""Cisco IOS-XE parser: source text -> vendor-neutral IR. Never emits target syntax."""

from app.core.ir import Vendor
from app.core.parsers.common import ParseResult, Source, parse as _parse
from app.core.rules import CISCO_HANDLERS


def parse(source: Source) -> ParseResult:
    return _parse(source, Vendor.CISCO_IOS_XE, CISCO_HANDLERS)
