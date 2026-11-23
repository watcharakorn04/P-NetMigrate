"""Huawei VRP parser: source text -> vendor-neutral IR. Never emits target syntax."""

from app.core.ir import Vendor
from app.core.parsers.common import ParseResult, Source, parse as _parse
from app.core.rules import HUAWEI_HANDLERS


def parse(source: Source) -> ParseResult:
    return _parse(source, Vendor.HUAWEI_VRP, HUAWEI_HANDLERS)
