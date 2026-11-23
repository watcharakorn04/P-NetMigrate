"""Per-vendor parsers (source text -> IR)."""

from app.core.ir import Vendor
from app.core.parsers import cisco_iosxe, huawei_vrp
from app.core.parsers.common import ParseResult, Source

_PARSERS = {Vendor.CISCO_IOS_XE: cisco_iosxe.parse, Vendor.HUAWEI_VRP: huawei_vrp.parse}


def parse_config(source: Source, vendor: Vendor) -> ParseResult:
    return _PARSERS[vendor](source)


__all__ = ["ParseResult", "Source", "parse_config"]
