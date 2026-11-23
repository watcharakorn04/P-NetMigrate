"""Deterministic source-vendor detection (batch "auto" direction, topology upload).

Counts syntax markers that exist on only one of the two vendors. Returns None when the
evidence is missing or tied, so the caller asks the user instead of guessing.
"""

from __future__ import annotations

import re
from typing import Optional

from app.core.ir import Vendor

_CISCO = [re.compile(p, re.I) for p in (
    r"^hostname\s", r"^!", r"^\s*switchport\b", r"^ip route\s", r"^router (ospf|rip|bgp)\b",
    r"^line vty\b", r"^end\s*$", r"^\s*no shutdown\b", r"^ip domain[- ]name\b", r"^logging host\b",
    r"^\s*spanning-tree portfast\b", r"^interface (vlan|port-channel)\d", r"^ip access-list\b",
    r"^access-list\s\d", r"^\s*ip address \S+ \S+",
)]
_HUAWEI = [re.compile(p, re.I) for p in (
    r"^sysname\s", r"^#\s*$", r"^\s*port link-type\b", r"^ip route-static\b", r"^ospf \d", r"^rip\b",
    r"^user-interface\b", r"^return\s*$", r"^\s*undo\s", r"^vlan batch\b", r"^interface (vlanif|eth-trunk|loopback)\d",
    r"^\s*port (default|trunk allow-pass)\b", r"^info-center\b", r"^acl (number|name)\b", r"^\s*stp edged-port\b",
    r"^\s*rule \d+ (permit|deny)\b",
)]


def detect_vendor(text: str) -> Optional[Vendor]:
    cisco = huawei = 0
    for line in text.splitlines()[:2000]:
        cisco += any(p.search(line) for p in _CISCO)
        huawei += any(p.search(line) for p in _HUAWEI)
    if cisco == huawei:
        return None
    return Vendor.CISCO_IOS_XE if cisco > huawei else Vendor.HUAWEI_VRP


def direction_for(vendor: Vendor) -> str:
    return "c2h" if vendor is Vendor.CISCO_IOS_XE else "h2c"
