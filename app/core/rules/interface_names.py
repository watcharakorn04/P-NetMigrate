"""Interface type-name mapping (proposal §2.3.2 item 4).

Only the type NAME is translated. The slot/port number is kept verbatim because it is a
physical location with no cross-vendor formula. Virtual interfaces (Loopback, Vlanif,
Eth-Trunk) are the exception in spirit: their number is just a name, so it is always valid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.core.ir import InterfaceRef, Vendor


@dataclass(frozen=True)
class IfType:
    neutral: str
    cisco: str
    huawei: str
    virtual: bool
    huawei_aliases: tuple[str, ...] = ()

    def name_for(self, vendor: Vendor) -> str:
        return self.cisco if vendor is Vendor.CISCO_IOS_XE else self.huawei


IF_TYPES: tuple[IfType, ...] = (
    IfType("gigabitethernet", "GigabitEthernet", "GigabitEthernet", False, ("ge",)),
    IfType("tengigabitethernet", "TenGigabitEthernet", "XGigabitEthernet", False, ("xge",)),
    IfType("fastethernet", "FastEthernet", "Ethernet", False),
    IfType("serial", "Serial", "Serial", False),
    IfType("loopback", "Loopback", "LoopBack", True),
    IfType("vlanif", "Vlan", "Vlanif", True),
    IfType("eth-trunk", "Port-channel", "Eth-Trunk", True),
)
_BY_NEUTRAL = {t.neutral: t for t in IF_TYPES}

# Interface types explicitly out of scope (proposal §2.3.2 item 3).
_OUT_OF_SCOPE = {"tunnel": "Interface ประเภท Tunnel", "atm": "Interface ประเภท ATM"}

_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*(\d[\d/.:]*)$")

# An interface name as written in a command: "Gi0/0/1" or typed with a space, "GigabitEthernet 0/0/1".
IF_NAME_PATTERN = r"[A-Za-z][A-Za-z\-]*\s*\d[\d/.:]*"


def split_name(name: str) -> Optional[tuple[str, str]]:
    m = _NAME_RE.match(name.strip())
    return (m[1], m[2]) if m else None


def _matches(letters: str, full: str) -> bool:
    """Exact name, or an abbreviation (prefix of at least 2 chars), case-insensitive."""
    letters, full = letters.lower(), full.lower()
    return letters == full or (len(letters) >= 2 and full.startswith(letters))


def resolve(name: str, vendor: Vendor) -> Optional[InterfaceRef]:
    """Vendor interface name (full or abbreviated) -> neutral reference; None if unknown/ambiguous."""
    parts = split_name(name)
    if parts is None:
        return None
    letters, number = parts
    low = letters.lower()
    exact = [t for t in IF_TYPES if t.name_for(vendor).lower() == low]
    if not exact and vendor is Vendor.HUAWEI_VRP:
        exact = [t for t in IF_TYPES if low in t.huawei_aliases]
    candidates = exact or [t for t in IF_TYPES if _matches(letters, t.name_for(vendor))]
    if len(candidates) != 1:
        return None
    return InterfaceRef(if_type=candidates[0].neutral, number=number)


def out_of_scope_type(name: str) -> Optional[str]:
    parts = split_name(name)
    letters = (parts[0] if parts else name).lower()
    for key, feature in _OUT_OF_SCOPE.items():
        if letters == key or (len(letters) >= 2 and key.startswith(letters)):
            return feature
    return None


def display_name(ref: InterfaceRef, vendor: Vendor) -> str:
    return f"{_BY_NEUTRAL[ref.if_type].name_for(vendor)}{ref.number}"


def is_virtual(if_type: str) -> bool:
    return _BY_NEUTRAL[if_type].virtual


def slot_of(number: str) -> Optional[int]:
    """Slot = first component of a multi-part number ("1/0/3" -> 1); None for "0" or "10"."""
    parts = number.split("/")
    if len(parts) < 2 or not parts[0].isdigit():
        return None
    return int(parts[0])
