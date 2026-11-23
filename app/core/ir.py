"""Vendor-agnostic Intermediate Representation (IR).

Architecture: Parser (per vendor) -> IR -> Renderer (per vendor).
The IR stores configuration *intent*; it never stores vendor syntax.
Round-trip fidelity is measured by comparing IR objects, not text.
"""

from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Optional

from pydantic import BaseModel, Field


class Vendor(str, Enum):
    CISCO_IOS_XE = "cisco_ios_xe"
    HUAWEI_VRP = "huawei_vrp"

    @property
    def comment_marker(self) -> str:
        """Comment character of this vendor's CLI ("!" Cisco, "#" Huawei)."""
        return "!" if self is Vendor.CISCO_IOS_XE else "#"


class ConversionMode(str, Enum):
    HYBRID = "hybrid"  # default: rules first, AI only for gaps
    RULE_ONLY = "rule_only"  # never sends data externally
    AI_ONLY = "ai_only"  # all (sanitized) commands go to AI

    @classmethod
    def default(cls) -> "ConversionMode":
        return cls.HYBRID

    @property
    def requires_ai(self) -> bool:
        return self is not ConversionMode.RULE_ONLY


class SyntaxCategory(str, Enum):
    """Classification of a syntax difference between vendors."""

    DIRECT = "D"  # 1:1 word/line replacement (hostname <-> sysname)
    TRANSFORM = "T"  # 1 line -> 1 line, argument format changes
    STRUCTURAL = "S"  # block nesting / line order changes (OSPF)


class Provenance(str, Enum):
    """Per-line provenance label. Values are the exact Thai strings from the spec."""

    RULE = "มาจากกฎ"
    AI = "มาจาก AI ต้องตรวจสอบก่อนใช้"
    SYSTEM = "ระบบสร้างขึ้นเอง"
    UNCONVERTED = "แปลงไม่ได้"
    NOT_NEEDED = "ไม่ต้องใช้คำสั่งนี้"

    @property
    def deployable(self) -> bool:
        """Whether a line with this label may be pushed to a device via SSH.

        AI lines need explicit user confirmation and unconverted lines are
        comments; neither is deployable by default (security rule #3).
        """
        return self in (Provenance.RULE, Provenance.SYSTEM)


class InterfaceIR(BaseModel):
    """A single interface. `if_type` is vendor-neutral; numbering is kept verbatim."""

    if_type: str  # neutral type: "gigabitethernet", "loopback", "vlanif", "eth-trunk", "serial", ...
    number: str  # slot/port string kept verbatim, e.g. "0/0/1" — never translated
    description: Optional[str] = None
    ipv4: Optional[IPv4Interface] = None
    shutdown: Optional[bool] = None  # None = not stated in source (do not guess)
    is_virtual: bool = False  # Loopback / Vlanif / Eth-Trunk — number is a name
    source_lines: list[int] = Field(default_factory=list)


class StaticRouteIR(BaseModel):
    destination: IPv4Network
    next_hop: Optional[IPv4Address] = None
    exit_interface: Optional[str] = None
    # None = not stated; defaults differ (Cisco AD=1, Huawei Preference=60) -> warn, never guess.
    preference: Optional[int] = None
    source_lines: list[int] = Field(default_factory=list)


class DeviceConfigIR(BaseModel):
    source_vendor: Vendor
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    interfaces: list[InterfaceIR] = Field(default_factory=list)
    static_routes: list[StaticRouteIR] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    # Source lines no rule could represent; rendered as target-vendor comments, never dropped.
    unsupported_lines: list[int] = Field(default_factory=list)


class RenderedLine(BaseModel):
    """One line of converted output with its mandatory provenance label."""

    text: str
    provenance: Provenance
    category: Optional[SyntaxCategory] = None
    source_line: Optional[int] = None
    is_comment: bool = False
    warning: Optional[str] = None
