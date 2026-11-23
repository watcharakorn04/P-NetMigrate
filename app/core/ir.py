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


class NoteIR(BaseModel):
    """A source line no rule converted. Rendered as a target-vendor comment, never dropped.

    `text` is the post-strip_secrets source line, so it can never carry a credential.
    """

    source_line: int
    text: str
    provenance: Provenance  # UNCONVERTED or NOT_NEEDED (RULE for translated free-text comments)
    reason: str


class InterfaceRef(BaseModel):
    """Vendor-neutral reference to an interface (used by OSPF silent-interface, static routes)."""

    if_type: str
    number: str


class InterfaceIR(BaseModel):
    """A single interface. `if_type` is vendor-neutral; numbering is kept verbatim."""

    if_type: str  # neutral type: "gigabitethernet", "loopback", "vlanif", "eth-trunk", "serial", ...
    number: str  # slot/port string kept verbatim, e.g. "0/0/1" — never translated
    description: Optional[str] = None
    ipv4: Optional[IPv4Interface] = None
    shutdown: Optional[bool] = None  # None = not stated in source (do not guess)
    is_virtual: bool = False  # Loopback / Vlanif / Eth-Trunk — number is a name
    # L2 switchport
    port_mode: Optional[str] = None  # "access" | "trunk" | None (not stated)
    access_vlan: Optional[int] = None
    trunk_allowed_vlans: Optional[list[int]] = None  # None = not stated; explicit ids only (no "all")
    stp_edge: Optional[bool] = None
    # Serial
    link_protocol: Optional[str] = None  # "ppp" | "hdlc" | None (not stated: defaults differ -> warn)
    # Interface-level OSPF
    ospf_cost: Optional[int] = None
    ospf_priority: Optional[int] = None
    ospf_network_p2p: Optional[bool] = None
    source_lines: list[int] = Field(default_factory=list)
    field_lines: dict[str, int] = Field(default_factory=dict)  # attribute -> source line
    notes: list[NoteIR] = Field(default_factory=list)

    @property
    def ref(self) -> InterfaceRef:
        return InterfaceRef(if_type=self.if_type, number=self.number)


class VlanIR(BaseModel):
    vlan_id: int
    name: Optional[str] = None
    source_lines: list[int] = Field(default_factory=list)
    field_lines: dict[str, int] = Field(default_factory=dict)
    notes: list[NoteIR] = Field(default_factory=list)


class StaticRouteIR(BaseModel):
    destination: IPv4Network
    next_hop: Optional[IPv4Address] = None
    exit_interface: Optional[InterfaceRef] = None
    # None = not stated; defaults differ (Cisco AD=1, Huawei Preference=60) -> warn, never guess.
    preference: Optional[int] = None
    source_lines: list[int] = Field(default_factory=list)


class OspfNetworkIR(BaseModel):
    address: IPv4Address
    wildcard: IPv4Address
    source_line: Optional[int] = None


class OspfAreaIR(BaseModel):
    area_id: int  # 32-bit area id; Cisco renders decimal, Huawei dotted
    stub: bool = False
    networks: list[OspfNetworkIR] = Field(default_factory=list)
    field_lines: dict[str, int] = Field(default_factory=dict)

    @property
    def dotted(self) -> str:
        return str(IPv4Address(self.area_id))


class OspfIR(BaseModel):
    """Single OSPFv2 process (multi-process is out of scope)."""

    process_id: int
    router_id: Optional[IPv4Address] = None
    areas: list[OspfAreaIR] = Field(default_factory=list)  # kept sorted by area_id
    silent_interfaces: list[InterfaceRef] = Field(default_factory=list)
    default_originate: bool = False
    source_lines: list[int] = Field(default_factory=list)
    field_lines: dict[str, int] = Field(default_factory=dict)
    notes: list[NoteIR] = Field(default_factory=list)

    def area(self, area_id: int) -> OspfAreaIR:
        for a in self.areas:
            if a.area_id == area_id:
                return a
        new = OspfAreaIR(area_id=area_id)
        self.areas.append(new)
        return new


# Fields that record *where* something came from, not *what* the config means.
# Excluded from round-trip comparison (proposal §2.6.2 item 2: compare at IR level).
_NON_INTENT_FIELDS = {
    "source_vendor", "source_lines", "source_line", "field_lines", "warnings", "notes", "comments",
}


def _strip_non_intent(value):
    if isinstance(value, dict):
        return {k: _strip_non_intent(v) for k, v in value.items() if k not in _NON_INTENT_FIELDS}
    if isinstance(value, list):
        return [_strip_non_intent(v) for v in value]
    return value


class DeviceConfigIR(BaseModel):
    source_vendor: Vendor
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    vlans: list[VlanIR] = Field(default_factory=list)  # kept sorted by vlan_id
    interfaces: list[InterfaceIR] = Field(default_factory=list)
    ospf: Optional[OspfIR] = None
    static_routes: list[StaticRouteIR] = Field(default_factory=list)
    field_lines: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    # Free-text source comments (comment-prefix translation only; not config intent).
    comments: list[NoteIR] = Field(default_factory=list)
    # Top-level source lines/blocks no rule represents; rendered as target comments.
    notes: list[NoteIR] = Field(default_factory=list)

    def intent(self) -> dict:
        """Vendor-neutral configuration intent, for round-trip fidelity checks."""
        return _strip_non_intent(self.model_dump(mode="json"))


class RenderedLine(BaseModel):
    """One line of converted output with its mandatory provenance label."""

    text: str
    provenance: Provenance
    category: Optional[SyntaxCategory] = None
    source_line: Optional[int] = None
    is_comment: bool = False
    warning: Optional[str] = None
