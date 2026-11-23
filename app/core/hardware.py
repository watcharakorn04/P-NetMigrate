"""Hardware compatibility validation (proposal §2.3.1 module 8).

Pure rules, no AI (8.4): the same input always gives the same verdict.

8.2 Every physical port declared in the configuration is classified:
    * active    — has configuration and is not shut down
    * prepared  — has configuration but is shut down
    * unused    — declared with no configuration at all
    Virtual interfaces (Loopback, Vlanif, Eth-Trunk) are not counted.

8.3 Four outcomes, checked in this order:
    INCOMPATIBLE — active ports exceed the model's ports     -> change model / add a device
    TRIM_UNUSED  — declared ports exceed it, active ones fit -> drop the unused ports, then OK
    RENUMBER     — the count fits, but some port numbers do not exist on the model
    OK           — the count fits and every port exists on the model

The catalogue lists front-panel ports of the base chassis only (no expansion modules). Port
names follow the vendor's own numbering; the system never renumbers ports for the user.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.core.ir import InterfaceIR, Vendor
from app.core.parsers import parse_config
from app.core.rules.interface_names import IF_TYPES, display_name


@dataclass(frozen=True)
class PortGroup:
    if_type: str  # neutral interface type (see interface_names.IF_TYPES)
    prefix: str  # numbering before the last component, e.g. "0/0/" or "1/0/"
    first: int
    last: int

    @property
    def count(self) -> int:
        return self.last - self.first + 1

    def contains(self, if_type: str, number: str) -> bool:
        if if_type != self.if_type or not number.startswith(self.prefix):
            return False
        tail = number[len(self.prefix):]
        return tail.isdigit() and self.first <= int(tail) <= self.last


@dataclass(frozen=True)
class HardwareModel:
    key: str
    vendor: Vendor
    display: str
    kind: str  # router | switch
    groups: tuple[PortGroup, ...]

    @property
    def capacity(self) -> int:
        return sum(g.count for g in self.groups)

    def has_port(self, if_type: str, number: str) -> bool:
        return any(g.contains(if_type, number) for g in self.groups)

    def port_ranges(self) -> list[str]:
        out = []
        for g in self.groups:
            name = display_name_for(g.if_type, self.vendor)
            out.append(f"{name}{g.prefix}{g.first}-{g.last}" if g.count > 1 else f"{name}{g.prefix}{g.first}")
        return out


def display_name_for(if_type: str, vendor: Vendor) -> str:
    return next(t.name_for(vendor) for t in IF_TYPES if t.neutral == if_type)


GE, XGE, FE = "gigabitethernet", "tengigabitethernet", "fastethernet"
_MODELS = [
    # Cisco IOS-XE
    HardwareModel("isr4321", Vendor.CISCO_IOS_XE, "Cisco ISR 4321", "router", (PortGroup(GE, "0/0/", 0, 1),)),
    HardwareModel("isr4331", Vendor.CISCO_IOS_XE, "Cisco ISR 4331", "router", (PortGroup(GE, "0/0/", 0, 2),)),
    HardwareModel("c8200-1n-4t", Vendor.CISCO_IOS_XE, "Cisco Catalyst 8200-1N-4T", "router", (PortGroup(GE, "0/0/", 0, 3),)),
    HardwareModel("c9200l-24t-4g", Vendor.CISCO_IOS_XE, "Cisco Catalyst 9200L-24T-4G", "switch",
                  (PortGroup(GE, "1/0/", 1, 24), PortGroup(GE, "1/1/", 1, 4))),
    HardwareModel("c9300-48t", Vendor.CISCO_IOS_XE, "Cisco Catalyst 9300-48T", "switch",
                  (PortGroup(GE, "1/0/", 1, 48),)),
    # Huawei VRP
    HardwareModel("ar2220", Vendor.HUAWEI_VRP, "Huawei AR2220", "router", (PortGroup(GE, "0/0/", 0, 2),)),
    HardwareModel("ar6120", Vendor.HUAWEI_VRP, "Huawei AR6120", "router", (PortGroup(GE, "0/0/", 0, 9),)),
    HardwareModel("s5735-l24t4x", Vendor.HUAWEI_VRP, "Huawei S5735-L24T4X-A", "switch",
                  (PortGroup(GE, "0/0/", 1, 24), PortGroup(XGE, "0/0/", 1, 4))),
    HardwareModel("s5735-l48t4x", Vendor.HUAWEI_VRP, "Huawei S5735-L48T4X-A", "switch",
                  (PortGroup(GE, "0/0/", 1, 48), PortGroup(XGE, "0/0/", 1, 4))),
]
CATALOG: dict[str, HardwareModel] = {m.key: m for m in _MODELS}


class PortState(str, Enum):
    ACTIVE = "active"
    PREPARED = "prepared"
    UNUSED = "unused"


class Verdict(str, Enum):
    OK = "ok"
    RENUMBER = "renumber"
    TRIM_UNUSED = "trim_unused"
    INCOMPATIBLE = "incompatible"


VERDICT_TEXT = {
    Verdict.OK: ("ใช้ได้เลย", "Compatible — ready to use"),
    Verdict.RENUMBER: ("ต้องย้ายหมายเลขพอร์ตก่อน", "Port count fits, but some port numbers must be moved first"),
    Verdict.TRIM_UNUSED: ("ตัดพอร์ตที่ไม่ได้ใช้ออกแล้วใช้ได้", "Remove the unused ports, then it fits"),
    Verdict.INCOMPATIBLE: ("ใช้กับรุ่นนี้ไม่ได้ ต้องเปลี่ยนรุ่นหรือเพิ่มอุปกรณ์",
                           "Not compatible — choose a larger model or add a device"),
}

# Fields that, when set, mean "this port has configuration" (shutdown alone is not config).
_CONFIG_FIELDS = ("description", "ipv4", "port_mode", "access_vlan", "trunk_allowed_vlans", "stp_edge",
                  "link_protocol", "ospf_cost", "ospf_priority", "ospf_network_p2p", "acl_in", "acl_out")


def port_state(iface: InterfaceIR) -> PortState:
    configured = any(getattr(iface, f) not in (None, False) for f in _CONFIG_FIELDS) or bool(iface.notes)
    if iface.shutdown is True:
        return PortState.PREPARED if configured else PortState.UNUSED
    if configured or iface.shutdown is False:  # explicit `no shutdown` / `undo shutdown`
        return PortState.ACTIVE
    return PortState.UNUSED


def classify_ports(config: str, vendor: Vendor) -> list[dict]:
    """Physical ports of a configuration with their 8.2 state (virtual interfaces skipped)."""
    ir = parse_config(config, vendor).ir
    return [
        {"name": display_name(i.ref, vendor), "if_type": i.if_type, "number": i.number, "state": port_state(i).value}
        for i in ir.interfaces
        if not i.is_virtual
    ]


def check_compatibility(config: str, vendor: Vendor, model_key: str) -> dict:
    model = CATALOG.get(model_key)
    if model is None:
        raise ValueError("unknown hardware model")
    if model.vendor is not vendor:
        raise ValueError("the configuration vendor and the model vendor differ")
    ports = classify_ports(config, vendor)
    for p in ports:
        p["exists"] = model.has_port(p["if_type"], p["number"])
    active = sum(1 for p in ports if p["state"] == "active")
    prepared = sum(1 for p in ports if p["state"] == "prepared")
    unused = sum(1 for p in ports if p["state"] == "unused")
    declared = len(ports)
    capacity = model.capacity
    out_of_range = [p["name"] for p in ports if not p["exists"]]

    if active > capacity:
        verdict = Verdict.INCOMPATIBLE
    elif declared > capacity:
        verdict = Verdict.TRIM_UNUSED
    elif out_of_range:
        verdict = Verdict.RENUMBER
    else:
        verdict = Verdict.OK

    th, en = VERDICT_TEXT[verdict]
    return {
        "model": {"key": model.key, "display": model.display, "vendor": model.vendor.value, "kind": model.kind,
                  "capacity": capacity, "ranges": model.port_ranges()},
        "verdict": verdict.value,
        "verdict_th": th,
        "verdict_en": en,
        "capacity": capacity,
        "declared": declared,
        "active": active,
        "prepared": prepared,
        "unused": unused,
        "out_of_range": out_of_range,
        "trim_candidates": [p["name"] for p in ports if p["state"] != "active"] if verdict is Verdict.TRIM_UNUSED else [],
        "shortfall": max(0, active - capacity),
        "ports": ports,
    }


def catalog_json(vendor: Optional[Vendor] = None) -> list[dict]:
    return [
        {"key": m.key, "display": m.display, "vendor": m.vendor.value, "kind": m.kind, "capacity": m.capacity,
         "ranges": m.port_ranges()}
        for m in _MODELS
        if vendor is None or m.vendor is vendor
    ]
