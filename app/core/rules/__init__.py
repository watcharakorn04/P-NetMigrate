"""Conversion rules, grouped by risk tier (CLAUDE.md §6).

Handler order matters only where patterns could overlap; tiers are independent today.
"""

from app.core.rules import tier1_interface, tier1_routing, tier1_system, tier1_vlan, tier2_services, tier3_bgp_acl
from app.core.rules.base import BlockHandler

CISCO_HANDLERS: list[BlockHandler] = [
    *tier1_system.CISCO_HANDLERS,
    *tier1_vlan.CISCO_HANDLERS,
    *tier1_interface.CISCO_HANDLERS,
    *tier1_routing.CISCO_HANDLERS,
    *tier2_services.CISCO_HANDLERS,
    *tier3_bgp_acl.CISCO_HANDLERS,
]

HUAWEI_HANDLERS: list[BlockHandler] = [
    *tier1_system.HUAWEI_HANDLERS,
    *tier1_vlan.HUAWEI_HANDLERS,
    *tier1_interface.HUAWEI_HANDLERS,
    *tier1_routing.HUAWEI_HANDLERS,
    *tier2_services.HUAWEI_HANDLERS,
    *tier3_bgp_acl.HUAWEI_HANDLERS,
]
