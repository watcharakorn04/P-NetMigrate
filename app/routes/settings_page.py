"""Module 6 — System Settings, API health and rule-coverage matrix."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.core.ir import Vendor
from app.core.prescan import prescan_config
from app.db import Database
from app.deps import get_db
from app.web import ASSET_VERSION, render_page

router = APIRouter()
C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP

# Rule groups by risk tier (CLAUDE.md §6) with a representative probe per direction; the
# matrix is computed live by running the pre-scan on each probe, so it reflects the rules
# actually installed. "Not supported" lists follow proposal §2.3.2 item 3.
COVERAGE_GROUPS = [
    (1, "cov_system", "hostname R1\nip domain name lab.local\n", "sysname R1\ndns domain lab.local\n", ""),
    (1, "cov_vlan_port",
     "vlan 10\n name USERS\ninterface GigabitEthernet0/0/1\n switchport mode access\n switchport access vlan 10\n spanning-tree portfast\n",
     "vlan 10\n description USERS\ninterface GigabitEthernet0/0/1\n port link-type access\n port default vlan 10\n stp edged-port enable\n",
     "port link-type hybrid · vlan 10,20 + name"),
    (1, "cov_interface",
     "interface GigabitEthernet0/0/0\n description WAN\n ip address 10.0.0.1 255.255.255.252\n no shutdown\ninterface Serial0/1/0\n encapsulation ppp\n",
     "interface GigabitEthernet0/0/0\n description WAN\n ip address 10.0.0.1 255.255.255.252\n undo shutdown\ninterface Serial0/1/0\n link-protocol ppp\n",
     "Clock Rate · Channelization · Frame Relay · Tunnel/ATM"),
    (1, "cov_static", "ip route 10.1.0.0 255.255.0.0 10.0.0.2\n", "ip route-static 10.1.0.0 255.255.0.0 10.0.0.2\n",
     "ip route … name X"),
    (1, "cov_ospf",
     "router ospf 1\n router-id 1.1.1.1\n network 10.0.0.0 0.0.0.3 area 0\n area 1 stub\n network 10.1.0.0 0.0.0.255 area 1\n",
     "ospf 1 router-id 1.1.1.1\n area 0.0.0.0\n  network 10.0.0.0 0.0.0.3\n area 0.0.0.1\n  stub\n  network 10.1.0.0 0.0.0.255\n",
     "Multi-process · NSSA · Virtual link · ABR summarization · Authentication · Timers · no-summary"),
    (2, "cov_rip", "router rip\n version 2\n network 10.0.0.0\n", "rip 1\n version 2\n network 10.0.0.0\n",
     "Authentication · Timers · >1 process"),
    (2, "cov_redistribute",
     "router ospf 1\n redistribute static metric 20 subnets\n", "ospf 1\n import-route static cost 20\n",
     "Route-Map / Route-Policy · no explicit metric"),
    (2, "cov_services", "ntp server 10.9.9.1\nlogging host 10.9.9.2\nline vty 0 4\n login local\n transport input ssh\n",
     "ntp-service unicast-server 10.9.9.1\ninfo-center loghost 10.9.9.2\nuser-interface vty 0 4\n authentication-mode aaa\n protocol inbound ssh\n",
     "User-account commands (never converted)"),
    (3, "cov_bgp", "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002\n network 1.1.1.1 mask 255.255.255.255\n",
     "bgp 65001\n peer 10.0.0.2 as-number 65002\n ipv4-family unicast\n  network 1.1.1.1 255.255.255.255\n  peer 10.0.0.2 enable\n",
     "Peer group · Route reflector · Confederation · Route filtering · Other AFs"),
    (3, "cov_acl",
     "access-list 10 permit 10.1.1.0 0.0.0.255\nip access-list extended WEB\n permit tcp any host 10.0.0.10 eq 443\ninterface GigabitEthernet0/0/0\n ip access-group WEB in\n",
     "acl number 2000\n rule 5 permit source 10.1.1.0 0.0.0.255\nacl name WEB advance\n rule 5 permit tcp destination 10.0.0.10 0 destination-port eq 443\ninterface GigabitEthernet0/0/0\n traffic-filter inbound acl name WEB\n",
     "L2 ACL · Time range · User-defined · Huawei 2800–2999 / 3800–3999"),
]


def mask_key(key: str) -> str:
    """Never show the key: only its length class and last 4 characters (when long enough)."""
    key = key.strip()
    if not key:
        return ""
    return "••••••••" + (key[-4:] if len(key) >= 16 else "")


def coverage_matrix() -> list[dict]:
    rows = []
    for tier, key, cisco, huawei, unsupported in COVERAGE_GROUPS:
        c2h = prescan_config(cisco, C, H).coverage_percent
        h2c = prescan_config(huawei, H, C).coverage_percent
        rows.append({"tier": tier, "key": key, "c2h": c2h, "h2c": h2c, "unsupported": unsupported})
    return rows


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, settings: Settings = Depends(get_settings),
                  db: Database = Depends(get_db)) -> Response:
    with db.connect() as conn:
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                  for t in ("conversions", "devices", "deployments")}
    return render_page(
        request, "settings.html", "nav_m6", settings,
        llm={
            "configured": settings.llm_api_key_configured,
            "masked_key": mask_key(settings.llm_api_key),
            "model": settings.llm_model,
            "base_url": settings.llm_api_base_url,
            "timeout": settings.llm_timeout_seconds,
            "complex": settings.complex_command_prefixes,
        },
        coverage=coverage_matrix(),
        db_info={"path": str(db.path), "counts": counts},
        version=ASSET_VERSION,
    )


@router.get("/api/settings/coverage")
def api_coverage() -> dict:
    return {"groups": coverage_matrix()}
