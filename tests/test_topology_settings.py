"""Module 7 (topology + advisory) and module 6 (settings / health / coverage matrix)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.advisory import advise, advise_sections
from app.core.ir import Vendor
from app.core.secret_stripper import contains_secret
from app.core.topology import TopologyInput, analyze
from app.deps import get_translator
from app.main import app
from app.routes.settings_page import COVERAGE_GROUPS, coverage_matrix, mask_key
from tests.test_ai_hybrid import API_KEY, CISCO_SECRETS, FakeLLM

FIXTURES = Path(__file__).parent / "fixtures"

CORE = """hostname CORE1
vlan 10
 name USERS
vlan 20
 name VOICE
interface GigabitEthernet1/0/1
 description to-ACC1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
interface GigabitEthernet1/0/24
 ip address 10.0.12.1 255.255.255.252
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
router ospf 1
 network 10.0.12.0 0.0.0.3 area 0
 network 192.168.10.0 0.0.0.255 area 0
username admin secret 9 $9$TopoSecretHash
"""
EDGE = """sysname EDGE1
#
interface GigabitEthernet0/0/1
 ip address 10.0.12.2 255.255.255.252
#
interface GigabitEthernet0/0/2
 ip address 203.0.113.1 255.255.255.252
#
ospf 1
 area 0.0.0.0
  network 10.0.12.0 0.0.0.3
#
bgp 65001
 peer 10.0.12.1 as-number 65001
#
return
"""
ACC = """hostname ACC1
vlan 10
vlan 20
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 20
interface GigabitEthernet1/0/3
 shutdown
interface GigabitEthernet1/1/1
 description uplink CORE1
 switchport mode trunk
 switchport trunk allowed vlan 10,20
"""


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


def topo():
    return analyze([TopologyInput("core.txt", CORE), TopologyInput("edge.cfg", EDGE), TopologyInput("acc.txt", ACC)])


class TestTopologyRules:
    def test_devices_vendors_and_roles(self):
        r = topo()
        devs = {d["name"]: d for d in r["devices"]}
        assert set(devs) == {"CORE1", "EDGE1", "ACC1"}
        assert devs["EDGE1"]["vendor"] == "huawei_vrp" and devs["CORE1"]["vendor"] == "cisco_ios_xe"
        assert devs["EDGE1"]["role"] == "edge_router"
        assert devs["ACC1"]["role"] == "access_switch"
        assert devs["CORE1"]["protocols"] == ["OSPF"]

    def test_shared_subnet_link_with_protocols(self):
        r = topo()
        names = [d["name"] for d in r["devices"]]
        l3 = [l for l in r["links"] if l["kind"] == "l3"]
        assert len(l3) == 1
        link = l3[0]
        assert {names[link["a"]], names[link["b"]]} == {"CORE1", "EDGE1"} and link["subnet"] == "10.0.12.0/30"
        assert "OSPF" in link["protocols"]  # both ends' network statements cover the subnet

    def test_bgp_neighbor_on_shared_subnet_is_added_to_that_link(self):
        r = topo()
        # EDGE1 peers 10.0.12.1 (CORE1's address on the shared /30): no separate edge is drawn,
        # BGP is listed on the existing L3 link.
        l3 = next(l for l in r["links"] if l["kind"] == "l3")
        assert "BGP" in l3["protocols"]
        assert not [l for l in r["links"] if l["kind"] == "bgp"]

    def test_description_link_and_port_roles(self):
        r = topo()
        names = [d["name"] for d in r["devices"]]
        desc = [l for l in r["links"] if l["kind"] == "description"]
        assert len(desc) == 1 and {names[desc[0]["a"]], names[desc[0]["b"]]} == {"CORE1", "ACC1"}
        acc = next(d for d in r["devices"] if d["name"] == "ACC1")
        roles = {p["name"]: p["role"] for p in acc["ports"]}
        assert roles == {"GigabitEthernet1/0/1": "access", "GigabitEthernet1/0/2": "access",
                         "GigabitEthernet1/0/3": "unused", "GigabitEthernet1/1/1": "uplink"}
        edge = next(d for d in r["devices"] if d["name"] == "EDGE1")
        assert {p["name"]: p["role"] for p in edge["ports"]}["GigabitEthernet0/0/2"] == "routed"

    def test_vlan_reach(self):
        r = topo()
        names = [d["name"] for d in r["devices"]]
        v10 = next(v for v in r["vlans"] if v["id"] == 10)
        assert {names[i] for i in v10["devices"]} == {"CORE1", "ACC1"} and v10["name"] == "USERS"

    def test_no_secret_in_result(self):
        r = topo()
        r.pop("_irs")
        assert "$9$TopoSecretHash" not in json.dumps(r) and "admin" not in json.dumps(r)


class TestAdvisory:
    def test_three_levels_cumulative_both_vendors(self):
        r = topo()
        acc_idx = next(i for i, d in enumerate(r["devices"]) if d["name"] == "ACC1")
        ir = r["_irs"][acc_idx]
        uplinks = {"GigabitEthernet1/1/1"}
        l1, l3 = advise(ir, uplinks, 1), advise(ir, uplinks, 3)
        for vendor in ("cisco_ios_xe", "huawei_vrp"):
            assert set(l1[vendor]).issubset(set(l3[vendor]))
        c, h = l3["cisco_ios_xe"], l3["huawei_vrp"]
        # level 1: VLAN, port mode, management
        assert "switchport access vlan 10" in [x.strip() for x in c] and "port default vlan 10" in [x.strip() for x in h]
        assert "transport input ssh" in [x.strip() for x in c] and "stelnet server enable" in h
        # level 2: QoS on access + uplink
        assert "policy-map NM-ACCESS-MARK" in c and "traffic policy NM-ACCESS-MARK" in h
        assert " qos lr outbound cir 100000" in h
        # level 3: security — port-security, root guard, DHCP snooping trust on uplink, shut unused
        assert " switchport port-security maximum 2" in c and " port-security max-mac-num 2" in h
        assert " spanning-tree guard root" in c and " stp root-protection" in h
        assert "interface GigabitEthernet1/1/1" in c and " ip dhcp snooping trust" in c and " dhcp snooping trusted" in h
        i = c.index("interface GigabitEthernet1/0/3", c.index("ip dhcp snooping vlan 10,20"))
        assert c[i + 1] == " shutdown"

    def test_port_numbers_never_translated_and_no_credentials(self):
        r = topo()
        for ir in r["_irs"]:
            for vendor, lines in advise(ir, set(), 3).items():
                assert not any(contains_secret(l) for l in lines if "[" not in l), vendor
        core = r["_irs"][0]
        h = advise(core, set(), 1)["huawei_vrp"]
        assert "interface GigabitEthernet1/0/24" in h  # 1/0/24 kept verbatim

    def test_inter_subnet_acl_from_vlanifs(self):
        core = topo()["_irs"][0]
        sec = advise_sections(core, set())[3]
        assert any("deny ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255" in l for l in sec["cisco_ios_xe"])
        assert any("source 192.168.10.0 0.0.0.255 destination 192.168.20.0 0.0.0.255" in l for l in sec["huawei_vrp"])

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            advise(topo()["_irs"][0], set(), 4)


class TestTopologyApi:
    def test_analyze_upload(self, client):
        files = [("files", ("core.txt", CORE.encode(), "text/plain")), ("files", ("edge.cfg", EDGE.encode(), "text/plain")),
                 ("files", ("acc.txt", ACC.encode(), "text/plain"))]
        r = client.post("/api/topology/analyze", files=files)
        assert r.status_code == 200
        body = r.json()
        assert len(body["devices"]) == 3 and "_irs" not in body
        assert set(body["devices"][0]["advisory"]) == {"1", "2", "3"}
        assert "$9$TopoSecretHash" not in r.text

    def test_analyze_rejects_empty(self, client):
        r = client.post("/api/topology/analyze", files=[("files", ("x.bin", b"\x00\x01", "application/octet-stream"))])
        assert r.status_code == 422

    def test_describe_without_ai(self, client):
        assert client.post("/api/topology/describe", json={"summary": {"devices": []}}).json() == {"available": False, "text": None}

    def test_describe_with_ai_sends_no_secret(self, client):
        llm = FakeLLM(lambda p: {"text": "CORE1 is the distribution switch."})
        app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=API_KEY, _env_file=None)
        app.dependency_overrides[get_translator] = llm.translator
        files = [("files", ("core.txt", CORE.encode(), "text/plain")), ("files", ("edge.cfg", EDGE.encode(), "text/plain"))]
        summary = client.post("/api/topology/analyze", files=files).json()["summary"]
        r = client.post("/api/topology/describe", json={"summary": summary, "lang": "en"}).json()
        assert r["text"] == "CORE1 is the distribution switch." and r["label"] == "มาจาก AI ต้องตรวจสอบก่อนใช้"
        assert "$9$TopoSecretHash" not in llm.sent and API_KEY not in llm.sent

    def test_describe_refuses_credential_like_summary(self, client):
        llm = FakeLLM(lambda p: {"text": "x"})
        app.dependency_overrides[get_translator] = llm.translator
        r = client.post("/api/topology/describe", json={"summary": {"note": "enable secret 5 abc"}}).json()
        assert r.get("error") is True and llm.requests == []

    def test_page(self, client):
        assert "Topology Analysis" in client.get("/topology?lang=en").text
        assert "วิเคราะห์โทโพโลยี" in client.get("/topology?lang=th").text


# ----------------------------------------------------------------------------- settings


class TestSettings:
    def test_mask_key(self):
        assert mask_key("") == ""
        assert mask_key("short") == "••••••••"
        assert mask_key("sk-test-NeverLeakThisKey") == "••••••••sKey"

    def test_page_masks_key_and_shows_matrix(self, client):
        app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=API_KEY, _env_file=None)
        html = client.get("/settings?lang=en").text
        assert API_KEY not in html and "NeverLeak" not in html
        assert "••••••••sKey" in html and "gpt-4o-mini" in html
        for _, key, *_ in COVERAGE_GROUPS:
            assert f'data-coverage-row="{key}"' in html
        assert "Tier 1" in html and "Tier 3" in html

    def test_page_without_key(self, client):
        html = client.get("/settings?lang=th").text
        assert "ยังไม่ได้ตั้งค่า" in html and 'id="masked-key"' not in html

    def test_coverage_matrix_is_live_and_full_for_supported_groups(self):
        rows = coverage_matrix()
        assert [r["tier"] for r in rows] == sorted(r["tier"] for r in rows)
        assert {r["tier"] for r in rows} == {1, 2, 3}
        for r in rows:
            assert r["c2h"] == 100.0 and r["h2c"] == 100.0, r["key"]

    def test_coverage_api(self, client):
        assert len(client.get("/api/settings/coverage").json()["groups"]) == len(COVERAGE_GROUPS)

    def test_health_still_never_echoes_key(self, client):
        app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=API_KEY, _env_file=None)
        assert API_KEY not in client.get("/api/health").text


class TestEveryPageBilingual:
    @pytest.mark.parametrize("path", ["/", "/batch", "/inventory", "/deploy", "/history", "/settings", "/topology", "/hardware"])
    def test_renders_both_languages_with_no_raw_keys(self, client, path):
        import re
        for lang in ("th", "en"):
            resp = client.get(f"{path}?lang={lang}")
            assert resp.status_code == 200
            body = re.sub(r"<script>window\.NM_I18N.*?</script>", "", resp.text, flags=re.S)
            # an unknown t('key') renders the bare key: none may leak into the page
            leaked = re.findall(r">\s*((?:nav|batch|inv|dep|hw|topo|adv|set|dash|diff|history|cov|role|port)_[a-z0-9_]+)\s*<", body)
            assert not leaked, leaked
