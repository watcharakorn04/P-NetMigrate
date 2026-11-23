"""Module 3 (inventory register) and module 8 (hardware compatibility — pure rules)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.hardware import CATALOG, Verdict, check_compatibility, classify_ports
from app.core.ir import Vendor
from app.deps import get_translator
from app.main import app

C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


def hua_ports(*specs: tuple[str, str]) -> str:
    """specs: (name, kind) kind = active | prepared | unused."""
    out = []
    for name, kind in specs:
        out.append(f"interface {name}")
        if kind == "active":
            out.append(" description link")
        elif kind == "prepared":
            out += [" description spare", " shutdown"]
        out.append("#")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- module 8


class TestPortClassification:
    def test_three_states_and_virtual_excluded(self):
        cfg = hua_ports(("GigabitEthernet0/0/1", "active"), ("GigabitEthernet0/0/2", "prepared"),
                        ("GigabitEthernet0/0/3", "unused")) + "interface LoopBack0\n ip address 1.1.1.1 32\n#\ninterface Vlanif10\n ip address 10.0.0.1 24\n"
        states = {p["name"]: p["state"] for p in classify_ports(cfg, H)}
        assert states == {"GigabitEthernet0/0/1": "active", "GigabitEthernet0/0/2": "prepared", "GigabitEthernet0/0/3": "unused"}

    def test_cisco_undo_states(self):
        cfg = "interface GigabitEthernet0/0/0\n no shutdown\ninterface GigabitEthernet0/0/1\n shutdown\ninterface GigabitEthernet0/0/2\n ip address 10.0.0.1 255.255.255.0\n shutdown\n"
        states = {p["name"]: p["state"] for p in classify_ports(cfg, C)}
        assert states == {"GigabitEthernet0/0/0": "active", "GigabitEthernet0/0/1": "unused", "GigabitEthernet0/0/2": "prepared"}


class TestFourVerdicts:
    """Proposal §2.3.1 8.3 / §2.6 item 8: four cases with known answers."""

    def test_ok(self):
        cfg = hua_ports(("GigabitEthernet0/0/1", "active"), ("GigabitEthernet0/0/2", "prepared"), ("XGigabitEthernet0/0/1", "active"))
        r = check_compatibility(cfg, H, "s5735-l24t4x")
        assert r["verdict"] == Verdict.OK.value and r["verdict_th"] == "ใช้ได้เลย"
        assert (r["active"], r["prepared"], r["unused"], r["capacity"]) == (2, 1, 0, 28)

    def test_renumber_when_count_fits_but_numbers_do_not_exist(self):
        cfg = hua_ports(("GigabitEthernet1/0/1", "active"), ("GigabitEthernet0/0/30", "active"))
        r = check_compatibility(cfg, H, "s5735-l24t4x")
        assert r["verdict"] == "renumber" and r["verdict_th"] == "ต้องย้ายหมายเลขพอร์ตก่อน"
        assert r["out_of_range"] == ["GigabitEthernet1/0/1", "GigabitEthernet0/0/30"]

    def test_trim_unused_when_declared_exceeds_but_active_fits(self):
        cfg = hua_ports(("GigabitEthernet0/0/0", "active"), ("GigabitEthernet0/0/1", "active"),
                        ("GigabitEthernet0/0/2", "unused"), ("GigabitEthernet0/0/3", "unused"), ("GigabitEthernet0/0/4", "prepared"))
        r = check_compatibility(cfg, H, "ar2220")
        assert r["verdict"] == "trim_unused" and r["verdict_th"] == "ตัดพอร์ตที่ไม่ได้ใช้ออกแล้วใช้ได้"
        assert r["declared"] == 5 and r["capacity"] == 3
        assert set(r["trim_candidates"]) == {"GigabitEthernet0/0/2", "GigabitEthernet0/0/3", "GigabitEthernet0/0/4"}

    def test_incompatible_when_active_exceeds(self):
        cfg = hua_ports(*[(f"GigabitEthernet0/0/{i}", "active") for i in range(4)])
        r = check_compatibility(cfg, H, "ar2220")
        assert r["verdict"] == "incompatible" and r["shortfall"] == 1
        assert r["verdict_th"] == "ใช้กับรุ่นนี้ไม่ได้ ต้องเปลี่ยนรุ่นหรือเพิ่มอุปกรณ์"

    def test_deterministic(self):
        cfg = hua_ports(("GigabitEthernet0/0/1", "active"))
        assert check_compatibility(cfg, H, "s5735-l24t4x") == check_compatibility(cfg, H, "s5735-l24t4x")

    def test_vendor_mismatch_and_unknown_model(self):
        with pytest.raises(ValueError):
            check_compatibility("hostname R1\n", C, "ar2220")
        with pytest.raises(ValueError):
            check_compatibility("hostname R1\n", C, "nope")

    def test_catalog_ranges(self):
        assert CATALOG["c9200l-24t-4g"].capacity == 28
        assert CATALOG["c9200l-24t-4g"].has_port("gigabitethernet", "1/1/4")
        assert not CATALOG["c9200l-24t-4g"].has_port("gigabitethernet", "1/1/5")
        assert CATALOG["s5735-l24t4x"].port_ranges() == ["GigabitEthernet0/0/1-24", "XGigabitEthernet0/0/1-4"]


class TestHardwareApi:
    def test_check_with_pasted_config_and_model(self, client):
        r = client.post("/api/hardware/check", data={"config": hua_ports(("GigabitEthernet0/0/1", "active")),
                                                     "vendor": "huawei_vrp", "model": "s5735-l24t4x"})
        assert r.status_code == 200 and r.json()["verdict"] == "ok"

    def test_check_history_output_against_inventory_device(self, client):
        conv = client.post("/api/convert", data={"direction": "c2h", "mode": "rule_only",
                                                 "config": "interface GigabitEthernet1/0/5\n description users\n"}).json()
        dev = client.post("/api/devices", json={"name": "SW1", "ip": "192.0.2.5", "vendor": "huawei_vrp", "model": "s5735-l24t4x"}).json()
        r = client.post("/api/hardware/check", data={"conversion_id": conv["history_id"], "device_id": dev["id"]}).json()
        # port numbers are never translated: Gi1/0/5 stays 1/0/5, which the S5735 does not have
        assert r["verdict"] == "renumber" and r["device"]["name"] == "SW1"

    def test_errors(self, client):
        assert client.post("/api/hardware/check", data={"config": "x", "vendor": "huawei_vrp"}).status_code == 422
        assert client.post("/api/hardware/check", data={"config": "", "vendor": "huawei_vrp", "model": "ar2220"}).status_code == 422
        assert client.post("/api/hardware/check", data={"config": "x", "vendor": "cisco_ios_xe", "model": "ar2220"}).status_code == 422
        dev = client.post("/api/devices", json={"name": "N", "ip": "192.0.2.9", "vendor": "huawei_vrp"}).json()
        assert client.post("/api/hardware/check", data={"config": "x", "vendor": "huawei_vrp", "device_id": dev["id"]}).status_code == 422
        assert client.get("/api/hardware/catalog?vendor=huawei_vrp").json()["items"][0]["vendor"] == "huawei_vrp"

    def test_page(self, client):
        assert "Hardware Compatibility Validation" in client.get("/hardware?lang=en").text
        assert "Huawei S5735-L24T4X-A" in client.get("/hardware?lang=th").text


# ----------------------------------------------------------------------------- module 3


class TestInventory:
    def test_crud(self, client):
        r = client.post("/api/devices", json={"name": "CORE-1", "ip": "192.0.2.1", "vendor": "cisco_ios_xe",
                                              "os_version": "17.9", "model": "c9300-48t", "location": "BKK DC", "ssh_port": 22})
        assert r.status_code == 201
        dev = r.json()
        assert dev["model_name"] == "Cisco Catalyst 9300-48T" and dev["status"] == "active"
        upd = client.put(f"/api/devices/{dev['id']}", json={**{k: dev[k] for k in ("name", "ip", "vendor", "os_version", "model", "ssh_port", "location")}, "status": "maintenance"})
        assert upd.json()["status"] == "maintenance"
        assert client.get(f"/api/devices/{dev['id']}").json()["status"] == "maintenance"
        assert client.delete(f"/api/devices/{dev['id']}").status_code == 200
        assert client.get(f"/api/devices/{dev['id']}").status_code == 404
        assert client.delete(f"/api/devices/{dev['id']}").status_code == 404

    def test_search_and_filter(self, client):
        for name, ip, vendor, loc in [("CORE-1", "192.0.2.1", "cisco_ios_xe", "Bangkok"),
                                      ("ACC-7", "198.51.100.7", "huawei_vrp", "Chiang Mai"),
                                      ("EDGE-2", "192.0.2.2", "huawei_vrp", "Bangkok")]:
            client.post("/api/devices", json={"name": name, "ip": ip, "vendor": vendor, "location": loc})
        names = lambda q: [d["name"] for d in client.get("/api/devices" + q).json()["items"]]
        assert names("?q=core") == ["CORE-1"]
        assert names("?q=198.51") == ["ACC-7"]
        assert names("?vendor=huawei_vrp") == ["ACC-7", "EDGE-2"]
        assert names("?location=bangkok") == ["CORE-1", "EDGE-2"]
        assert names("?q=chiang") == ["ACC-7"]

    @pytest.mark.parametrize("patch", [
        {"ip": "999.1.1.1"}, {"ip": "2001:db8::1"}, {"vendor": "juniper"}, {"ssh_port": 0},
        {"status": "broken"}, {"name": ""}, {"model": "ar2220"},  # Huawei model on a Cisco device
    ])
    def test_validation(self, client, patch):
        data = {"name": "X", "ip": "192.0.2.3", "vendor": "cisco_ios_xe", **patch}
        assert client.post("/api/devices", json=data).status_code == 422

    def test_no_credentials_accepted_or_stored(self, client, db):
        r = client.post("/api/devices", json={"name": "X", "ip": "192.0.2.3", "vendor": "cisco_ios_xe",
                                              "password": "DoNotStoreMe1", "username": "nobody77"})
        assert r.status_code == 201
        assert "DoNotStoreMe1" not in r.text and "nobody77" not in r.text
        dump = b"".join(p.read_bytes() for p in db.path.parent.glob(db.path.name + "*")).decode("utf-8", "ignore")
        assert "DoNotStoreMe1" not in dump and "nobody77" not in dump

    def test_page(self, client):
        assert "Device Inventory" in client.get("/inventory?lang=en").text
        assert "ทะเบียนอุปกรณ์" in client.get("/inventory?lang=th").text
