"""Module 4 — deployment guardrails (Security Non-Negotiable #3). Never weaken these tests.

Netmiko is replaced by a fake: no test ever opens a socket.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.engine import convert
from app.core.ir import ConversionMode, Provenance, Vendor
from app.core.prescan import prescan_config
from app.deps import get_translator
from app.main import app
from app.services import deploy_service as deploy
from app.services import history_service as history
from tests.test_ai_hybrid import FakeLLM, echo_items

FIXTURES = Path(__file__).parent / "fixtures"
C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP
SSH_USER, SSH_PASS = "eveadmin-UniqueUser", "EveLabPass-Unique-7731"


class FakeConn:
    instances: list["FakeConn"] = []

    def __init__(self, **params):
        self.params = dict(params)
        self.sent: list[str] = []
        FakeConn.instances.append(self)

    def send_config_set(self, commands):
        self.sent.extend(commands)
        return "\n".join(commands)

    def save_config(self):
        return "ok"

    def disconnect(self):
        pass


@pytest.fixture(autouse=True)
def fake_netmiko(monkeypatch):
    FakeConn.instances = []
    monkeypatch.setattr(deploy, "ConnectHandler", FakeConn)
    yield


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


def L(text, prov="RULE", comment=False):
    return {"text": text, "provenance": prov, "is_comment": comment}


def wait(job, timeout=5.0):
    end = time.time() + timeout
    while not job.done and time.time() < end:
        time.sleep(0.01)
    assert job.done


def add_device(client, **kw):
    data = {"name": "EVE-R1", "ip": "192.0.2.11", "vendor": "huawei_vrp", "ssh_port": 2222}
    data.update(kw)
    r = client.post("/api/devices", json=data)
    assert r.status_code == 201, r.text
    return r.json()


def ai_record(db) -> int:
    """A hybrid conversion with AI-labelled lines, stored in history."""
    text = "hostname R1\nip http server\ninterface GigabitEthernet0/0/1\n speed 100\nipv6 unicast-routing\n"
    llm = FakeLLM(echo_items())
    result = convert(text, C, H, mode=ConversionMode.HYBRID, translator=llm.translator())
    assert result.ai_line_count > 0
    return history.record_conversion(db, text, result, prescan_config(text, C, H))


# ----------------------------------------------------------------------------- filtering


class TestPlanFiltering:
    def test_removes_comments_ai_unconverted_and_credentials(self):
        plan = deploy.build_plan([
            L("sysname R1"),
            L("# [มาจากกฎ] header", comment=True),
            L("! a cisco comment"),
            L("AI-ip http server", "AI"),
            L("# [มาจาก AI ต้องตรวจสอบก่อนใช้] translated", "AI", comment=True),
            L("# [แปลงไม่ได้] ipv6 unicast-routing", "UNCONVERTED", comment=True),
            L("ipv6 something raw", "UNCONVERTED"),
            L("local-user admin password irreversible-cipher Hush123"),
            L("snmp-agent community read PubComm"),
            L(" ipv4-family unicast", "SYSTEM"),
            L("return"),
        ], H)
        assert plan.commands == ["sysname R1", " ipv4-family unicast"]
        reasons = [r["reason"] for r in plan.removed]
        assert reasons.count(deploy.R_COMMENT) == 2
        assert reasons.count(deploy.R_AI) == 2 and reasons.count(deploy.R_UNCONVERTED) == 2
        assert reasons.count(deploy.R_SECRET) == 2 and reasons.count(deploy.R_TERMINATOR) == 1
        assert plan.ai_review_count == 1 and plan.requires_review_ack
        dumped = json.dumps(plan.to_json())
        assert "Hush123" not in dumped and "PubComm" not in dumped and "admin" not in dumped

    def test_pasted_text_strips_comments_and_secrets(self):
        plan = deploy.plan_from_text("hostname R1\n!\nusername bob secret 9 $9$x\nenable secret Zz\nend\n", C)
        assert plan.commands == ["hostname R1"]
        assert not plan.requires_review_ack

    def test_final_refilter_blocks_ai_text_pasted_back(self):
        commands, removed = deploy.final_commands("sysname R1\nAI-ip http server\n# c\nsuper password cipher X1\n",
                                                  H, blocked_texts=["AI-ip http server"])
        assert commands == ["sysname R1"]
        assert {r["reason"] for r in removed} == {deploy.R_AI, deploy.R_COMMENT, deploy.R_SECRET}

    def test_every_provenance_is_considered(self):
        for p in Provenance:
            plan = deploy.build_plan([L("x command", p.name)], H)
            assert (plan.commands == ["x command"]) == p.deployable


# ----------------------------------------------------------------------------- API guardrails


class TestDeployApi:
    def test_plan_from_history_record(self, client, db):
        rid = ai_record(db)
        plan = client.post("/api/deploy/plan", json={"conversion_id": rid}).json()
        assert plan["requires_review_ack"] is True and plan["ai_review_count"] >= 1
        assert not any(c.startswith("AI-") or c.lstrip().startswith("AI-") for c in plan["commands"])
        assert not any(c.lstrip().startswith("#") for c in plan["commands"])
        assert "sysname R1" in plan["commands"]

    def test_confirmation_required(self, client):
        r = client.post("/api/deploy/run", json={"vendor": "huawei_vrp", "commands": "sysname R1"})
        assert r.status_code == 400

    def test_ai_lines_block_without_acknowledgement(self, client, db):
        rid = ai_record(db)
        plan = client.post("/api/deploy/plan", json={"conversion_id": rid}).json()
        base = {"vendor": "huawei_vrp", "commands": "\n".join(plan["commands"]), "conversion_id": rid, "confirm": True}
        assert client.post("/api/deploy/run", json=base).status_code == 409
        ok = client.post("/api/deploy/run", json={**base, "acknowledge_review": True})
        assert ok.status_code == 200

    def test_ai_line_reinserted_by_user_is_still_stripped(self, client, db):
        rid = ai_record(db)
        rec = history.get_conversion(db, rid)
        ai_text = next(l["text"] for l in rec["lines"] if l["provenance"] == "AI" and not l["is_comment"])
        body = {"vendor": "huawei_vrp", "commands": "sysname R1\n" + ai_text, "conversion_id": rid,
                "confirm": True, "acknowledge_review": True}
        res = client.post("/api/deploy/run", json=body).json()
        assert res["commands"] == ["sysname R1"]
        assert any(r["reason"] == "ai_review" for r in res["removed"])

    def test_simulation_is_default_and_contacts_nothing(self, client):
        res = client.post("/api/deploy/run", json={"vendor": "huawei_vrp", "commands": "sysname R1\nvlan 10", "confirm": True}).json()
        assert res["mode"] == "simulation"
        job = deploy.get_job(res["job_id"])
        wait(job)
        assert FakeConn.instances == []
        assert job.status == "success"
        levels = [e["level"] for e in job.logs]
        assert levels.count("COMMAND") == 2 and "SUCCESS" in levels

    def test_sse_stream(self, client):
        res = client.post("/api/deploy/run", json={"vendor": "cisco_ios_xe", "commands": "hostname R1", "confirm": True}).json()
        wait(deploy.get_job(res["job_id"]))
        with client.stream("GET", f"/api/deploy/jobs/{res['job_id']}/events") as s:
            assert s.headers["content-type"].startswith("text/event-stream")
            text = "".join(s.iter_text())
        assert "event: log" in text and "event: done" in text and '"level": "COMMAND"' in text
        assert client.get("/api/deploy/jobs/nope/events").status_code == 404

    def test_live_requires_inventory_device_lab_confirm_and_credentials(self, client):
        base = {"vendor": "huawei_vrp", "commands": "sysname R1", "confirm": True, "mode": "live"}
        assert client.post("/api/deploy/run", json=base).status_code == 422  # no device
        dev = add_device(client)
        with_dev = {**base, "device_id": dev["id"]}
        assert client.post("/api/deploy/run", json=with_dev).status_code == 422  # no lab confirm
        assert client.post("/api/deploy/run", json={**with_dev, "lab_confirm": True}).status_code == 422  # no creds
        cisco_dev = add_device(client, name="EVE-C1", vendor="cisco_ios_xe")
        r = client.post("/api/deploy/run", json={**base, "device_id": cisco_dev["id"], "lab_confirm": True,
                                                  "username": "u", "password": "p"})
        assert r.status_code == 422  # vendor mismatch
        assert FakeConn.instances == []

    def test_live_push_strips_and_never_persists_credentials(self, client, db, caplog):
        dev = add_device(client)
        cmds = "sysname R1\n# comment\nlocal-user bob password cipher Pw1\nvlan 10\n"
        res = client.post("/api/deploy/run", json={
            "vendor": "huawei_vrp", "commands": cmds, "confirm": True, "mode": "live", "device_id": dev["id"],
            "lab_confirm": True, "username": SSH_USER, "password": SSH_PASS})
        assert res.status_code == 200, res.text
        job = deploy.get_job(res.json()["job_id"])
        wait(job)
        assert job.status == "success"
        conn = FakeConn.instances[0]
        assert conn.sent == ["sysname R1", "vlan 10"]  # comment + credential line stripped before push
        assert conn.params["device_type"] == "huawei" and conn.params["port"] == 2222
        assert conn.params["host"] == "192.0.2.11"
        # credentials: used for the connection only, never stored or logged
        dep = client.get(f"/api/deployments/{job.deployment_id}")
        log = client.get(f"/api/deployments/{job.deployment_id}/log.txt")
        db_dump = b"".join(p.read_bytes() for p in db.path.parent.glob(db.path.name + "*")).decode("utf-8", "ignore")
        everything = dep.text + log.text + db_dump + caplog.text + json.dumps(job.logs) + res.text
        for secret in (SSH_USER, SSH_PASS, "Pw1"):
            assert secret not in everything, secret
        assert "sysname R1" in log.text and "[COMMAND]" in log.text

    def test_live_failure_logs_type_only(self, client, monkeypatch):
        class Boom(FakeConn):
            def __init__(self, **params):
                raise RuntimeError(f"auth failed for {params['username']} / {params['password']}")
        monkeypatch.setattr(deploy, "ConnectHandler", Boom)
        dev = add_device(client)
        res = client.post("/api/deploy/run", json={
            "vendor": "huawei_vrp", "commands": "sysname R1", "confirm": True, "mode": "live",
            "device_id": dev["id"], "lab_confirm": True, "username": SSH_USER, "password": SSH_PASS}).json()
        job = deploy.get_job(res["job_id"])
        wait(job)
        assert job.status == "failed"
        text = json.dumps(job.logs)
        assert "RuntimeError" in text and SSH_USER not in text and SSH_PASS not in text

    def test_nothing_deployable(self, client):
        r = client.post("/api/deploy/run", json={"vendor": "cisco_ios_xe", "commands": "! only a comment\nend", "confirm": True})
        assert r.status_code == 422

    def test_deployment_history(self, client):
        client.post("/api/deploy/run", json={"vendor": "cisco_ios_xe", "commands": "hostname R1", "confirm": True})
        items = client.get("/api/deployments").json()["items"]
        assert len(items) == 1 and items[0]["mode"] == "simulation" and items[0]["command_count"] == 1
        assert client.get("/api/deployments/999").status_code == 404

    def test_page(self, client):
        html = client.get("/deploy?lang=en").text
        assert "Configuration Deployment" in html and 'value="simulation" checked' in html
        assert "ส่งชุดคำสั่งไปติดตั้งบนอุปกรณ์" in client.get("/deploy?lang=th").text
