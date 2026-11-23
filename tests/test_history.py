"""Module 5 — SQLite audit history: secret-free persistence, search/filter, export, delete, diff."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.diff import source_aligned, text_diff
from app.core.engine import convert
from app.core.ir import ConversionMode, Vendor
from app.core.prescan import prescan_config
from app.core.secret_stripper import strip_secrets_keep_lines
from app.db import Database, path_from_url
from app.deps import get_translator
from app.main import app
from app.services import history_service as history
from tests.test_ai_hybrid import API_KEY, CISCO_SECRETS, HUAWEI_SECRETS, FakeLLM, echo_items

FIXTURES = Path(__file__).parent / "fixtures"
C, H = Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


def record(db: Database, text: str, source=C, target=H, **kw) -> int:
    result = convert(text, source, target)
    return history.record_conversion(db, text, result, prescan_config(text, source, target), **kw)


def db_bytes(db: Database) -> str:
    """Everything SQLite wrote to disk (incl. WAL/journal leftovers) as text."""
    data = b"".join(p.read_bytes() for p in db.path.parent.glob(db.path.name + "*"))
    return data.decode("utf-8", errors="ignore")


# ----------------------------------------------------------------------------- persistence


class TestSecretFreePersistence:
    """Never store raw unstripped secrets in SQLite — not in input, output or line JSON."""

    @pytest.mark.parametrize("fixture, source, target, secrets", [
        ("cisco_with_secrets.txt", C, H, CISCO_SECRETS),
        ("huawei_with_secrets.txt", H, C, HUAWEI_SECRETS),
    ])
    def test_no_secret_reaches_the_database_file(self, db, fixture, source, target, secrets):
        text = (FIXTURES / fixture).read_text(encoding="utf-8")
        rid = record(db, text, source, target)
        rec = history.get_conversion(db, rid)
        assert rec["secret_stripped_count"] > 0
        dump = json.dumps(rec, ensure_ascii=False) + db_bytes(db)
        for secret in secrets:
            assert secret not in dump, secret

    def test_stored_input_keeps_line_numbers(self, db):
        text = "hostname R1\nenable secret 9 $9$abc\ninterface Loopback0\n"
        rid = record(db, text)
        stored = history.get_conversion(db, rid)["input_text"].splitlines()
        assert len(stored) == 3
        assert stored[0] == "hostname R1" and stored[2] == "interface Loopback0"
        assert "$9$abc" not in stored[1] and "ระบบสร้างขึ้นเอง" in stored[1]

    def test_keep_lines_helper(self):
        out = strip_secrets_keep_lines("a\nusername x secret y\nb\n", C)
        assert out.splitlines()[0] == "a" and out.splitlines()[2] == "b"
        assert "x" not in out.splitlines()[1].split("]")[0] and "secret y" not in out

    def test_ai_mode_record_is_secret_free(self, client):
        llm = FakeLLM(echo_items())
        app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=API_KEY, _env_file=None)
        app.dependency_overrides[get_translator] = llm.translator
        data = (FIXTURES / "cisco_with_secrets.txt").read_bytes() + b"ip http server\n"
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "hybrid"},
                           files={"file": ("r1.txt", data, "text/plain")}).json()
        rec = client.get(f"/api/history/{body['history_id']}").text
        for secret in CISCO_SECRETS:
            assert secret not in rec
        assert API_KEY not in rec

    def test_counts_mode_and_coverage_recorded(self, db):
        text = "hostname R1\nip http server\n"
        rid = record(db, text, filename="r1.txt")
        rec = history.get_conversion(db, rid)
        assert rec["direction"] == "c2h" and rec["requested_mode"] == "rule_only"
        assert rec["coverage_percent"] == 50.0 and rec["count_unconverted"] == 1
        assert rec["review_count"] == 1 and rec["filename"] == "r1.txt" and rec["hostname"] == "R1"
        assert any(l["provenance"] == "RULE" and l["text"] == "sysname R1" for l in rec["lines"])

    def test_tables_auto_created(self, tmp_path):
        db = Database(tmp_path / "sub" / "x.db")
        with db.connect() as conn:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"conversions", "devices", "deployments", "batch_skipped"} <= names

    def test_devices_table_has_no_credential_columns(self, db):
        with db.connect() as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert not cols & {"username", "password", "secret", "key"}

    def test_database_url_parsing(self):
        assert str(path_from_url("sqlite:///./netmigrate.db")).endswith("netmigrate.db")
        with pytest.raises(ValueError):
            path_from_url("postgres://x")


# ----------------------------------------------------------------------------- API


class TestHistoryApi:
    def test_single_conversion_is_recorded(self, client):
        r = client.post("/api/convert", data={"direction": "c2h", "mode": "rule_only", "config": "hostname R9\n"}).json()
        listing = client.get("/api/history").json()
        assert listing["total"] == 1 and listing["items"][0]["id"] == r["history_id"]
        assert listing["items"][0]["kind"] == "single"

    def test_selected_conversion_is_recorded(self, client):
        client.post("/api/convert/selected", data={"direction": "c2h", "config": "hostname R1\nip http server\n", "line_numbers": "2"})
        assert client.get("/api/history").json()["total"] == 1

    def test_search_and_filters(self, client, db):
        record(db, "hostname ALPHA\n", filename="alpha.txt")
        record(db, "sysname BRAVO\n", H, C)
        record(db, "hostname CHARLIE\n", kind="batch", batch_id="b" * 32)
        assert client.get("/api/history?q=BRAVO").json()["total"] == 1
        assert client.get("/api/history?q=alpha.txt").json()["total"] == 1
        assert client.get("/api/history?direction=h2c").json()["total"] == 1
        assert client.get("/api/history?kind=batch").json()["total"] == 1
        assert client.get("/api/history?mode=rule_only").json()["total"] == 3
        assert client.get("/api/history?mode=hybrid").json()["total"] == 0
        page = client.get("/api/history?limit=2&offset=0").json()
        assert page["total"] == 3 and len(page["items"]) == 2

    def test_detail_localized(self, client, db):
        rid = record(db, "hostname R1\nip route 10.0.0.0 255.0.0.0 1.1.1.1\n")
        en = client.get(f"/api/history/{rid}?lang=en").json()
        assert en["lines"][1]["label"] == "Rule-based"
        th = client.get(f"/api/history/{rid}?lang=th").json()
        assert th["lines"][1]["label"] == "มาจากกฎ"

    def test_download_and_export(self, client, db):
        rid = record(db, "hostname R1\n", filename="core-1.txt")
        dl = client.get(f"/api/history/{rid}/download")
        assert dl.status_code == 200 and "sysname R1" in dl.text
        assert 'filename="core-1_huawei.txt"' in dl.headers["content-disposition"]
        one = client.get(f"/api/history/{rid}/export").json()
        assert one["id"] == rid and one["lines"]
        allx = client.get("/api/history/export").json()
        assert allx["exported"] == 1 and allx["conversions"][0]["id"] == rid
        ids = client.get(f"/api/history/export?ids={rid}").json()
        assert ids["exported"] == 1
        assert client.get("/api/history/export?ids=a").status_code == 422

    def test_delete(self, client, db):
        rid = record(db, "hostname R1\n")
        assert client.delete(f"/api/history/{rid}").status_code == 200
        assert client.get(f"/api/history/{rid}").status_code == 404
        assert client.delete(f"/api/history/{rid}").status_code == 404

    def test_dashboard(self, client, db):
        record(db, "hostname R1\nip http server\n")
        record(db, "sysname R2\n", H, C)
        d = client.get("/api/dashboard").json()
        assert d["conversions"] == 2
        assert d["by_direction"] == {"c2h": 1, "h2c": 1}
        assert d["review_count"] == 1 and d["lines"]["UNCONVERTED"] == 1
        assert len(d["trend"]) == 14 and d["trend"][-1]["count"] == 2

    def test_detail_page(self, client, db):
        rid = record(db, "hostname R1\n")
        assert client.get(f"/history/{rid}?lang=en").status_code == 200
        assert client.get("/history/999").status_code == 404


# ----------------------------------------------------------------------------- diff


class TestDiff:
    def test_text_diff_counts(self):
        res = text_diff("a\nb\nc\n", "a\nB\nc\nd\n")
        assert res["counts"] == {"equal": 2, "replace": 1, "delete": 0, "insert": 1}
        assert [r["tag"] for r in res["rows"]] == ["equal", "replace", "equal", "insert"]
        assert res["rows"][1]["left"] == "b" and res["rows"][1]["right"] == "B"
        assert "-b" in res["unified"] and "+B" in res["unified"]

    def test_identical_texts(self):
        res = text_diff("x\ny\n", "x\ny\n")
        assert res["ratio"] == 1.0 and res["counts"]["equal"] == 2

    def test_source_aligned_groups_outputs_under_source_line(self):
        rows = source_aligned("hostname R1\n!\nip http server\n", [
            {"text": "sysname R1", "provenance": "RULE", "source_line": 1},
            {"text": "# [แปลงไม่ได้] ip http server", "provenance": "UNCONVERTED", "source_line": 3},
        ])
        assert rows[0]["outputs"][0]["text"] == "sysname R1"
        assert rows[1]["outputs"] == []
        assert rows[2]["outputs"][0]["provenance"] == "UNCONVERTED"

    def test_history_diff_api(self, client, db):
        rid = record(db, "hostname R1\nvlan 10\n")
        rows = client.get(f"/api/history/{rid}/diff").json()["rows"]
        first = next(r for r in rows if r["no"] == 1)
        assert first["source"] == "hostname R1"
        assert any(o["text"] == "sysname R1" for o in first["outputs"])

    def test_compare_two_records(self, client, db):
        a = record(db, "hostname R1\nvlan 10\n")
        b = record(db, "hostname R2\nvlan 10\n")
        res = client.get(f"/api/history/compare?a={a}&b={b}").json()
        assert res["same_target"] is True and res["counts"]["replace"] >= 1
        assert any(r["left"] == "sysname R1" and r["right"] == "sysname R2" for r in res["rows"])

    def test_adhoc_diff_api(self, client):
        res = client.post("/api/diff", data={"left": "a\n", "right": "b\n"}).json()
        assert res["counts"]["replace"] == 1
