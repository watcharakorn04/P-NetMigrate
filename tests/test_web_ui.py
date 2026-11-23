"""Web UI + HTTP API (modules 1 and 6): bilingual pages, pre-scan, convert, selective AI."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.ir import Provenance
from app.i18n import PROVENANCE_EN, UI, provenance_label, translate_message, ui_dict
from app.main import app, get_translator
from tests.test_ai_hybrid import API_KEY, CISCO_SECRETS, MIXED, FakeLLM, echo_items

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parent.parent / "app" / "static" / "samples"


@pytest.fixture
def client():
    yield TestClient(app)
    app.dependency_overrides.clear()


def no_key():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None


def with_fake_ai(reply=None) -> FakeLLM:
    llm = FakeLLM(reply or echo_items())
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key=API_KEY, _env_file=None)
    app.dependency_overrides[get_translator] = llm.translator
    return llm


# ----------------------------------------------------------------------------- i18n dictionary


class TestI18n:
    def test_thai_provenance_labels_are_exact_enum_strings(self):
        assert [provenance_label(p, "th") for p in Provenance] == [
            "มาจากกฎ", "มาจาก AI ต้องตรวจสอบก่อนใช้", "ระบบสร้างขึ้นเอง", "แปลงไม่ได้", "ไม่ต้องใช้คำสั่งนี้"]

    def test_english_provenance_labels(self):
        assert [provenance_label(p, "en") for p in Provenance] == [
            "Rule-based", "AI-generated (Review Required)", "System-generated", "Unconverted", "Not Needed"]
        assert set(PROVENANCE_EN) == set(Provenance)

    def test_every_ui_key_has_both_languages(self):
        for key, entry in UI.items():
            assert set(entry) == {"th", "en"} and all(entry.values()), key
        assert ui_dict("en")["prov_AI"] == "AI-generated (Review Required)"
        assert ui_dict("xx")["prov_AI"] == "มาจาก AI ต้องตรวจสอบก่อนใช้"  # unknown -> Thai default

    @pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.txt")) + ["cisco_sample.txt", "huawei_sample.txt"])
    def test_every_engine_message_has_an_english_rendering(self, fixture):
        from app.core.engine import convert
        from app.core.ir import Vendor

        path = FIXTURES / fixture if (FIXTURES / fixture).exists() else SAMPLES / fixture
        source = Vendor.HUAWEI_VRP if "huawei" in fixture else Vendor.CISCO_IOS_XE
        target = Vendor.CISCO_IOS_XE if source is Vendor.HUAWEI_VRP else Vendor.HUAWEI_VRP
        result = convert(path.read_text(encoding="utf-8"), source, target)
        messages = result.warnings + result.notices + [i.reason for i in result.unconverted_items]
        for message in messages:
            english = translate_message(message, "en")
            assert not re.search("[฀-๿]", english), english
            assert translate_message(message, "th") == message


# ----------------------------------------------------------------------------- pages


class TestPages:
    def test_thai_page(self, client):
        no_key()
        resp = client.get("/?lang=th")
        assert resp.status_code == 200
        html = resp.text
        assert '<html lang="th">' in html
        assert "แปลงคำสั่งแบบไฟล์เดี่ยว" in html
        assert "ตรวจสอบก่อนแปลง" in html
        assert "เร็วๆ นี้" not in html  # all 8 modules are live
        assert resp.cookies.get("lang") == "th"

    def test_english_page(self, client):
        no_key()
        resp = client.get("/?lang=en")
        html = resp.text
        assert '<html lang="en">' in html
        assert "Single File / CLI Conversion" in html
        assert "Run Pre-scan" in html and "Send Selected to AI" in html
        assert "Coming Soon" not in html
        assert "แปลงคำสั่งแบบไฟล์เดี่ยว" not in html
        assert resp.cookies.get("lang") == "en"

    def test_language_persists_via_cookie(self, client):
        no_key()
        client.get("/?lang=en")
        assert "Single File / CLI Conversion" in client.get("/").text
        client.get("/?lang=th")
        assert "แปลงคำสั่งแบบไฟล์เดี่ยว" in client.get("/").text

    def test_unknown_language_defaults_to_thai(self, client):
        no_key()
        assert '<html lang="th">' in client.get("/?lang=fr").text

    def test_navigation_lists_all_eight_modules(self, client):
        no_key()
        html = client.get("/?lang=en").text
        for key in [f"nav_m{i}" for i in range(1, 9)]:
            assert UI[key]["en"].replace("&", "&amp;") in html, key
        assert 'aria-current="page"' in html

    def test_theme_and_language_toggles_and_health_badge_present(self, client):
        no_key()
        html = client.get("/").text
        assert "darkMode" in html and '"class"' in html
        assert 'id="theme-toggle"' in html and "localStorage" in html
        assert 'href="?lang=th"' in html and 'href="?lang=en"' in html
        assert 'id="health-badge"' in html
        assert "/static/js/app.js?v=" in html and "/static/js/convert.js?v=" in html

    def test_ai_modes_disabled_without_key(self, client):
        no_key()
        html = client.get("/?lang=en").text
        assert re.search(r'value="hybrid"[^>]*disabled', html)
        assert re.search(r'value="ai_only"[^>]*disabled', html)
        assert re.search(r'value="rule_only"[^>]*checked', html)
        assert "LLM_API_KEY is not set" in html

    def test_hybrid_default_with_key(self, client):
        with_fake_ai()
        html = client.get("/?lang=en").text
        assert re.search(r'value="hybrid"[^>]*checked', html)
        assert not re.search(r'value="hybrid"[^>]*disabled', html)
        assert API_KEY not in html

    def test_static_assets_and_samples_served(self, client):
        for path in ("/static/js/app.js", "/static/js/convert.js",
                     "/static/samples/cisco_sample.txt", "/static/samples/huawei_sample.txt"):
            assert client.get(path).status_code == 200, path


# ----------------------------------------------------------------------------- health


class TestHealthLanguage:
    def test_english_message(self, client):
        no_key()
        body = client.get("/api/health?lang=en").json()
        assert body["message"] == "No API key configured or AI unavailable — running in rule-only mode"
        assert body["llm_model"] is None

    def test_model_reported_but_key_never_echoed(self, client):
        with_fake_ai()
        resp = client.get("/api/health")
        assert resp.json()["llm_model"] == "gpt-4o-mini"
        assert API_KEY not in resp.text


# ----------------------------------------------------------------------------- pre-scan


class TestPrescanApi:
    def test_text(self, client):
        no_key()
        body = client.post("/api/prescan", data={"direction": "c2h", "config": MIXED}).json()
        assert body["total_lines"] == 8
        assert body["unsupported_lines"] == 5
        assert body["coverage_percent"] == 37.5
        assert [i["line_no"] for i in body["unsupported_items"]] == [2, 5, 6, 7, 8]
        assert body["unsupported_items"][0]["reason"] == "ยังไม่มีกฎรองรับคำสั่งนี้"

    def test_english_reasons(self, client):
        no_key()
        body = client.post("/api/prescan", data={"direction": "c2h", "config": MIXED, "lang": "en"}).json()
        reasons = [i["reason"] for i in body["unsupported_items"]]
        assert reasons[0] == "No rule supports this command yet"
        assert reasons[3] == "Out of scope (IPv6) — review and configure manually"

    def test_file_upload_and_secret_count(self, client):
        no_key()
        data = (FIXTURES / "cisco_with_secrets.txt").read_bytes()
        resp = client.post("/api/prescan", data={"direction": "c2h"}, files={"file": ("r1.txt", data, "text/plain")})
        body = resp.json()
        assert resp.status_code == 200
        assert body["secret_stripped_count"] > 0
        for secret in CISCO_SECRETS:
            assert secret not in resp.text

    def test_huawei_direction(self, client):
        no_key()
        body = client.post("/api/prescan", data={"direction": "h2c", "config": "sysname R2\n"}).json()
        assert body["source_vendor"] == "huawei_vrp" and body["coverage_percent"] == 100.0


# ----------------------------------------------------------------------------- convert


class TestConvertApi:
    def test_rule_only_text(self, client):
        no_key()
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "rule_only", "config": MIXED}).json()
        assert body["effective_mode"] == "rule_only"
        sysname = next(l for l in body["lines"] if l["text"] == "sysname R1")
        assert sysname["provenance"] == "RULE" and sysname["label"] == "มาจากกฎ"
        assert [i["line_no"] for i in body["unconverted_items"]] == [2, 5, 6, 7, 8]
        assert body["provenance_counts"]["UNCONVERTED"] == 5

    def test_download_text_is_clean_cli(self, client):
        no_key()
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "rule_only", "config": MIXED}).json()
        assert body["text"].splitlines() == [l["text"] for l in body["lines"]]
        assert not any(line.startswith("[มาจากกฎ]") for line in body["text"].splitlines())
        assert "sysname R1" in body["text"].splitlines()

    def test_txt_file_upload(self, client):
        no_key()
        resp = client.post(
            "/api/convert",
            data={"direction": "h2c", "mode": "rule_only"},
            files={"file": ("r2.txt", "﻿sysname R2\r\n".encode("utf-8"), "text/plain")},
        )
        body = resp.json()
        assert resp.status_code == 200
        assert any(l["text"] == "hostname R2" for l in body["lines"])

    def test_file_overrides_editor_text(self, client):
        no_key()
        body = client.post(
            "/api/convert",
            data={"direction": "c2h", "mode": "rule_only", "config": "hostname FROM-EDITOR\n"},
            files={"file": ("a.txt", b"hostname FROM-FILE\n", "text/plain")},
        ).json()
        assert any(l["text"] == "sysname FROM-FILE" for l in body["lines"])

    def test_english_labels_and_warnings(self, client):
        no_key()
        text = "hostname R1\nip route 10.1.0.0 255.255.0.0 10.0.0.2\n"
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "rule_only", "config": text, "lang": "en"}).json()
        assert body["lines"][1]["label"] in PROVENANCE_EN.values()
        assert any("Cisco default AD=1" in w for w in body["warnings"])

    def test_no_key_hybrid_falls_back_with_notice(self, client):
        no_key()
        body = client.post("/api/convert", data={"direction": "c2h", "config": MIXED, "lang": "en"}).json()
        assert body["requested_mode"] == "hybrid"
        assert body["effective_mode"] == "rule_only"
        assert body["ai_available"] is False
        assert any("rule-only" in n for n in body["notices"])

    def test_hybrid_with_ai(self, client):
        llm = with_fake_ai()
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "hybrid", "config": MIXED, "lang": "en"}).json()
        assert body["effective_mode"] == "hybrid"
        ai = [l for l in body["lines"] if l["provenance"] == "AI" and not l["is_comment"]]
        assert sorted(l["text"] for l in ai) == [" AI-speed 100", "AI-ip http server"]
        assert all(l["label"] == "AI-generated (Review Required)" for l in ai)
        assert body["ai_sent_line_numbers"] == [2, 5]
        assert len(llm.requests) == 1

    def test_ai_only_with_ai(self, client):
        with_fake_ai(lambda p: {"lines": ["sysname R1"]})
        body = client.post("/api/convert", data={"direction": "c2h", "mode": "ai_only", "config": MIXED}).json()
        assert body["effective_mode"] == "ai_only"
        assert all(l["provenance"] == "AI" for l in body["lines"])

    def test_no_secret_in_api_response_or_ai_request(self, client):
        llm = with_fake_ai()
        data = (FIXTURES / "cisco_with_secrets.txt").read_bytes() + b"ip http server\n"
        resp = client.post("/api/convert", data={"direction": "c2h", "mode": "hybrid"},
                           files={"file": ("r1.txt", data, "text/plain")})
        assert resp.status_code == 200 and llm.requests
        for secret in CISCO_SECRETS:
            assert secret not in resp.text, secret
            assert secret not in llm.sent, secret

    def test_sample_configs_convert(self, client):
        no_key()
        for name, direction in (("cisco_sample.txt", "c2h"), ("huawei_sample.txt", "h2c")):
            text = (SAMPLES / name).read_text(encoding="utf-8")
            body = client.post("/api/convert", data={"direction": direction, "mode": "rule_only", "config": text}).json()
            assert body["secret_stripped_count"] == 1
            assert "DEMO-ONLY" not in body["text"]
            assert body["provenance_counts"]["RULE"] > 10

    @pytest.mark.parametrize(
        "data, files, status",
        [
            ({"direction": "c2h", "config": "   "}, None, 422),
            ({"direction": "x2y", "config": "hostname R1"}, None, 422),
            ({"direction": "c2h", "mode": "magic", "config": "hostname R1"}, None, 422),
            ({"direction": "c2h"}, {"file": ("r1.cfg", b"hostname R1\n", "text/plain")}, 415),
            ({"direction": "c2h"}, {"file": ("big.txt", b"a" * 1_000_001, "text/plain")}, 413),
        ],
        ids=["empty", "bad-direction", "bad-mode", "not-txt", "too-large"],
    )
    def test_bad_input(self, client, data, files, status):
        no_key()
        assert client.post("/api/convert", data=data, files=files).status_code == status


class TestSelectedApi:
    def test_sends_only_selected_lines(self, client):
        llm = with_fake_ai()
        body = client.post("/api/convert/selected",
                           data={"direction": "c2h", "config": MIXED, "line_numbers": "7, 8"}).json()
        assert body["effective_mode"] == "rule_only"
        assert body["ai_sent_line_numbers"] == [7, 8]
        assert "ip http server" not in llm.sent
        assert [i["line_no"] for i in body["unconverted_items"]] == [2, 5, 6]

    def test_without_key_returns_rule_result_with_notice(self, client):
        no_key()
        body = client.post("/api/convert/selected",
                           data={"direction": "c2h", "config": MIXED, "line_numbers": "2", "lang": "en"}).json()
        assert any("unavailable" in n for n in body["notices"])
        assert 2 in [i["line_no"] for i in body["unconverted_items"]]

    def test_bad_line_numbers(self, client):
        no_key()
        resp = client.post("/api/convert/selected", data={"direction": "c2h", "config": MIXED, "line_numbers": "a,b"})
        assert resp.status_code == 422
