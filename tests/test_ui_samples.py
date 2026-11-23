"""Regression: sample buttons must feed Pre-scan / Convert; sidebar labels never truncated."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.deps import get_translator
from app.main import app
from app.web import NAV_MODULES

JS = (Path(__file__).parent.parent / "app" / "static" / "js" / "convert.js").read_text(encoding="utf-8")
BASE = (Path(__file__).parent.parent / "app" / "templates" / "base.html").read_text(encoding="utf-8")


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


class TestSampleButtonsWiring:
    def test_samples_go_through_set_source(self):
        handler = JS[JS.index('querySelectorAll("[data-sample]")'):JS.index('$("clear-btn")')]
        assert "setSource(text" in handler
        assert "editor.value =" not in handler  # never a bare value assignment that skips state updates

    def test_set_source_dispatches_input_and_clears_stale_error(self):
        body = JS[JS.index("function setSource"):JS.index('fileInput.addEventListener("change"')]
        assert 'dispatchEvent(new Event("input"' in body
        assert '$("error").textContent = ""' in body

    def test_empty_check_reads_live_editor_value(self):
        body = JS[JS.index("function formData"):JS.index("function post")]
        assert "sourceText()" in body
        assert "function sourceText() { return editor.value; }" in JS

    def test_sample_fetch_failure_is_reported(self):
        handler = JS[JS.index('querySelectorAll("[data-sample]")'):JS.index('$("clear-btn")')]
        assert ".catch(" in handler and "r.ok" in handler

    def test_scripts_are_cache_busted(self, client):
        html = client.get("/").text
        assert re.search(r'/static/js/convert\.js\?v=[\d.]+', html)
        assert re.search(r'/static/js/app\.js\?v=[\d.]+', html)


class TestSampleFlowEndToEnd:
    """The exact requests the page sends after a sample button click."""

    @pytest.mark.parametrize("vendor, direction", [("cisco", "c2h"), ("huawei", "h2c")])
    def test_prescan_and_convert_on_sample(self, client, vendor, direction):
        text = client.get(f"/static/samples/{vendor}_sample.txt").text
        assert text.strip()
        pre = client.post("/api/prescan", data={"direction": direction, "config": text, "lang": "en"})
        assert pre.status_code == 200 and pre.json()["total_lines"] > 10
        conv = client.post("/api/convert", data={"direction": direction, "mode": "rule_only", "config": text})
        assert conv.status_code == 200
        body = conv.json()
        assert body["history_id"] > 0 and body["provenance_counts"]["RULE"] > 10


class TestSidebar:
    def test_all_eight_modules_are_links_without_badges(self, client):
        for lang in ("th", "en"):
            html = client.get(f"/?lang={lang}").text
            for item in NAV_MODULES:
                assert f'href="{item["href"]}" data-nav="{item["key"]}"' in html
            assert "Coming Soon" not in html and "เร็วๆ นี้" not in html
            assert "aria-disabled" not in html.split('id="sidenav"')[1].split("</nav>")[0]

    def test_labels_wrap_instead_of_truncating(self):
        nav = BASE[BASE.index('<nav id="sidenav"'):BASE.index("</nav>")]
        assert "truncate" not in nav
        assert "break-words" in nav
        assert "xl:w-72" in nav

    @pytest.mark.parametrize("path", ["/", "/batch", "/inventory", "/deploy", "/history", "/settings", "/topology", "/hardware"])
    def test_active_page_marked(self, client, path):
        html = client.get(path + "?lang=en").text
        key = next(m["key"] for m in NAV_MODULES if m["href"] == path)
        assert re.search(rf'data-nav="{key}"[^>]*>|data-nav="{key}"\s', html)
        nav = html.split('id="sidenav"')[1].split("</nav>")[0]
        assert nav.count('aria-current="page"') == 1


NODE = shutil.which("node")
HARNESS = Path(__file__).parent / "js" / "convert_harness.js"
CONVERT_JS = Path(__file__).parent.parent / "app" / "static" / "js" / "convert.js"


@pytest.mark.skipif(NODE is None, reason="Node.js not installed")
class TestSampleButtonsBehaviour:
    """Executes the real convert.js (stub DOM). 'race' = action clicked while the sample is
    still loading — the exact browser bug: populated editor + "Please paste commands" error."""

    @pytest.mark.parametrize("timing", ["wait", "race"])
    @pytest.mark.parametrize("action", ["prescan", "convert"])
    def test_action_uses_sample_text(self, action, timing):
        proc = subprocess.run([NODE, str(HARNESS), str(CONVERT_JS), action, timing],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f'{action} sent: true | config: "hostname R1"' in proc.stdout
