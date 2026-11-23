"""Module 2 — batch .zip conversion: Zip Slip / binary / bomb protection and output packaging."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.core.ir import Vendor
from app.core.vendor_detect import detect_vendor
from app.deps import get_translator
from app.main import app
from app.services import batch_service as batch
from tests.test_ai_hybrid import CISCO_SECRETS, HUAWEI_SECRETS

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parent.parent / "app" / "static" / "samples"
CISCO = (SAMPLES / "cisco_sample.txt").read_text(encoding="utf-8")
HUAWEI = (SAMPLES / "huawei_sample.txt").read_text(encoding="utf-8")


def make_zip(entries: dict[str, bytes | str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data.encode("utf-8") if isinstance(data, str) else data)
    return buf.getvalue()


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(llm_api_key="", _env_file=None)
    app.dependency_overrides[get_translator] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.pop(get_settings, None)
    app.dependency_overrides.pop(get_translator, None)


# ----------------------------------------------------------------------------- extraction safety


class TestZipSlip:
    @pytest.mark.parametrize("name", [
        "../evil.txt", "../../etc/passwd.txt", "a/../../evil.cfg", "/abs/evil.txt", "C:/Windows/evil.txt",
        "c:evil.txt", "..\\evil.txt", "dir\\..\\..\\evil.txt", "ok/../../../x.txt",
    ])
    def test_unsafe_member_names_rejected(self, name):
        assert batch.is_unsafe_member(name)
        out = batch.extract_zip(make_zip({name: "hostname R1\n"}))
        assert out.files == []
        assert out.skipped and out.skipped[0].reason == batch.SKIP_UNSAFE_PATH
        assert "/" not in out.skipped[0].name and "\\" not in out.skipped[0].name and ".." not in out.skipped[0].name

    @pytest.mark.parametrize("name", ["r1.txt", "site-a/r1.cfg", "a/b/c/R2.TXT", "configs/./r3.txt"])
    def test_safe_names_accepted_as_basename(self, name):
        out = batch.extract_zip(make_zip({name: "hostname R1\n"}))
        assert len(out.files) == 1
        assert "/" not in out.files[0].name

    def test_nothing_is_written_to_disk(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        batch.extract_zip(make_zip({"../escape.txt": "hostname X\n", "ok.txt": "hostname Y\n"}))
        assert list(tmp_path.iterdir()) == []
        assert not (tmp_path.parent / "escape.txt").exists()

    def test_safe_basename(self):
        name = batch.safe_basename("../../a b/évil name.txt")
        assert name.endswith("vil_name.txt") and "/" not in name and " " not in name
        assert batch.safe_basename("..") == "config"
        assert batch.safe_basename("x\\y\\z.cfg") == "z.cfg"


class TestContentChecks:
    def test_binary_file_skipped(self):
        out = batch.extract_zip(make_zip({"blob.txt": b"\x00\x01\x02ELF\x00\x00", "ok.txt": "hostname R1\n"}))
        assert [f.name for f in out.files] == ["ok.txt"]
        assert out.skipped[0].reason == batch.SKIP_BINARY

    def test_wrong_extension_skipped(self):
        out = batch.extract_zip(make_zip({"run.exe": b"MZ", "notes.md": "x", "r1.cfg": "hostname R1\n"}))
        assert [f.name for f in out.files] == ["r1.cfg"]
        assert {s.reason for s in out.skipped} == {batch.SKIP_EXTENSION}

    def test_empty_and_oversized(self):
        out = batch.extract_zip(make_zip({"empty.txt": "  \n", "big.txt": "a" * (batch.MAX_FILE_BYTES + 10)}))
        reasons = {s.name: s.reason for s in out.skipped}
        assert reasons["empty.txt"] == batch.SKIP_EMPTY and reasons["big.txt"] == batch.SKIP_TOO_LARGE

    def test_zip_bomb_ratio(self, monkeypatch):
        monkeypatch.setattr(batch, "MAX_FILE_BYTES", 10_000_000)
        out = batch.extract_zip(make_zip({"bomb.txt": "!" * 5_000_000}))  # compresses ~1000:1
        assert out.files == [] and out.skipped[0].reason == batch.SKIP_TOO_LARGE

    def test_too_many_entries(self, monkeypatch):
        monkeypatch.setattr(batch, "MAX_ENTRIES", 3)
        out = batch.extract_zip(make_zip({f"r{i}.txt": "hostname R\n" for i in range(5)}))
        assert out.files == [] and out.skipped[0].reason == batch.SKIP_LIMIT

    def test_corrupt_archive(self):
        out = batch.extract_upload("x.zip", b"PK\x03\x04 not really a zip")
        assert out.files == [] and out.skipped[0].reason == batch.SKIP_BAD_ZIP

    def test_encrypted_entry_skipped(self):
        data = bytearray(make_zip({"r1.txt": "hostname R1\n"}))
        # set the "encrypted" flag bit in both the local and the central directory headers
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = data.find(sig)
            off = i + (6 if sig == b"PK\x03\x04" else 8)
            data[off] |= 0x1
        out = batch.extract_zip(bytes(data))
        assert out.files == [] and out.skipped[0].reason == batch.SKIP_ENCRYPTED

    def test_plain_upload_and_cp874(self):
        out = batch.extract_upload("r1.txt", "hostname R1\n description ทดสอบ\n".encode("cp874"))
        assert out.files and "ทดสอบ" in out.files[0].text


class TestVendorDetection:
    def test_samples(self):
        assert detect_vendor(CISCO) is Vendor.CISCO_IOS_XE
        assert detect_vendor(HUAWEI) is Vendor.HUAWEI_VRP

    def test_undetectable(self):
        assert detect_vendor("foo bar\n") is None


# ----------------------------------------------------------------------------- conversion + packaging


class TestConversionAndPackaging:
    def test_convert_files_records_history_and_strips_secrets(self, db):
        cisco_secret = (FIXTURES / "cisco_with_secrets.txt").read_text(encoding="utf-8")
        hua_secret = (FIXTURES / "huawei_with_secrets.txt").read_text(encoding="utf-8")
        ex = batch.extract_zip(make_zip({"site/r1.txt": cisco_secret, "r2.cfg": hua_secret, "../x.txt": "hostname X\n"}))
        rows = batch.convert_files(db, "a" * 32, ex, direction="auto")
        done = [r for r in rows if r.get("history_id")]
        assert len(done) == 2 and all(r["secret_stripped_count"] > 0 for r in done)
        assert {r["direction"] for r in done} == {"c2h", "h2c"}
        assert any(r["status"] == "skipped" for r in rows)

        records = batch.batch_records(db, "a" * 32)
        from app.services.history_service import skipped_for_batch
        data = batch.build_output_zip("a" * 32, records, skipped_for_batch(db, "a" * 32))
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            assert {"r1_huawei.txt", "r2_cisco.txt", "migration_report.txt", "migration_report.json"} == set(names)
            assert all("/" not in n and ".." not in n for n in names)
            everything = "".join(zf.read(n).decode("utf-8") for n in names)
            report = json.loads(zf.read("migration_report.json"))
        for secret in CISCO_SECRETS + HUAWEI_SECRETS:
            assert secret not in everything, secret
        assert report["converted"] == 2 and report["skipped"] == 1
        assert {f["output"] for f in report["files"]} == {"r1_huawei.txt", "r2_cisco.txt"}
        assert report["skipped_files"][0]["reason"] == batch.SKIP_UNSAFE_PATH

    def test_output_names_deduplicated(self, db):
        ex = batch.Extracted(files=[batch.InputFile("r1.txt", "hostname A\n"), batch.InputFile("r1.cfg", "hostname B\n")])
        batch.convert_files(db, "c" * 32, ex, direction="c2h")
        data = batch.build_output_zip("c" * 32, batch.batch_records(db, "c" * 32), [])
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            assert sorted(n for n in zf.namelist() if n.startswith("r1")) == ["r1_huawei.txt", "r1_huawei_2.txt"]

    def test_unknown_vendor_with_auto(self, db):
        ex = batch.Extracted(files=[batch.InputFile("mystery.txt", "foo\nbar\n")])
        rows = batch.convert_files(db, "d" * 32, ex, direction="auto")
        assert rows[0]["status"] == "skipped" and rows[0]["reason"] == batch.SKIP_UNKNOWN_VENDOR

    def test_report_text(self, db):
        ex = batch.Extracted(files=[batch.InputFile("r1.txt", "hostname A\nip http server\n")])
        batch.convert_files(db, "e" * 32, ex, direction="c2h")
        text = batch.report_text(batch.build_report("e" * 32, batch.batch_records(db, "e" * 32), []))
        assert "r1.txt  ->  r1_huawei.txt" in text and "UNCONVERTED=1" in text and "[REVIEW]" in text


class TestBatchApi:
    def test_zip_roundtrip(self, client):
        z = make_zip({"r1.txt": CISCO, "r2.txt": HUAWEI, "../evil.txt": "hostname E\n", "bin.cfg": b"\x00\x00"})
        res = client.post("/api/batch/convert", data={"direction": "auto", "mode": "rule_only", "lang": "en"},
                          files=[("files", ("configs.zip", z, "application/zip"))])
        assert res.status_code == 200
        body = res.json()
        bid = body["batch_id"]
        statuses = {r["filename"]: r["status"] for r in body["rows"]}
        assert statuses["evil.txt"] == "skipped" and statuses["bin.cfg"] == "skipped"
        assert statuses["r1.txt"] in ("done", "review") and statuses["r2.txt"] in ("done", "review")
        assert any("Zip Slip" in r.get("reason", "") for r in body["rows"])
        conv = [r for r in body["rows"] if r.get("history_id")]
        assert all(0 <= r["coverage_percent"] <= 100 for r in conv)

        status = client.get(f"/api/batch/{bid}").json()
        assert len(status["items"]) == 2 and len(status["skipped"]) == 2

        dl = client.get(f"/api/batch/{bid}/download")
        assert dl.status_code == 200 and dl.headers["content-type"] == "application/zip"
        with zipfile.ZipFile(io.BytesIO(dl.content)) as zf:
            assert "migration_report.json" in zf.namelist() and "r1_huawei.txt" in zf.namelist()
            assert "DEMO-ONLY" not in zf.read("r1_huawei.txt").decode()

    def test_queue_steps_share_one_batch(self, client):
        first = client.post("/api/batch/convert", data={"direction": "c2h", "mode": "rule_only"},
                            files=[("files", ("a.txt", b"hostname A\n", "text/plain"))]).json()
        client.post("/api/batch/convert", data={"direction": "h2c", "mode": "rule_only", "batch_id": first["batch_id"]},
                    files=[("files", ("b.cfg", b"sysname B\n", "text/plain"))])
        status = client.get(f"/api/batch/{first['batch_id']}").json()
        assert [i["filename"] for i in status["items"]] == ["a.txt", "b.cfg"]
        assert client.get("/api/history?kind=batch").json()["total"] == 2

    def test_bad_inputs(self, client):
        f = [("files", ("a.txt", b"hostname A\n", "text/plain"))]
        assert client.post("/api/batch/convert", data={"direction": "x"}, files=f).status_code == 422
        assert client.post("/api/batch/convert", data={"mode": "magic"}, files=f).status_code == 422
        assert client.post("/api/batch/convert", data={"batch_id": "../../etc"}, files=f).status_code == 422
        assert client.get("/api/batch/not-a-batch-id/download").status_code == 422
        assert client.get("/api/batch/" + "f" * 32 + "/download").status_code == 404

    def test_page(self, client):
        html = client.get("/batch?lang=en").text
        assert "Batch File Conversion" in html and "/static/js/batch.js?v=" in html
        assert "แปลงไฟล์แบบกลุ่ม" in client.get("/batch?lang=th").text
