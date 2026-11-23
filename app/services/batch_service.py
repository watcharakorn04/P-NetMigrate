"""Batch conversion (proposal §2.3.1 module 2).

Input: several .txt / .cfg uploads and/or .zip archives of them. Archives are read
entirely in memory — nothing is ever extracted to disk — and every entry is vetted:

  * Zip Slip: absolute paths, drive letters, `..` components and backslash tricks are
    rejected, and output names are reduced to a safe basename, so no name from an upload
    can ever become a filesystem path (in this server or in the user's unzip tool);
  * only .txt / .cfg; encrypted entries, binary content (NUL bytes / undecodable) skipped;
  * zip-bomb limits: entry count, per-file and total uncompressed size, compression ratio.

Each accepted file goes through the normal engine (strip_secrets first, then rules / AI per
the mode), is recorded in the audit history, and can be downloaded singly or as one .zip
with `migration_report.txt` + `migration_report.json`.
"""

from __future__ import annotations

import io
import json
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from typing import Optional, Sequence

from app.core.engine import convert
from app.core.ir import ConversionMode, Vendor
from app.core.prescan import prescan_config
from app.core.vendor_detect import detect_vendor
from app.db import Database, utcnow
from app.services import history_service as history
from app.services.ai_translator import Translator

ALLOWED_EXT = (".txt", ".cfg")
MAX_FILE_BYTES = 1_000_000
MAX_ENTRIES = 200
MAX_TOTAL_BYTES = 20_000_000
MAX_RATIO = 200  # uncompressed / compressed
DIRECTIONS = {
    "c2h": (Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP),
    "h2c": (Vendor.HUAWEI_VRP, Vendor.CISCO_IOS_XE),
}
TARGET_SUFFIX = {Vendor.HUAWEI_VRP: "huawei", Vendor.CISCO_IOS_XE: "cisco"}

# Thai reason strings are the canonical text (translated for the UI in app.i18n).
SKIP_UNSAFE_PATH = "ชื่อไฟล์ในไฟล์ .zip ไม่ปลอดภัย (Zip Slip / path traversal) จึงไม่อ่านไฟล์นี้"
SKIP_EXTENSION = "รองรับเฉพาะไฟล์ .txt และ .cfg"
SKIP_BINARY = "ไฟล์นี้เป็นไฟล์ไบนารี ไม่ใช่ไฟล์ข้อความ Config"
SKIP_ENCRYPTED = "ไฟล์ในไฟล์ .zip ถูกเข้ารหัสไว้ จึงอ่านไม่ได้"
SKIP_TOO_LARGE = "ไฟล์ใหญ่เกินกำหนด (สูงสุด 1 MB ต่อไฟล์)"
SKIP_LIMIT = "ไฟล์ .zip มีจำนวนไฟล์หรือขนาดรวมเกินกำหนด"
SKIP_EMPTY = "ไฟล์ว่าง ไม่มีคำสั่งให้แปลง"
SKIP_BAD_ZIP = "ไฟล์ .zip เสียหายหรือไม่ใช่ไฟล์ .zip"
SKIP_UNKNOWN_VENDOR = "ระบุยี่ห้อต้นทางของไฟล์นี้อัตโนมัติไม่ได้ กรุณาเลือกทิศทางการแปลงเอง"
SKIP_CONVERT_ERROR = "แปลงไฟล์นี้ไม่สำเร็จ"

_DRIVE = re.compile(r"^[A-Za-z]:")
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class InputFile:
    name: str  # safe basename
    text: str


@dataclass
class Skipped:
    name: str
    reason: str


@dataclass
class Extracted:
    files: list[InputFile] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


def is_unsafe_member(name: str) -> bool:
    """True for any archive member name that could escape an extraction directory."""
    if not name or "\x00" in name:
        return True
    if "\\" in name:  # Windows separators: treat as traversal attempts
        return True
    if name.startswith("/") or _DRIVE.match(name):
        return True
    parts = name.split("/")
    if any(p == ".." for p in parts):
        return True
    norm = posixpath.normpath(name)
    return norm.startswith("..") or norm.startswith("/")


def safe_basename(name: str) -> str:
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _SAFE_CHARS.sub("_", base).strip("._") or "config"
    return base[:120]


def decode_text(data: bytes) -> Optional[str]:
    """Text of a config file, or None when it is binary."""
    if b"\x00" in data:
        return None
    for enc in ("utf-8-sig", "cp874"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t\f")
    return None if controls > max(4, len(text) // 100) else text


def _accept(name: str, data: bytes, out: Extracted) -> None:
    safe = safe_basename(name)
    if not safe.lower().endswith(ALLOWED_EXT):
        out.skipped.append(Skipped(safe, SKIP_EXTENSION))
        return
    if len(data) > MAX_FILE_BYTES:
        out.skipped.append(Skipped(safe, SKIP_TOO_LARGE))
        return
    text = decode_text(data)
    if text is None:
        out.skipped.append(Skipped(safe, SKIP_BINARY))
        return
    if not text.strip():
        out.skipped.append(Skipped(safe, SKIP_EMPTY))
        return
    out.files.append(InputFile(safe, text))


def extract_zip(data: bytes, out: Optional[Extracted] = None) -> Extracted:
    """Vet and read every member of an in-memory .zip archive (never touches the disk)."""
    out = out or Extracted()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        out.skipped.append(Skipped("archive.zip", SKIP_BAD_ZIP))
        return out
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > MAX_ENTRIES or sum(m.file_size for m in members) > MAX_TOTAL_BYTES:
            out.skipped.append(Skipped("archive.zip", SKIP_LIMIT))
            return out
        for info in members:
            shown = safe_basename(info.filename)
            if is_unsafe_member(info.filename):
                out.skipped.append(Skipped(shown, SKIP_UNSAFE_PATH))
                continue
            if info.flag_bits & 0x1:
                out.skipped.append(Skipped(shown, SKIP_ENCRYPTED))
                continue
            if not info.filename.lower().endswith(ALLOWED_EXT):
                out.skipped.append(Skipped(shown, SKIP_EXTENSION))
                continue
            if info.file_size > MAX_FILE_BYTES or (
                info.compress_size and info.file_size / info.compress_size > MAX_RATIO
            ):
                out.skipped.append(Skipped(shown, SKIP_TOO_LARGE))
                continue
            try:
                with archive.open(info) as fh:
                    blob = fh.read(MAX_FILE_BYTES + 1)  # never trust the declared size
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
                out.skipped.append(Skipped(shown, SKIP_BAD_ZIP))
                continue
            _accept(info.filename, blob, out)
    return out


def extract_upload(filename: str, data: bytes, out: Optional[Extracted] = None) -> Extracted:
    """One uploaded file: a .zip archive is expanded, a .txt/.cfg is taken as-is."""
    out = out or Extracted()
    if filename.lower().endswith(".zip"):
        return extract_zip(data, out)
    _accept(filename, data, out)
    return out


# ----------------------------------------------------------------------------- conversion


def resolve_direction(direction: str, text: str) -> Optional[tuple[Vendor, Vendor]]:
    if direction in DIRECTIONS:
        return DIRECTIONS[direction]
    vendor = detect_vendor(text)
    if vendor is None:
        return None
    return DIRECTIONS["c2h" if vendor is Vendor.CISCO_IOS_XE else "h2c"]


def convert_files(
    db: Database,
    batch_id: str,
    extracted: Extracted,
    *,
    direction: str = "auto",
    mode: ConversionMode = ConversionMode.default(),
    translator: Optional[Translator] = None,
    complex_commands: Sequence[str] = (),
) -> list[dict]:
    """Convert each file in queue order. Returns one status row per input (incl. skipped)."""
    rows: list[dict] = []
    for skip in extracted.skipped:
        history.record_skipped(db, batch_id, skip.name, skip.reason)
        rows.append({"filename": skip.name, "status": "skipped", "reason": skip.reason})
    for item in extracted.files:
        pair = resolve_direction(direction, item.text)
        if pair is None:
            history.record_skipped(db, batch_id, item.name, SKIP_UNKNOWN_VENDOR)
            rows.append({"filename": item.name, "status": "skipped", "reason": SKIP_UNKNOWN_VENDOR})
            continue
        source, target = pair
        try:
            report = prescan_config(item.text, source, target)
            result = convert(item.text, source, target, mode=mode, translator=translator,
                             complex_commands=complex_commands)
        except Exception:  # one bad file must not stop the queue
            history.record_skipped(db, batch_id, item.name, SKIP_CONVERT_ERROR)
            rows.append({"filename": item.name, "status": "error", "reason": SKIP_CONVERT_ERROR})
            continue
        record_id = history.record_conversion(db, item.text, result, report, kind="batch",
                                              filename=item.name, batch_id=batch_id)
        counts = result.provenance_counts
        rows.append({
            "filename": item.name,
            "status": "review" if history.review_count(result) else "done",
            "history_id": record_id,
            "direction": history.DIRECTION_OF[source],
            "effective_mode": result.effective_mode.value,
            "coverage_percent": report.coverage_percent,
            "provenance_counts": counts,
            "review_count": history.review_count(result),
            "secret_stripped_count": result.secret_stripped_count,
            "warnings_count": len(result.warnings),
            "notices": result.notices,
            "output_name": output_name(item.name, target),
        })
    return rows


def output_name(filename: str, target: Vendor) -> str:
    stem = safe_basename(filename).rsplit(".", 1)[0] or "config"
    return f"{stem}_{TARGET_SUFFIX[target]}.txt"


# ----------------------------------------------------------------------------- packaging


def build_report(batch_id: str, records: list[dict], skipped: list[dict]) -> dict:
    files = [
        {
            "filename": r["filename"],
            "output": output_name(r["filename"] or f"config_{r['id']}", Vendor(r["target_vendor"])),
            "history_id": r["id"],
            "hostname": r["hostname"],
            "direction": r["direction"],
            "requested_mode": r["requested_mode"],
            "effective_mode": r["effective_mode"],
            "coverage_percent": r["coverage_percent"],
            "lines": {"RULE": r["count_rule"], "AI": r["count_ai"], "SYSTEM": r["count_system"],
                      "UNCONVERTED": r["count_unconverted"], "NOT_NEEDED": r["count_not_needed"]},
            "review_count": r["review_count"],
            "secret_stripped_count": r["secret_stripped_count"],
            "warnings": r.get("warnings", []),
            "status": "review" if r["review_count"] else "done",
        }
        for r in records
    ]
    return {
        "batch_id": batch_id,
        "generated_at": utcnow(),
        "converted": len(files),
        "skipped": len(skipped),
        "files": files,
        "skipped_files": skipped,
    }


def report_text(report: dict) -> str:
    out = [
        "NetMigrate — Migration Report / รายงานการแปลงแบบกลุ่ม",
        f"Batch: {report['batch_id']}",
        f"Generated (UTC): {report['generated_at']}",
        f"Converted files: {report['converted']}   Skipped files: {report['skipped']}",
        "",
        "Provenance labels: RULE=มาจากกฎ  AI=มาจาก AI ต้องตรวจสอบก่อนใช้  SYSTEM=ระบบสร้างขึ้นเอง  "
        "UNCONVERTED=แปลงไม่ได้  NOT_NEEDED=ไม่ต้องใช้คำสั่งนี้",
        "=" * 78,
    ]
    for f in report["files"]:
        l = f["lines"]
        out += [
            f"{f['filename']}  ->  {f['output']}   [{f['status'].upper()}]",
            f"  hostname={f['hostname'] or '-'}  direction={f['direction']}  mode={f['effective_mode']} "
            f"(requested {f['requested_mode']})  coverage={f['coverage_percent']}%",
            f"  RULE={l['RULE']} AI={l['AI']} SYSTEM={l['SYSTEM']} UNCONVERTED={l['UNCONVERTED']} "
            f"NOT_NEEDED={l['NOT_NEEDED']}  review={f['review_count']}  secrets_stripped={f['secret_stripped_count']}",
        ]
        out += [f"  ! {w}" for w in f["warnings"]]
        out.append("-" * 78)
    if report["skipped_files"]:
        out.append("Skipped / ไม่ได้แปลง:")
        out += [f"  {s['filename']}: {s['reason']}" for s in report["skipped_files"]]
    out.append("")
    return "\n".join(out)


def build_output_zip(batch_id: str, records: list[dict], skipped: list[dict]) -> bytes:
    """Converted configs + migration_report.txt/.json. Every member name is a safe basename."""
    report = build_report(batch_id, records, skipped)
    buf = io.BytesIO()
    used: set[str] = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rec, entry in zip(records, report["files"]):
            name = entry["output"]
            stem, n = name[:-4], 2
            while name in used:
                name = f"{stem}_{n}.txt"
                n += 1
            used.add(name)
            entry["output"] = name
            zf.writestr(name, rec["output_text"])
        zf.writestr("migration_report.json", json.dumps(report, ensure_ascii=False, indent=2))
        zf.writestr("migration_report.txt", report_text(report))
    return buf.getvalue()


def batch_records(db: Database, batch_id: str) -> list[dict]:
    listing = history.list_conversions(db, batch_id=batch_id, limit=500)
    ids = sorted(i["id"] for i in listing["items"])
    return [r for r in (history.get_conversion(db, i) for i in ids) if r is not None]
