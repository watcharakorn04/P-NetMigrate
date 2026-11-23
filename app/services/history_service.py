"""Conversion audit history + dashboard statistics (proposal §2.3.1 module 5).

Every conversion (single and batch) is recorded with its mode, pre-scan coverage, per-line
provenance and counts. Persisted text is ALWAYS secret-free:
  * input  -> `strip_secrets_keep_lines` (credential lines replaced by a fixed advisory);
  * output -> the converted lines, which never contain a secret (Non-Negotiable #2), and are
              re-checked here as defence in depth before anything is written.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.core.engine import ConversionResult
from app.core.ir import Provenance, Vendor
from app.core.prescan import PrescanReport
from app.core.secret_stripper import contains_secret, strip_secrets_keep_lines
from app.db import Database, utcnow

DIRECTION_OF = {Vendor.CISCO_IOS_XE: "c2h", Vendor.HUAWEI_VRP: "h2c"}
SUMMARY_COLUMNS = (
    "id, created_at, kind, batch_id, filename, hostname, direction, source_vendor, target_vendor, "
    "requested_mode, effective_mode, coverage_percent, total_lines, unsupported_lines, count_rule, count_ai, "
    "count_system, count_unconverted, count_not_needed, review_count, secret_stripped_count, warnings_count"
)
# Advisory comments (fixed text, never a secret) are allowed through the defence-in-depth check.
_ADVISORY_MARK = f"[{Provenance.SYSTEM.value}]"


def _safe_line(text: str) -> str:
    """Final guard before persistence: a line that looks like a credential is never stored."""
    if _ADVISORY_MARK in text or not contains_secret(text):
        return text
    return "[ตัดข้อมูลลับออกก่อนบันทึก]"


def review_count(result: ConversionResult) -> int:
    """Commands that need human review: AI output lines + unconverted lines (module 5.1)."""
    ai = sum(1 for l in result.lines if l.provenance is Provenance.AI and not l.is_comment)
    return ai + result.provenance_counts.get("UNCONVERTED", 0)


def record_conversion(
    db: Database,
    raw: str,
    result: ConversionResult,
    prescan: PrescanReport,
    *,
    kind: str = "single",
    filename: Optional[str] = None,
    batch_id: Optional[str] = None,
) -> int:
    counts = result.provenance_counts
    lines = [
        {
            "text": _safe_line(l.text),
            "provenance": l.provenance.name,
            "is_comment": l.is_comment,
            "source_line": l.source_line,
            "category": l.category.value if l.category else None,
            "warning": l.warning,
        }
        for l in result.lines
    ]
    sanitized_input = "\n".join(_safe_line(x) for x in strip_secrets_keep_lines(raw, result.source_vendor).splitlines())
    output = "\n".join(l["text"] for l in lines) + "\n"
    with db.connect() as conn:
        cur = conn.execute(
            """INSERT INTO conversions (created_at, kind, batch_id, filename, hostname, direction, source_vendor,
                   target_vendor, requested_mode, effective_mode, coverage_percent, total_lines, unsupported_lines,
                   count_rule, count_ai, count_system, count_unconverted, count_not_needed, review_count,
                   secret_stripped_count, warnings_count, input_text, output_text, lines_json, warnings_json,
                   notices_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                utcnow(), kind, batch_id, filename, result.ir.hostname, DIRECTION_OF[result.source_vendor],
                result.source_vendor.value, result.target_vendor.value, result.requested_mode.value,
                result.effective_mode.value, prescan.coverage_percent, prescan.total_lines,
                prescan.unsupported_lines, counts["RULE"], counts["AI"], counts["SYSTEM"], counts["UNCONVERTED"],
                counts["NOT_NEEDED"], review_count(result), result.secret_stripped_count, len(result.warnings),
                sanitized_input, output, json.dumps(lines, ensure_ascii=False),
                json.dumps(result.warnings, ensure_ascii=False), json.dumps(result.notices, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)


# ----------------------------------------------------------------------------- queries


def _filters(q: Optional[str], direction: Optional[str], mode: Optional[str], kind: Optional[str],
             batch_id: Optional[str] = None) -> tuple[str, list[Any]]:
    where, args = [], []
    if q:
        like = f"%{q.strip()}%"
        where.append("(filename LIKE ? OR hostname LIKE ? OR input_text LIKE ? OR output_text LIKE ? OR CAST(id AS TEXT) = ?)")
        args += [like, like, like, like, q.strip()]
    if direction in ("c2h", "h2c"):
        where.append("direction = ?")
        args.append(direction)
    if mode in ("hybrid", "rule_only", "ai_only"):
        where.append("effective_mode = ?")
        args.append(mode)
    if kind in ("single", "batch"):
        where.append("kind = ?")
        args.append(kind)
    if batch_id:
        where.append("batch_id = ?")
        args.append(batch_id)
    return (" WHERE " + " AND ".join(where)) if where else "", args


def list_conversions(db: Database, q: Optional[str] = None, direction: Optional[str] = None,
                     mode: Optional[str] = None, kind: Optional[str] = None, batch_id: Optional[str] = None,
                     limit: int = 50, offset: int = 0) -> dict:
    where, args = _filters(q, direction, mode, kind, batch_id)
    limit = max(1, min(int(limit), 500))
    with db.connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM conversions{where}", args).fetchone()[0]
        rows = conn.execute(
            f"SELECT {SUMMARY_COLUMNS} FROM conversions{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            args + [limit, max(0, int(offset))],
        ).fetchall()
    return {"total": total, "items": [dict(r) for r in rows]}


def get_conversion(db: Database, conversion_id: int) -> Optional[dict]:
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM conversions WHERE id = ?", (conversion_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["lines"] = json.loads(data.pop("lines_json"))
    data["warnings"] = json.loads(data.pop("warnings_json"))
    data["notices"] = json.loads(data.pop("notices_json"))
    return data


def delete_conversion(db: Database, conversion_id: int) -> bool:
    with db.connect() as conn:
        return conn.execute("DELETE FROM conversions WHERE id = ?", (conversion_id,)).rowcount > 0


def export_conversions(db: Database, ids: Optional[list[int]] = None, **filters: Any) -> list[dict]:
    """Full records (incl. per-line provenance) for JSON export (module 5.3)."""
    if ids is not None:
        out = [get_conversion(db, i) for i in ids]
        return [r for r in out if r is not None]
    listing = list_conversions(db, limit=500, **filters)
    return [r for r in (get_conversion(db, i["id"]) for i in listing["items"]) if r is not None]


def record_skipped(db: Database, batch_id: str, filename: str, reason: str) -> None:
    with db.connect() as conn:
        conn.execute("INSERT INTO batch_skipped (batch_id, created_at, filename, reason) VALUES (?,?,?,?)",
                     (batch_id, utcnow(), filename, reason))


def skipped_for_batch(db: Database, batch_id: str) -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute("SELECT filename, reason FROM batch_skipped WHERE batch_id = ? ORDER BY id",
                            (batch_id,)).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------- dashboard


def dashboard_stats(db: Database, days: int = 14) -> dict:
    """Totals, lines per provenance, review count, daily trend and vendor split (module 5.1/5.2)."""
    with db.connect() as conn:
        tot = conn.execute(
            """SELECT COUNT(*) AS conversions, COALESCE(SUM(count_rule),0) AS RULE, COALESCE(SUM(count_ai),0) AS AI,
                      COALESCE(SUM(count_system),0) AS SYSTEM, COALESCE(SUM(count_unconverted),0) AS UNCONVERTED,
                      COALESCE(SUM(count_not_needed),0) AS NOT_NEEDED, COALESCE(SUM(review_count),0) AS review,
                      COALESCE(SUM(secret_stripped_count),0) AS secrets, COALESCE(AVG(coverage_percent),0) AS coverage
               FROM conversions"""
        ).fetchone()
        by_dir = {r["direction"]: r["n"] for r in conn.execute(
            "SELECT direction, COUNT(*) AS n FROM conversions GROUP BY direction")}
        by_mode = {r["effective_mode"]: r["n"] for r in conn.execute(
            "SELECT effective_mode, COUNT(*) AS n FROM conversions GROUP BY effective_mode")}
        by_kind = {r["kind"]: r["n"] for r in conn.execute("SELECT kind, COUNT(*) AS n FROM conversions GROUP BY kind")}
        per_day = {r["day"]: r["n"] for r in conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n FROM conversions GROUP BY day")}
        deployments = conn.execute("SELECT COUNT(*) FROM deployments").fetchone()[0]
        devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    today = datetime.now(timezone.utc).date()
    trend = [
        {"day": (d := (today - timedelta(days=i)).isoformat()), "count": per_day.get(d, 0)}
        for i in range(days - 1, -1, -1)
    ]
    return {
        "conversions": tot["conversions"],
        "lines": {k: tot[k] for k in ("RULE", "AI", "SYSTEM", "UNCONVERTED", "NOT_NEEDED")},
        "review_count": tot["review"],
        "secret_stripped": tot["secrets"],
        "avg_coverage": round(tot["coverage"], 1),
        "by_direction": {"c2h": by_dir.get("c2h", 0), "h2c": by_dir.get("h2c", 0)},
        "by_mode": {m: by_mode.get(m, 0) for m in ("hybrid", "rule_only", "ai_only")},
        "by_kind": {k: by_kind.get(k, 0) for k in ("single", "batch")},
        "trend": trend,
        "deployments": deployments,
        "devices": devices,
    }
