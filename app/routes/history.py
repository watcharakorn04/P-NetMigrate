"""Module 5 — Dashboard & Audit History."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.core.diff import source_aligned, text_diff
from app.db import Database
from app.deps import get_db
from app.i18n import provenance_label, translate_message
from app.core.ir import Provenance
from app.services import history_service as history
from app.web import page_lang, render_page

router = APIRouter()


def _record_or_404(db: Database, conversion_id: int) -> dict:
    rec = history.get_conversion(db, conversion_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="conversion not found")
    return rec


def _localize(rec: dict, lang: str) -> dict:
    for line in rec["lines"]:
        line["label"] = provenance_label(Provenance[line["provenance"]], lang)
        line["warning"] = translate_message(line.get("warning"), lang) or None
    rec["warnings"] = [translate_message(w, lang) for w in rec["warnings"]]
    rec["notices"] = [translate_message(n, lang) for n in rec["notices"]]
    return rec


# ----------------------------------------------------------------------------- pages


@router.get("/history", response_class=HTMLResponse)
def history_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "history.html", "nav_m5", settings)


@router.get("/history/{conversion_id}", response_class=HTMLResponse)
def history_detail_page(conversion_id: int, request: Request, settings: Settings = Depends(get_settings),
                        db: Database = Depends(get_db)) -> Response:
    _record_or_404(db, conversion_id)
    return render_page(request, "history_detail.html", "nav_m5", settings, conversion_id=conversion_id)


# ----------------------------------------------------------------------------- API


@router.get("/api/dashboard")
def api_dashboard(db: Database = Depends(get_db)) -> dict:
    return history.dashboard_stats(db)


@router.get("/api/history")
def api_history(q: Optional[str] = None, direction: Optional[str] = None, mode: Optional[str] = None,
                kind: Optional[str] = None, limit: int = 25, offset: int = 0, db: Database = Depends(get_db)) -> dict:
    return history.list_conversions(db, q=q, direction=direction, mode=mode, kind=kind, limit=limit, offset=offset)


@router.get("/api/history/export")
def api_history_export(q: Optional[str] = None, direction: Optional[str] = None, mode: Optional[str] = None,
                       kind: Optional[str] = None, ids: Optional[str] = None,
                       db: Database = Depends(get_db)) -> Response:
    """Export history as a JSON file (module 5.3). `ids` = comma-separated record ids."""
    id_list = None
    if ids:
        try:
            id_list = [int(i) for i in ids.split(",") if i.strip()]
        except ValueError:
            raise HTTPException(status_code=422, detail="ids must be comma-separated integers") from None
    records = history.export_conversions(db, ids=id_list) if id_list is not None else history.export_conversions(
        db, q=q, direction=direction, mode=mode, kind=kind)
    body = json.dumps({"exported": len(records), "conversions": records}, ensure_ascii=False, indent=2)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="netmigrate-history.json"'})


@router.get("/api/history/compare")
def api_history_compare(a: int, b: int, db: Database = Depends(get_db)) -> dict:
    """difflib comparison of two records' converted outputs (same target vendor expected)."""
    ra, rb = _record_or_404(db, a), _record_or_404(db, b)
    result = text_diff(ra["output_text"], rb["output_text"])
    result["same_target"] = ra["target_vendor"] == rb["target_vendor"]
    return result


@router.get("/api/history/{conversion_id}")
def api_history_detail(conversion_id: int, request: Request, lang: Optional[str] = None,
                       db: Database = Depends(get_db)) -> dict:
    return _localize(_record_or_404(db, conversion_id), page_lang(request, lang))


@router.get("/api/history/{conversion_id}/diff")
def api_history_diff(conversion_id: int, request: Request, lang: Optional[str] = None,
                     db: Database = Depends(get_db)) -> dict:
    """Before (sanitized source) vs after (converted), aligned line by line via provenance."""
    rec = _localize(_record_or_404(db, conversion_id), page_lang(request, lang))
    return {"id": rec["id"], "source_vendor": rec["source_vendor"], "target_vendor": rec["target_vendor"],
            "rows": source_aligned(rec["input_text"], rec["lines"])}


@router.get("/api/history/{conversion_id}/download")
def api_history_download(conversion_id: int, db: Database = Depends(get_db)) -> Response:
    rec = _record_or_404(db, conversion_id)
    stem = (rec["filename"] or rec["hostname"] or f"conversion-{rec['id']}").rsplit(".", 1)[0]
    stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stem)[:80] or "config"
    suffix = "huawei" if rec["target_vendor"] == "huawei_vrp" else "cisco"
    return Response(rec["output_text"], media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{stem}_{suffix}.txt"'})


@router.get("/api/history/{conversion_id}/export")
def api_history_export_one(conversion_id: int, db: Database = Depends(get_db)) -> Response:
    rec = _record_or_404(db, conversion_id)
    return Response(json.dumps(rec, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="netmigrate-conversion-{conversion_id}.json"'})


@router.delete("/api/history/{conversion_id}")
def api_history_delete(conversion_id: int, db: Database = Depends(get_db)) -> dict:
    if not history.delete_conversion(db, conversion_id):
        raise HTTPException(status_code=404, detail="conversion not found")
    return {"deleted": conversion_id}


@router.post("/api/diff")
def api_diff(left: str = Form(""), right: str = Form("")) -> dict:
    """Ad-hoc difflib comparison of two texts."""
    if len(left) + len(right) > 2_000_000:
        raise HTTPException(status_code=413, detail="texts too large")
    return text_diff(left, right)
