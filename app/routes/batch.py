"""Module 2 — Batch File Conversion."""

from __future__ import annotations

import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.db import Database
from app.deps import get_db, get_translator
from app.i18n import translate_message
from app.services import batch_service as batch
from app.services import history_service as history
from app.services.ai_translator import Translator
from app.web import page_lang, parse_mode, render_page

router = APIRouter()
MAX_UPLOAD = 25_000_000
_BATCH_ID = re.compile(r"^[0-9a-f]{32}$")


def _batch_id(value: Optional[str]) -> str:
    if not value:
        return uuid.uuid4().hex
    if not _BATCH_ID.match(value):
        raise HTTPException(status_code=422, detail="invalid batch id")
    return value


@router.get("/batch", response_class=HTMLResponse)
def batch_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "batch.html", "nav_m2", settings)


@router.post("/api/batch/convert")
async def api_batch_convert(
    request: Request,
    files: list[UploadFile] = File(...),
    direction: str = Form("auto"),
    mode: str = Form("hybrid"),
    batch_id: Optional[str] = Form(None),
    lang: Optional[str] = Form(None),
    settings: Settings = Depends(get_settings),
    translator: Optional[Translator] = Depends(get_translator),
    db: Database = Depends(get_db),
) -> dict:
    """Convert one queue step: any number of .txt/.cfg files and/or .zip archives.

    The UI calls this once per queued item (so it can show progress, 2.3) with the same
    `batch_id`; everything converted under one id is downloadable as a single .zip.
    """
    if direction not in ("auto", "c2h", "h2c"):
        raise HTTPException(status_code=422, detail="direction must be auto, c2h or h2c")
    requested = parse_mode(mode)
    bid = _batch_id(batch_id)
    lang = page_lang(request, lang)
    extracted = batch.Extracted()
    total = 0
    for upload in files:
        data = await upload.read(MAX_UPLOAD + 1)
        total += len(data)
        if total > MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="upload too large (max 25 MB per request)")
        batch.extract_upload(upload.filename or "upload.txt", data, extracted)
    rows = batch.convert_files(db, bid, extracted, direction=direction, mode=requested, translator=translator,
                               complex_commands=settings.complex_command_prefixes)
    for row in rows:
        if "reason" in row:
            row["reason"] = translate_message(row["reason"], lang)
        if "notices" in row:
            row["notices"] = [translate_message(n, lang) for n in row["notices"]]
    return {"batch_id": bid, "ai_available": translator is not None, "rows": rows}


@router.get("/api/batch/{batch_id}")
def api_batch_status(batch_id: str, request: Request, db: Database = Depends(get_db)) -> dict:
    bid = _batch_id(batch_id)
    lang = page_lang(request)
    listing = history.list_conversions(db, batch_id=bid, limit=500)
    skipped = [{**s, "reason": translate_message(s["reason"], lang)} for s in history.skipped_for_batch(db, bid)]
    return {"batch_id": bid, "items": sorted(listing["items"], key=lambda r: r["id"]), "skipped": skipped}


@router.get("/api/batch/{batch_id}/download")
def api_batch_download(batch_id: str, db: Database = Depends(get_db)) -> Response:
    """All converted configs of the batch + migration_report.txt/.json as one .zip (2.4)."""
    bid = _batch_id(batch_id)
    records = batch.batch_records(db, bid)
    skipped = history.skipped_for_batch(db, bid)
    if not records and not skipped:
        raise HTTPException(status_code=404, detail="batch not found")
    data = batch.build_output_zip(bid, records, skipped)
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="netmigrate-batch-{bid[:8]}.zip"'})
