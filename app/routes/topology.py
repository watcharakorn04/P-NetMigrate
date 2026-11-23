"""Module 7 — Topology Analysis & Configuration Advisory."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.core.advisory import advise_sections
from app.core.topology import TopologyInput, ai_summary, analyze
from app.deps import get_translator
from app.services import batch_service as batch
from app.services.ai_translator import AIError, Translator
from app.web import page_lang, render_page

router = APIRouter()
MAX_UPLOAD = 10_000_000


@router.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "topology.html", "nav_m7", settings)


@router.post("/api/topology/analyze")
async def api_topology_analyze(files: list[UploadFile] = File(...)) -> dict:
    """Several configs of ONE network (.txt/.cfg or a .zip of them) -> topology + advisory."""
    extracted = batch.Extracted()
    total = 0
    for upload in files:
        data = await upload.read(MAX_UPLOAD + 1)
        total += len(data)
        if total > MAX_UPLOAD:
            raise HTTPException(status_code=413, detail="upload too large")
        batch.extract_upload(upload.filename or "config.txt", data, extracted)
    if not extracted.files:
        raise HTTPException(status_code=422, detail="no readable .txt/.cfg configuration in the upload")
    result = analyze([TopologyInput(f.name, f.text) for f in extracted.files])
    irs = result.pop("_irs")
    for dev, ir in zip(result["devices"], irs):
        uplinks = {p["name"] for p in dev["ports"] if p["role"] == "uplink"}
        dev["advisory"] = {str(k): v for k, v in advise_sections(ir, uplinks).items()}
    result["skipped"] = [{"filename": s.name, "reason": s.reason} for s in extracted.skipped]
    result["summary"] = ai_summary(result)
    return result


@router.post("/api/topology/describe")
def api_topology_describe(request: Request, summary: dict[str, Any] = Body(..., embed=True),
                          lang: Optional[str] = Body(None, embed=True),
                          translator: Optional[Translator] = Depends(get_translator)) -> dict:
    """AI part of 7.2 (roles / unresolved links / explanation). Without AI: rules-only notice."""
    describe = getattr(translator, "describe_topology", None)
    if translator is None or describe is None:
        return {"available": False, "text": None}
    try:
        text = describe(summary, page_lang(request, lang))
    except AIError:
        return {"available": True, "error": True, "text": None}
    return {"available": True, "text": text, "label": "มาจาก AI ต้องตรวจสอบก่อนใช้"}
