"""Module 8 — Hardware Compatibility Validation (pure rules, no AI)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.core.hardware import catalog_json, check_compatibility
from app.db import Database
from app.deps import get_db
from app.services import history_service as history
from app.services import inventory_service as inv
from app.web import parse_vendor, render_page

router = APIRouter()


@router.get("/hardware", response_class=HTMLResponse)
def hardware_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "hardware.html", "nav_m8", settings, catalog=catalog_json())


@router.get("/api/hardware/catalog")
def api_catalog(vendor: Optional[str] = None) -> dict:
    return {"items": catalog_json(parse_vendor(vendor) if vendor else None)}


@router.post("/api/hardware/check")
def api_hardware_check(
    config: Optional[str] = Form(None),
    vendor: Optional[str] = Form(None),
    conversion_id: Optional[int] = Form(None),
    model: Optional[str] = Form(None),
    device_id: Optional[int] = Form(None),
    db: Database = Depends(get_db),
) -> dict:
    """Check a converted config against a model (8.1) — the model may come from an inventory device.

    The config is pasted text (with `vendor`) or a history record's converted output.
    """
    if conversion_id is not None:
        rec = history.get_conversion(db, conversion_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="conversion not found")
        text, cfg_vendor = rec["output_text"], parse_vendor(rec["target_vendor"])
    else:
        if not config or not config.strip():
            raise HTTPException(status_code=422, detail="config is empty")
        if vendor is None:
            raise HTTPException(status_code=422, detail="vendor is required with pasted config")
        text, cfg_vendor = config, parse_vendor(vendor)
    device = None
    if device_id is not None:
        device = inv.get_device(db, device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        if not device["model"]:
            raise HTTPException(status_code=422, detail="this inventory device has no hardware model set")
        model = device["model"]
    if not model:
        raise HTTPException(status_code=422, detail="choose a model or an inventory device")
    try:
        result = check_compatibility(text, cfg_vendor, model)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    result["device"] = {"id": device["id"], "name": device["name"]} if device else None
    return result
