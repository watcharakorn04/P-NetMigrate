"""Module 3 — Device Inventory (a register only; never connects to devices)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from app.config import Settings, get_settings
from app.core.hardware import catalog_json
from app.db import Database
from app.deps import get_db
from app.services import inventory_service as inv
from app.web import render_page

router = APIRouter()


@router.get("/inventory", response_class=HTMLResponse)
def inventory_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "inventory.html", "nav_m3", settings, catalog=catalog_json(), statuses=inv.STATUSES)


@router.get("/api/devices")
def api_devices(q: Optional[str] = None, vendor: Optional[str] = None, location: Optional[str] = None,
                status: Optional[str] = None, db: Database = Depends(get_db)) -> dict:
    return {"items": inv.list_devices(db, q=q, vendor=vendor, location=location, status=status)}


@router.get("/api/devices/{device_id}")
def api_device(device_id: int, db: Database = Depends(get_db)) -> dict:
    device = inv.get_device(db, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device


def _validated(fn, *args):
    try:
        return fn(*args)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.post("/api/devices", status_code=201)
def api_device_create(data: inv.DeviceIn, db: Database = Depends(get_db)) -> dict:
    return _validated(inv.create_device, db, data)


@router.put("/api/devices/{device_id}")
def api_device_update(device_id: int, data: inv.DeviceIn, db: Database = Depends(get_db)) -> dict:
    device = _validated(inv.update_device, db, device_id, data)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")
    return device


@router.delete("/api/devices/{device_id}")
def api_device_delete(device_id: int, db: Database = Depends(get_db)) -> dict:
    if not inv.delete_device(db, device_id):
        raise HTTPException(status_code=404, detail="device not found")
    return {"deleted": device_id}
