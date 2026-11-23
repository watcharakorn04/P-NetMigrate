"""Module 4 — Configuration Deployment (Security Non-Negotiable #3)."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, SecretStr

from app.config import Settings, get_settings
from app.core.ir import Vendor
from app.db import Database
from app.deps import get_db
from app.services import deploy_service as deploy
from app.services import history_service as history
from app.services import inventory_service as inv
from app.web import render_page

router = APIRouter()


class PlanRequest(BaseModel):
    conversion_id: Optional[int] = None
    text: Optional[str] = Field(default=None, max_length=1_000_000)
    vendor: Optional[Vendor] = None


class RunRequest(BaseModel):
    vendor: Vendor
    commands: str = Field(max_length=1_000_000)  # the (possibly edited) list the user reviewed (4.1)
    conversion_id: Optional[int] = None
    device_id: Optional[int] = None
    mode: str = "simulation"
    confirm: bool = False  # 4.4: user saw the full command list and confirmed
    acknowledge_review: bool = False  # AI-labelled lines were removed and must be reviewed by hand
    lab_confirm: bool = False  # live: the target is a self-built EVE-NG virtual device
    username: SecretStr = SecretStr("")  # memory only — never logged / stored
    password: SecretStr = SecretStr("")


def _plan_for(req: PlanRequest, db: Database) -> deploy.DeployPlan:
    if req.conversion_id is not None:
        rec = history.get_conversion(db, req.conversion_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="conversion not found")
        return deploy.build_plan(rec["lines"], Vendor(rec["target_vendor"]))
    if not req.text or not req.text.strip() or req.vendor is None:
        raise HTTPException(status_code=422, detail="give a conversion_id, or text + vendor")
    return deploy.plan_from_text(req.text, req.vendor)


@router.get("/deploy", response_class=HTMLResponse)
def deploy_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    conversion = request.query_params.get("conversion")
    return render_page(request, "deploy.html", "nav_m4", settings,
                       preselect=int(conversion) if conversion and conversion.isdigit() else None)


@router.post("/api/deploy/plan")
def api_deploy_plan(req: PlanRequest, db: Database = Depends(get_db)) -> dict:
    """Filtered command list for review: what will be sent, and what was removed and why."""
    return _plan_for(req, db).to_json()


@router.post("/api/deploy/run")
def api_deploy_run(req: RunRequest, db: Database = Depends(get_db)) -> dict:
    if not req.confirm:
        raise HTTPException(status_code=400, detail="confirmation required: review the command list and confirm")
    blocked: list[str] = []
    if req.conversion_id is not None:
        rec = history.get_conversion(db, req.conversion_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="conversion not found")
        if rec["target_vendor"] != req.vendor.value:
            raise HTTPException(status_code=422, detail="vendor does not match the conversion's target vendor")
        plan = deploy.build_plan(rec["lines"], Vendor(rec["target_vendor"]))
        if plan.requires_review_ack and not req.acknowledge_review:
            raise HTTPException(
                status_code=409,
                detail="AI-generated lines (มาจาก AI ต้องตรวจสอบก่อนใช้) were removed from this deployment — "
                       "tick the review acknowledgement to continue",
            )
        blocked = plan.blocked_texts
    commands, removed = deploy.final_commands(req.commands, req.vendor, blocked)
    device = None
    if req.device_id is not None:
        device = inv.get_device(db, req.device_id)
        if device is None:
            raise HTTPException(status_code=404, detail="device not found")
        if device["vendor"] != req.vendor.value:
            raise HTTPException(status_code=422, detail="device vendor does not match the configuration vendor")
    if req.mode == "live":
        if device is None:
            raise HTTPException(status_code=422, detail="live mode needs a device from the inventory")
        if not req.lab_confirm:
            raise HTTPException(status_code=422, detail="live mode only targets self-built EVE-NG virtual devices — confirm the lab target")
        if not req.username.get_secret_value() or not req.password.get_secret_value():
            raise HTTPException(status_code=422, detail="SSH username and password are required for live mode")
    try:
        job = deploy.start_deployment(
            db, vendor=req.vendor, commands=commands, removed=removed, mode=req.mode, device=device,
            conversion_id=req.conversion_id, username=req.username.get_secret_value(),
            password=req.password.get_secret_value(),
        )
    except deploy.DeployError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {"job_id": job.id, "deployment_id": job.deployment_id, "mode": job.mode, "commands": commands,
            "removed": removed}


@router.get("/api/deploy/jobs/{job_id}/events")
async def api_deploy_events(job_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events: live log lines (INFO / SUCCESS / WARNING / ERROR / COMMAND) — 4.3."""
    job = deploy.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")

    async def stream():
        seq = 0
        while True:
            for entry in job.since(seq):
                seq = entry["seq"] + 1
                yield f"event: log\ndata: {json.dumps(entry, ensure_ascii=False)}\n\n"
            if job.done and seq >= len(job.since(0)):
                yield f"event: done\ndata: {json.dumps({'status': job.status, 'deployment_id': job.deployment_id})}\n\n"
                return
            if await request.is_disconnected():
                return
            await asyncio.sleep(0.1)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/api/deployments")
def api_deployments(db: Database = Depends(get_db)) -> dict:
    return {"items": deploy.list_deployments(db)}


@router.get("/api/deployments/{deployment_id}")
def api_deployment(deployment_id: int, db: Database = Depends(get_db)) -> dict:
    dep = deploy.get_deployment(db, deployment_id)
    if dep is None:
        raise HTTPException(status_code=404, detail="deployment not found")
    return dep


@router.get("/api/deployments/{deployment_id}/log.txt")
def api_deployment_log(deployment_id: int, db: Database = Depends(get_db)) -> Response:
    dep = deploy.get_deployment(db, deployment_id)
    if dep is None:
        raise HTTPException(status_code=404, detail="deployment not found")
    return Response(deploy.log_text(dep), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="deployment-{deployment_id}.log"'})
