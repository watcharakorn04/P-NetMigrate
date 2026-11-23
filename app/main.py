"""NetMigrate FastAPI application — all 8 modules of proposal §2.3.1.

Module 1 (single conversion) lives here; the other modules are routers in `app/routes/`:
  2 batch · 3 inventory · 4 deploy · 5 history/dashboard · 6 settings · 7 topology · 8 hardware

API (module 1):
        GET  /api/health             key configured? which modes usable? (never echoes the key)
        POST /api/prescan            rule coverage report, nothing converted or sent
        POST /api/convert            hybrid | rule_only | ai_only   (recorded in the audit history)
        POST /api/convert/selected   rule_only + user-picked "แปลงไม่ได้" lines to AI (recorded)
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import Settings, get_settings
from app.core.engine import ConversionResult, convert, convert_selected
from app.core.ir import ConversionMode
from app.core.prescan import prescan_config
from app.db import Database, database_for
from app.deps import get_db, get_translator
from app.i18n import normalize_lang, provenance_label, translate_message
from app.routes import batch, deploy, hardware, history, inventory, settings_page, topology
from app.services import history_service
from app.services.ai_translator import Translator
from app.services.mode_selector import mode_availability, resolve_mode
from app.web import BASE_DIR, LANG_COOKIE, NAV_MODULES, decode_upload, page_lang, parse_direction, parse_mode, render_page

MAX_UPLOAD_BYTES = 1_000_000

__all__ = ["app", "get_translator", "get_db", "NAV_MODULES", "LANG_COOKIE"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    database_for(get_settings().database_url)  # create the SQLite file + tables on startup
    yield


app = FastAPI(title="NetMigrate", version="0.5.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
for module in (batch, inventory, deploy, history, settings_page, topology, hardware):
    app.include_router(module.router)


# ----------------------------------------------------------------------------- helpers


def _lang(request: Request, lang: Optional[str] = None) -> str:
    return page_lang(request, lang)


async def _source_text(config: Optional[str], file: Optional[UploadFile]) -> str:
    """Uploaded .txt wins over the editor text."""
    if file is not None and file.filename:
        if not file.filename.lower().endswith(".txt"):
            raise HTTPException(status_code=415, detail="only .txt files are accepted")
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="file too large (max 1 MB)")
        return decode_upload(data)
    text = config or ""
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="config too large (max 1 MB)")
    return text


def _require_text(text: str) -> str:
    if not text.strip():
        raise HTTPException(status_code=422, detail="config is empty")
    return text


def _result_json(result: ConversionResult, lang: str, ai_available: bool) -> dict:
    return {
        "source_vendor": result.source_vendor.value,
        "target_vendor": result.target_vendor.value,
        "requested_mode": result.requested_mode.value,
        "effective_mode": result.effective_mode.value,
        "ai_available": ai_available,
        "lines": [
            {
                "text": l.text,
                "provenance": l.provenance.name,
                "label": provenance_label(l.provenance, lang),
                "is_comment": l.is_comment,
                "source_line": l.source_line,
                "category": l.category.value if l.category else None,
                "warning": translate_message(l.warning, lang) or None,
            }
            for l in result.lines
        ],
        "text": result.text,  # clean CLI text for copy / download (no UI badges)
        "warnings": [translate_message(w, lang) for w in result.warnings],
        "notices": [translate_message(n, lang) for n in result.notices],
        "unconverted_items": [
            {"line_no": i.line_no, "command": i.command, "reason": translate_message(i.reason, lang)}
            for i in result.unconverted_items
        ],
        "secret_stripped_count": result.secret_stripped_count,
        "ai_sent_line_numbers": result.ai_sent_line_numbers,
        "ai_line_count": result.ai_line_count,
        "provenance_counts": result.provenance_counts,
    }


def _recorded(db: Database, text: str, result: ConversionResult, file: Optional[UploadFile], lang: str,
              ai_available: bool) -> dict:
    """Persist the conversion (module 5.3, secret-free) and return the API payload with its id."""
    report = prescan_config(text, result.source_vendor, result.target_vendor)
    filename = file.filename if file is not None and file.filename else None
    data = _result_json(result, lang, ai_available)
    data["coverage_percent"] = report.coverage_percent
    data["history_id"] = history_service.record_conversion(db, text, result, report, filename=filename)
    return data


# ----------------------------------------------------------------------------- pages


@app.get("/", response_class=HTMLResponse)
def convert_single_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    return render_page(request, "convert_single.html", "nav_m1", settings)


# ----------------------------------------------------------------------------- API


@app.get("/api/health")
def health(lang: Optional[str] = None, settings: Settings = Depends(get_settings)) -> dict:
    """Report whether the LLM API key is set and which modes are usable.

    Never echoes the key itself.
    """
    key_configured = settings.llm_api_key_configured
    ai_available = key_configured
    default_mode = ConversionMode.default()
    effective_mode = resolve_mode(default_mode, ai_available)
    lang = normalize_lang(lang)

    return {
        "status": "ok",
        "llm_api_key_configured": key_configured,
        "ai_available": ai_available,
        "llm_model": settings.llm_model if key_configured else None,
        "default_mode": default_mode.value,
        "effective_mode": effective_mode.value,
        "modes": mode_availability(ai_available),
        "message": (
            ("AI พร้อมใช้งาน" if lang == "th" else "AI is available")
            if ai_available
            else (
                "ยังไม่ได้ตั้งค่า API Key หรือ AI ใช้งานไม่ได้ — ระบบทำงานแบบกฎอย่างเดียว (rule_only)"
                if lang == "th"
                else "No API key configured or AI unavailable — running in rule-only mode"
            )
        ),
    }


@app.post("/api/prescan")
async def api_prescan(
    request: Request,
    direction: str = Form("c2h"),
    config: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    lang: Optional[str] = Form(None),
) -> dict:
    lang = _lang(request, lang)
    source, target = parse_direction(direction)
    text = _require_text(await _source_text(config, file))
    report = prescan_config(text, source, target)
    data = report.model_dump(mode="json")
    for item in data["unsupported_items"]:
        item["reason"] = translate_message(item["reason"], lang)
    return data


@app.post("/api/convert")
async def api_convert(
    request: Request,
    direction: str = Form("c2h"),
    mode: str = Form(ConversionMode.default().value),
    config: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    lang: Optional[str] = Form(None),
    settings: Settings = Depends(get_settings),
    translator: Optional[Translator] = Depends(get_translator),
    db: Database = Depends(get_db),
) -> dict:
    lang = _lang(request, lang)
    source, target = parse_direction(direction)
    requested = parse_mode(mode)
    text = _require_text(await _source_text(config, file))
    result = convert(
        text,
        source,
        target,
        mode=requested,
        translator=translator,
        complex_commands=settings.complex_command_prefixes,
    )
    return _recorded(db, text, result, file, lang, translator is not None)


@app.post("/api/convert/selected")
async def api_convert_selected(
    request: Request,
    direction: str = Form("c2h"),
    line_numbers: str = Form(""),
    config: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    lang: Optional[str] = Form(None),
    translator: Optional[Translator] = Depends(get_translator),
    db: Database = Depends(get_db),
) -> dict:
    """`line_numbers`: comma-separated source line numbers picked from a rule_only result."""
    lang = _lang(request, lang)
    source, target = parse_direction(direction)
    text = _require_text(await _source_text(config, file))
    try:
        selected = [int(n) for n in line_numbers.replace(" ", "").split(",") if n]
    except ValueError:
        raise HTTPException(status_code=422, detail="line_numbers must be comma-separated integers") from None
    result = convert_selected(text, source, target, selected, translator)
    return _recorded(db, text, result, file, lang, translator is not None)
