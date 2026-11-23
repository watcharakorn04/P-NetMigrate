"""NetMigrate FastAPI application.

Module 1 (single file / CLI conversion) and module 6 (theme, language, API health).

Pages:  GET  /                       single-conversion workspace (?lang=th|en, cookie-persisted)
API:    GET  /api/health             key configured? which modes usable? (never echoes the key)
        POST /api/prescan            rule coverage report, nothing converted or sent
        POST /api/convert            hybrid | rule_only | ai_only
        POST /api/convert/selected   rule_only + user-picked "แปลงไม่ได้" lines to AI
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import Settings, get_settings
from app.core.engine import ConversionResult, convert, convert_selected
from app.core.ir import ConversionMode, Vendor
from app.core.prescan import prescan_config
from app.i18n import normalize_lang, provenance_label, t, translate_message, ui_dict
from app.services.ai_translator import AITranslator, Translator
from app.services.mode_selector import mode_availability, resolve_mode

BASE_DIR = Path(__file__).parent
MAX_UPLOAD_BYTES = 1_000_000
LANG_COOKIE = "lang"

app = FastAPI(title="NetMigrate", version="0.4.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

DIRECTIONS = {
    "c2h": (Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP),
    "h2c": (Vendor.HUAWEI_VRP, Vendor.CISCO_IOS_XE),
}

# The 8 modules of proposal §2.3.1. Module 1 and 6 are live in this milestone.
NAV_MODULES = [
    {"key": "nav_m1", "href": "/", "live": True, "icon": "M4 7h16M4 12h10M4 17h7"},
    {"key": "nav_m2", "href": None, "live": False, "icon": "M4 6h16v4H4zM4 14h16v4H4z"},
    {"key": "nav_m3", "href": None, "live": False, "icon": "M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01"},
    {"key": "nav_m4", "href": None, "live": False, "icon": "M5 12h14M13 6l6 6-6 6"},
    {"key": "nav_m5", "href": None, "live": False, "icon": "M4 19V9M10 19V5M16 19v-7M22 19H2"},
    {"key": "nav_m6", "href": "/api/health", "live": True, "icon": "M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 100 8 4 4 0 000-8z"},
    {"key": "nav_m7", "href": None, "live": False, "icon": "M6 6h.01M18 6h.01M12 18h.01M6 6l6 12 6-12"},
    {"key": "nav_m8", "href": None, "live": False, "icon": "M9 3h6v4H9zM5 7h14v14H5zM9 12h6M9 16h6"},
]


# ----------------------------------------------------------------------------- dependencies


def get_translator(settings: Settings = Depends(get_settings)) -> Iterator[Optional[Translator]]:
    """AI client for this request, or None when no API key is configured."""
    translator = AITranslator.from_settings(settings)
    try:
        yield translator
    finally:
        if translator is not None:
            translator.close()


def _lang(request: Request, lang: Optional[str] = None) -> str:
    return normalize_lang(lang or request.query_params.get("lang") or request.cookies.get(LANG_COOKIE))


def _direction(direction: str) -> tuple[Vendor, Vendor]:
    try:
        return DIRECTIONS[direction]
    except KeyError:
        raise HTTPException(status_code=422, detail="direction must be 'c2h' or 'h2c'") from None


def _mode(mode: str) -> ConversionMode:
    try:
        return ConversionMode(mode)
    except ValueError:
        raise HTTPException(status_code=422, detail="mode must be hybrid, rule_only or ai_only") from None


async def _source_text(config: Optional[str], file: Optional[UploadFile]) -> str:
    """Uploaded .txt wins over the editor text."""
    if file is not None and file.filename:
        if not file.filename.lower().endswith(".txt"):
            raise HTTPException(status_code=415, detail="only .txt files are accepted")
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="file too large (max 1 MB)")
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data.decode("latin-1")
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


# ----------------------------------------------------------------------------- pages


@app.get("/", response_class=HTMLResponse)
def convert_single_page(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    lang = _lang(request)
    ai_available = settings.llm_api_key_configured
    response = templates.TemplateResponse(
        request,
        "convert_single.html",
        {
            "lang": lang,
            "t": lambda key: t(key, lang),
            "ui": ui_dict(lang),
            "nav": NAV_MODULES,
            "active": "nav_m1",
            "ai_available": ai_available,
            "default_mode": resolve_mode(ConversionMode.default(), ai_available).value,
            "modes": [m.value for m in ConversionMode],
            "mode_availability": mode_availability(ai_available),
        },
    )
    if request.query_params.get("lang"):
        response.set_cookie(LANG_COOKIE, lang, max_age=365 * 24 * 3600, samesite="lax")
    return response


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
    source, target = _direction(direction)
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
) -> dict:
    lang = _lang(request, lang)
    source, target = _direction(direction)
    requested = _mode(mode)
    text = _require_text(await _source_text(config, file))
    result = convert(
        text,
        source,
        target,
        mode=requested,
        translator=translator,
        complex_commands=settings.complex_command_prefixes,
    )
    return _result_json(result, lang, translator is not None)


@app.post("/api/convert/selected")
async def api_convert_selected(
    request: Request,
    direction: str = Form("c2h"),
    line_numbers: str = Form(""),
    config: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    lang: Optional[str] = Form(None),
    translator: Optional[Translator] = Depends(get_translator),
) -> dict:
    """`line_numbers`: comma-separated source line numbers picked from a rule_only result."""
    lang = _lang(request, lang)
    source, target = _direction(direction)
    text = _require_text(await _source_text(config, file))
    try:
        selected = [int(n) for n in line_numbers.replace(" ", "").split(",") if n]
    except ValueError:
        raise HTTPException(status_code=422, detail="line_numbers must be comma-separated integers") from None
    result = convert_selected(text, source, target, selected, translator)
    return _result_json(result, lang, translator is not None)
