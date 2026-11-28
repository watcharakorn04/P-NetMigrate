"""Shared page plumbing: templates, the 8-module navigation, language handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates

from app.config import Settings
from app.core.ir import ConversionMode, Vendor
from app.i18n import normalize_lang, t, ui_dict
from app.services.mode_selector import mode_availability, resolve_mode

BASE_DIR = Path(__file__).parent
LANG_COOKIE = "lang"
# Bumped with every UI release: appended to /static URLs so browsers never run a stale script.
ASSET_VERSION = "0.5.1"

templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.globals["asset_v"] = ASSET_VERSION

DIRECTIONS = {
    "c2h": (Vendor.CISCO_IOS_XE, Vendor.HUAWEI_VRP),
    "h2c": (Vendor.HUAWEI_VRP, Vendor.CISCO_IOS_XE),
}

# The 8 modules of proposal §2.3.1 — all live.
NAV_MODULES = [
    {"key": "nav_m1", "href": "/", "icon": "M4 7h16M4 12h10M4 17h7"},
    {"key": "nav_m2", "href": "/batch", "icon": "M4 6h16v4H4zM4 14h16v4H4z"},
    {"key": "nav_m3", "href": "/inventory", "icon": "M3 5h18v6H3zM3 13h18v6H3zM7 8h.01M7 16h.01"},
    {"key": "nav_m4", "href": "/deploy", "icon": "M5 12h14M13 6l6 6-6 6"},
    {"key": "nav_m5", "href": "/history", "icon": "M4 19V9M10 19V5M16 19v-7M22 19H2"},
    {"key": "nav_m6", "href": "/settings", "icon": "M12 3v3M12 18v3M3 12h3M18 12h3M12 8a4 4 0 100 8 4 4 0 000-8z"},
    {"key": "nav_m7", "href": "/topology", "icon": "M6 6h.01M18 6h.01M12 18h.01M6 6l6 12 6-12"},
    {"key": "nav_m8", "href": "/hardware", "icon": "M9 3h6v4H9zM5 7h14v14H5zM9 12h6M9 16h6"},
]


def page_lang(request: Request, lang: Optional[str] = None) -> str:
    return normalize_lang(lang or request.query_params.get("lang") or request.cookies.get(LANG_COOKIE))


def render_page(request: Request, template: str, active: str, settings: Settings, **extra: Any) -> Response:
    lang = page_lang(request)
    ai_available = settings.llm_api_key_configured
    context = {
        "lang": lang,
        "t": lambda key: t(key, lang),
        "ui": ui_dict(lang),
        "nav": NAV_MODULES,
        "active": active,
        "ai_available": ai_available,
        "default_mode": resolve_mode(ConversionMode.default(), ai_available).value,
        "modes": [m.value for m in ConversionMode],
        "mode_availability": mode_availability(ai_available),
    }
    context.update(extra)
    response = templates.TemplateResponse(request, template, context)
    if request.query_params.get("lang"):
        response.set_cookie(LANG_COOKIE, lang, max_age=365 * 24 * 3600, samesite="lax")
    return response


def parse_direction(direction: str) -> tuple[Vendor, Vendor]:
    try:
        return DIRECTIONS[direction]
    except KeyError:
        raise HTTPException(status_code=422, detail="direction must be 'c2h' or 'h2c'") from None


def parse_mode(mode: str) -> ConversionMode:
    try:
        return ConversionMode(mode)
    except ValueError:
        raise HTTPException(status_code=422, detail="mode must be hybrid, rule_only or ai_only") from None


def parse_vendor(vendor: str) -> Vendor:
    try:
        return Vendor(vendor)
    except ValueError:
        raise HTTPException(status_code=422, detail="vendor must be cisco_ios_xe or huawei_vrp") from None


def decode_upload(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")
