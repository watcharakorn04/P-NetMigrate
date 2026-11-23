"""NetMigrate FastAPI application."""

from fastapi import Depends, FastAPI

from app.config import Settings, get_settings
from app.core.ir import ConversionMode
from app.services.mode_selector import mode_availability, resolve_mode

app = FastAPI(title="NetMigrate", version="0.1.0")


@app.get("/api/health")
def health(settings: Settings = Depends(get_settings)) -> dict:
    """Report whether the LLM API key is set and which modes are usable.

    Never echoes the key itself.
    """
    key_configured = settings.llm_api_key_configured
    # Milestone 1: availability == key configured. A live connectivity probe can be
    # added once the AI client exists in app/services/.
    ai_available = key_configured
    default_mode = ConversionMode.default()
    effective_mode = resolve_mode(default_mode, ai_available)

    return {
        "status": "ok",
        "llm_api_key_configured": key_configured,
        "ai_available": ai_available,
        "default_mode": default_mode.value,
        "effective_mode": effective_mode.value,
        "modes": mode_availability(ai_available),
        "message": (
            "AI พร้อมใช้งาน"
            if ai_available
            else "ยังไม่ได้ตั้งค่า API Key หรือ AI ใช้งานไม่ได้ — ระบบทำงานแบบกฎอย่างเดียว (rule_only)"
        ),
    }
