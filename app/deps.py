"""FastAPI dependencies shared by every router (overridable in tests)."""

from __future__ import annotations

from typing import Iterator, Optional

from fastapi import Depends

from app.config import Settings, get_settings
from app.db import Database, database_for
from app.services.ai_translator import AITranslator, Translator


def get_translator(settings: Settings = Depends(get_settings)) -> Iterator[Optional[Translator]]:
    """AI client for this request, or None when no API key is configured."""
    translator = AITranslator.from_settings(settings)
    try:
        yield translator
    finally:
        if translator is not None:
            translator.close()


def get_db(settings: Settings = Depends(get_settings)) -> Database:
    """The SQLite database (single file, tables auto-created on first use)."""
    return database_for(settings.database_url)
