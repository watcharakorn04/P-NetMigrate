"""Application settings, loaded from environment / .env."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    llm_api_key: str = ""
    # Any OpenAI-compatible Chat Completions endpoint.
    llm_api_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 60.0
    # Proposal §2.3.1 item 1.2.2 (3rd case): block headers (case-insensitive prefixes,
    # comma-separated) that hybrid mode always sends to AI even when a rule converted them.
    ai_complex_commands: str = ""
    database_url: str = "sqlite:///./netmigrate.db"

    @property
    def llm_api_key_configured(self) -> bool:
        return bool(self.llm_api_key.strip())

    @property
    def complex_command_prefixes(self) -> list[str]:
        return [p.strip().lower() for p in self.ai_complex_commands.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
