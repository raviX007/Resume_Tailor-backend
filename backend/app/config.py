"""Application settings loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    openai_api_key: str = ""
    google_ai_api_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_public_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"
    llm_model: str = "gpt-4o-mini"
    gemini_model: str = "gemini-2.0-flash"
    base_tex_path: str = "resume_base.tex"
    output_dir: str = "output"
    allowed_origins: str = "http://localhost:3000"
    log_level: str = "INFO"
    auth_username: str = ""
    auth_password: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


_settings: Settings | None = None


def load_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
