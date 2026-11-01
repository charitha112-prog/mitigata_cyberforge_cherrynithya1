from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "IntegrateX"
    app_env: str = "development"
    secret_key: str = "CHANGE_ME"
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/integratex_db"
    credential_encryption_key: str = ""
    sarvam_api_key: str = ""
    sarvam_model: str = "sarvam-m"
    sarvam_base_url: str = "https://api.sarvam.ai"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    allow_private_targets: bool = False
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

@lru_cache
def get_settings():
    return Settings()

settings = get_settings()
