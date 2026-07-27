from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Enterprise Cryptographic Discovery Platform"
    API_V1_STR: str = "/api/v1"
    
    # Database URL defaults to PostgreSQL, can fallback to SQLite for testing
    DATABASE_URL: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/qdiscovery"
    TEST_DATABASE_URL: Optional[str] = "sqlite:///:memory:"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
