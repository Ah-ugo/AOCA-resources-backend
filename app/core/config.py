from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Optional
import os
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    PROJECT_NAME: str = "AOCA Platform API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Security
    SECRET_KEY: str = "super-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # MongoDB
    MONGODB_URI: str = os.getenv("MONGODB_URI") or os.getenv("MONGO_URL")
    MONGODB_DB_NAME: str = "aoca_resources"

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Optional integrations
    API_KEY: Optional[str] = None
    API_SECRET: Optional[str] = None
    CLOUD_NAME: Optional[str] = None
    GMAIL_ADDRESS: Optional[str] = None
    GMAIL_PASS: Optional[str] = None
    GOOGLE_API_URL: Optional[str] = None
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    MONGO_URL: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=True, extra="ignore"
    )


settings = Settings()
