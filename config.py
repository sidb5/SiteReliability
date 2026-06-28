import base64
from typing import List
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.fernet import Fernet


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    DATABASE_URL: str = "sqlite:///./watchdog.db"

    # JWT — RS256 asymmetric signing. Store as base64-encoded PEM in .env.
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Fernet encryption key for secrets at rest (webhook secrets, connection strings)
    FERNET_KEY: str

    # Platform bootstrap credentials (used once on first startup)
    PLATFORM_ADMIN_EMAIL: str
    PLATFORM_ADMIN_PASSWORD: str

    # Application
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "WARNING"
    CORS_ORIGINS: List[str] = ["http://localhost:8000"]

    # Rate limiting
    RATE_LIMIT_INGEST: str = "100/minute"
    RATE_LIMIT_AUTH: str = "10/minute"

    # Cache backend
    CACHE_BACKEND: str = "memory"
    REDIS_URL: str = "redis://localhost:6379/0"

    @field_validator("FERNET_KEY")
    @classmethod
    def validate_fernet_key(cls, v: str) -> str:
        try:
            Fernet(v.encode())
        except Exception:
            raise ValueError(
                "FERNET_KEY must be a valid Fernet key. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()

    def get_fernet(self) -> Fernet:
        return Fernet(self.FERNET_KEY.encode())

    def get_jwt_private_key(self) -> bytes:
        """Decode base64-encoded PEM private key."""
        try:
            return base64.b64decode(self.JWT_PRIVATE_KEY)
        except Exception:
            return self.JWT_PRIVATE_KEY.encode()

    def get_jwt_public_key(self) -> bytes:
        """Decode base64-encoded PEM public key."""
        try:
            return base64.b64decode(self.JWT_PUBLIC_KEY)
        except Exception:
            return self.JWT_PUBLIC_KEY.encode()


settings = Settings()
