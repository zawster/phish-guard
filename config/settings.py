"""Application configuration settings."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application configuration."""

    # Application
    APP_NAME: str = "Phishing Detection System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    RAW_DATA_DIR: Path = DATA_DIR / "raw"
    PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
    MODELS_DIR: Path = DATA_DIR / "models"

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR}/phishing.db"

    # ML Model
    MODEL_PATH: Path = MODELS_DIR / "phishing_model.pkl"
    MODEL_THRESHOLD: float = 0.5

    # Phishing data
    PHISHTANK_CSV: Path = BASE_DIR / "verified_online.csv"

    # Alert thresholds
    ALERT_CRITICAL_THRESHOLD: float = 0.95
    ALERT_HIGH_THRESHOLD: float = 0.85
    ALERT_MEDIUM_THRESHOLD: float = 0.7
    ALERT_LOW_THRESHOLD: float = 0.5

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()

# Ensure directories exist
settings.RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
