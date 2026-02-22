import os
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "ZTNA Secure Banking API"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-me")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # DB Configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./ztna_banking.db")
    
    # ZTNA Configuration
    RISK_THRESHOLD_MEDIUM: float = 0.6
    RISK_THRESHOLD_HIGH: float = 0.8
    
    # Audit Logging
    LOG_LEVEL: str = "INFO"

    # Currency Conversion (2026 Simulation)
    EXCHANGE_RATE: float = 90.0
    CURRENCY_SYMBOL: str = "₹"

    # Threat Detection Thresholds
    DAILY_TRANSACTION_COUNT_LIMIT: int = 10
    VELOCITY_WINDOW_MINUTES: int = 10
    VELOCITY_THRESHOLD: int = 5
    AUTO_FREEZE_ALERT_THRESHOLD: int = 2
    
    # ngrok (dev only)
    PUBLIC_BASE_URL: Optional[str] = "https://thymiest-eliza-demiurgic.ngrok-free.dev"

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()