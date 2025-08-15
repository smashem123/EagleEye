"""
Core configuration settings for ScamSwatter API
"""
from typing import List, Optional
from pydantic import BaseSettings, validator
import os


class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "ScamSwatter"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Real-Time Scam Intelligence Platform"
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str
    DATABASE_URL_ASYNC: str
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v
    
    # External API Keys
    PHISHTANK_API_KEY: Optional[str] = None
    URLVOID_API_KEY: Optional[str] = None
    FTC_API_KEY: Optional[str] = None
    
    # Application Settings
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    MAX_CONNECTIONS_COUNT: int = 10
    MIN_CONNECTIONS_COUNT: int = 10
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
