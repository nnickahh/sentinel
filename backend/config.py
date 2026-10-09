import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # Nebius Token Factory Credentials
    nebius_api_key: Optional[str] = None
    nebius_base_url: str = "https://api.studio.nebius.ai/v1/"
    nebius_model: str = "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF"
    nebius_timeout: int = 45

    # Sentinel App Settings
    sentinel_host: str = "127.0.0.1"
    sentinel_port: int = 8765
    sentinel_demo_mode: bool = True
    database_path: str = str(BASE_DIR / "sentinel_data.db")
    
    # Model configuration for environment loading
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def is_nebius_configured(self) -> bool:
        """Check if a real Nebius API key is configured."""
        if not self.nebius_api_key:
            return False
        clean_key = self.nebius_api_key.strip()
        return bool(clean_key and clean_key != "your_nebius_api_key_here")

# Global singleton settings instance
settings = Settings()
