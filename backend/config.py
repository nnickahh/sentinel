import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _HAS_PYDANTIC_SETTINGS = True
except ImportError:
    from pydantic import BaseModel as BaseSettings
    _HAS_PYDANTIC_SETTINGS = False

class Settings(BaseSettings):
    # Nebius Token Factory Credentials
    nebius_api_key: Optional[str] = os.getenv("NEBIUS_API_KEY")
    nebius_base_url: str = os.getenv("NEBIUS_BASE_URL", "https://api.studio.nebius.ai/v1/")
    nebius_model: str = os.getenv("NEBIUS_MODEL", "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF")
    nebius_timeout: int = int(os.getenv("NEBIUS_TIMEOUT", "45"))

    # Sentinel App Settings
    sentinel_host: str = os.getenv("SENTINEL_HOST", "127.0.0.1")
    sentinel_port: int = int(os.getenv("SENTINEL_PORT", "8765"))
    sentinel_demo_mode: bool = os.getenv("SENTINEL_DEMO_MODE", "true").lower() in ("true", "1", "yes")
    database_path: str = os.getenv("DATABASE_PATH", str(BASE_DIR / "sentinel_data.db"))
    
    if _HAS_PYDANTIC_SETTINGS:
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
