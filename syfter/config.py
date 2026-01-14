"""
Client configuration.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ClientConfig:
    """Client configuration."""

    # Server URL (None = local mode using sqlite directly)
    server_url: Optional[str] = None

    # Local mode settings (used when server_url is None)
    local_db_path: Path = Path("~/.syfter/syfter.db")
    local_storage_path: Path = Path("~/.syfter/sboms")

    @property
    def is_local_mode(self) -> bool:
        """Check if running in local mode (no server)."""
        return self.server_url is None

    @classmethod
    def from_env(cls) -> "ClientConfig":
        """Load configuration from environment variables."""
        server_url = os.getenv("SYFTER_SERVER")

        return cls(
            server_url=server_url,
            local_db_path=Path(
                os.getenv("SYFTER_LOCAL_DB", "~/.syfter/syfter.db")
            ).expanduser(),
            local_storage_path=Path(
                os.getenv("SYFTER_LOCAL_STORAGE", "~/.syfter/sboms")
            ).expanduser(),
        )


# Global config instance
_config: Optional[ClientConfig] = None


def get_client_config() -> ClientConfig:
    """Get the global client configuration."""
    global _config
    if _config is None:
        _config = ClientConfig.from_env()
    return _config


def set_client_config(config: ClientConfig) -> None:
    """Set the global client configuration."""
    global _config
    _config = config
