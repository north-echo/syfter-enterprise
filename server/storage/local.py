"""
Local filesystem storage backend.
"""

from pathlib import Path

from .base import StorageBackend
from ..config import StorageConfig


class LocalStorage(StorageBackend):
    """Local filesystem storage backend."""

    def __init__(self, config: StorageConfig):
        """
        Initialize local storage.

        Args:
            config: Storage configuration
        """
        self.base_path = config.local_path
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _get_path(self, key: str) -> Path:
        """Get full path for a key."""
        return self.base_path / key

    def put(self, key: str, data: bytes) -> int:
        """Store data at the given key."""
        path = self._get_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return len(data)

    def get(self, key: str) -> bytes:
        """Retrieve data from the given key."""
        path = self._get_path(key)
        if not path.exists():
            raise FileNotFoundError(f"Key not found: {key}")
        return path.read_bytes()

    def delete(self, key: str) -> bool:
        """Delete data at the given key."""
        path = self._get_path(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        return self._get_path(key).exists()

    def get_url(self, key: str, expires_in: int = 3600) -> str:
        """Get a file:// URL for local storage."""
        path = self._get_path(key)
        return f"file://{path.absolute()}"
