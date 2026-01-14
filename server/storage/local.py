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

    def get_presigned_upload_url(self, key: str, expires_in: int = 3600) -> str:
        """
        Get URL for uploading (for local storage, returns file:// path).

        Note: Local storage doesn't support presigned URLs, so this returns
        a special URL that the client should interpret as a local path.
        """
        path = self._get_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"file://{path.absolute()}"

    def copy(self, src_key: str, dst_key: str) -> bool:
        """Copy data from one key to another."""
        import shutil
        src_path = self._get_path(src_key)
        dst_path = self._get_path(dst_key)
        if not src_path.exists():
            return False
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        return True

    def get_size(self, key: str) -> int:
        """Get the size of stored data."""
        path = self._get_path(key)
        if path.exists():
            return path.stat().st_size
        return 0
