"""
Base storage interface.
"""

import gzip
import io
import json
from abc import ABC, abstractmethod
from typing import Optional

from ..config import get_config

# Global storage instance
_storage: Optional["StorageBackend"] = None

# Maximum decompressed size to prevent zip bombs (4GB)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_gzip_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.

    Args:
        data: Compressed gzip data
        max_size: Maximum allowed decompressed size in bytes

    Returns:
        Decompressed bytes

    Raises:
        ValueError: If decompressed size exceeds limit
    """
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)  # Read 1MB at a time
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB"
            )
        chunks.append(chunk)

    return b''.join(chunks)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def put(self, key: str, data: bytes) -> int:
        """
        Store data at the given key.

        Args:
            key: Storage key/path
            data: Raw bytes to store

        Returns:
            int: Size of stored data in bytes
        """
        pass

    @abstractmethod
    def get(self, key: str) -> bytes:
        """
        Retrieve data from the given key.

        Args:
            key: Storage key/path

        Returns:
            bytes: Raw data

        Raises:
            FileNotFoundError: If key doesn't exist
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete data at the given key.

        Args:
            key: Storage key/path

        Returns:
            bool: True if deleted, False if not found
        """
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """
        Check if a key exists.

        Args:
            key: Storage key/path

        Returns:
            bool: True if exists
        """
        pass

    @abstractmethod
    def get_url(self, key: str, expires_in: int = 3600) -> str:
        """
        Get a URL to access the data (presigned for S3, file:// for local).

        Args:
            key: Storage key/path
            expires_in: URL expiration in seconds (for presigned URLs)

        Returns:
            str: URL to access the data
        """
        pass

    @abstractmethod
    def get_presigned_upload_url(self, key: str, expires_in: int = 3600) -> str:
        """
        Get a presigned URL for uploading data.

        Args:
            key: Storage key/path
            expires_in: URL expiration in seconds

        Returns:
            str: Presigned URL for PUT upload
        """
        pass

    @abstractmethod
    def copy(self, src_key: str, dst_key: str) -> bool:
        """
        Copy data from one key to another.

        Args:
            src_key: Source key
            dst_key: Destination key

        Returns:
            bool: True if successful
        """
        pass

    @abstractmethod
    def get_size(self, key: str) -> int:
        """
        Get the size of stored data.

        Args:
            key: Storage key/path

        Returns:
            int: Size in bytes
        """
        pass

    def put_json(self, key: str, data: dict, compress: bool = True) -> int:
        """
        Store JSON data, optionally compressed.

        Args:
            key: Storage key/path
            data: Dictionary to store as JSON
            compress: Whether to gzip compress (default: True)

        Returns:
            int: Size of stored data in bytes
        """
        json_str = json.dumps(data)
        if compress:
            raw_data = gzip.compress(json_str.encode("utf-8"))
        else:
            raw_data = json_str.encode("utf-8")
        return self.put(key, raw_data)

    def get_json(self, key: str, compressed: bool = True) -> dict:
        """
        Retrieve JSON data, optionally decompressing.

        Args:
            key: Storage key/path
            compressed: Whether data is gzip compressed (default: True)

        Returns:
            dict: Parsed JSON data
        """
        raw_data = self.get(key)
        if compressed:
            json_str = _safe_gzip_decompress(raw_data).decode("utf-8")
        else:
            json_str = raw_data.decode("utf-8")
        return json.loads(json_str)


def get_storage() -> StorageBackend:
    """Get the configured storage backend."""
    global _storage
    if _storage is None:
        config = get_config()
        if config.storage.type == "s3":
            from .s3 import S3Storage
            _storage = S3Storage(config.storage)
        else:
            from .local import LocalStorage
            _storage = LocalStorage(config.storage)
    return _storage


def reset_storage() -> None:
    """Reset the storage instance (useful for testing)."""
    global _storage
    _storage = None
