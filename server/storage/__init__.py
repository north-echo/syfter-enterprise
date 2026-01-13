"""
Storage module - abstraction for SBOM file storage.
"""

from .base import StorageBackend, get_storage
from .local import LocalStorage
from .s3 import S3Storage

__all__ = [
    "StorageBackend",
    "get_storage",
    "LocalStorage",
    "S3Storage",
]
