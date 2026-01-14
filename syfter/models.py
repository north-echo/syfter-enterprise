"""
Data models for Syfter.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Product:
    """Represents a Red Hat product with its metadata."""

    name: str  # e.g., "rhel"
    version: str  # e.g., "10.0"
    vendor: str = "Red Hat"
    cpe_vendor: str = "redhat"
    cpe_product: str = ""  # Will default to name if not specified
    purl_namespace: str = "redhat"
    description: str = ""

    def __post_init__(self):
        if not self.cpe_product:
            self.cpe_product = self.name

    @property
    def full_name(self) -> str:
        """Full product identifier."""
        return f"{self.name}-{self.version}"

    @property
    def cpe_prefix(self) -> str:
        """Generate CPE 2.3 prefix for this product."""
        return f"cpe:2.3:o:{self.cpe_vendor}:{self.cpe_product}:{self.version}"

    @property
    def purl_qualifier(self) -> str:
        """Generate PURL qualifier for this product."""
        return f"distro={self.name}-{self.version}"


@dataclass
class ScanRecord:
    """Represents a scan/import record in the database."""

    id: Optional[int] = None
    product_id: Optional[int] = None
    source_path: str = ""
    source_type: str = "directory"  # directory, container, archive, etc.
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    syft_version: str = ""
    original_sbom: str = ""  # Original syft-json
    modified_sbom: str = ""  # Modified syft-json with product metadata
    package_count: int = 0
    file_count: int = 0


@dataclass
class PackageInfo:
    """Indexed package information for querying."""

    id: Optional[int] = None
    scan_id: Optional[int] = None
    product_id: Optional[int] = None
    name: str = ""
    version: str = ""
    release: str = ""
    arch: str = ""
    epoch: str = ""
    source_rpm: str = ""
    license: str = ""
    purl: str = ""
    cpes: str = ""  # JSON array of CPEs


@dataclass
class FileInfo:
    """Indexed file information for querying."""

    id: Optional[int] = None
    package_id: Optional[int] = None
    scan_id: Optional[int] = None
    product_id: Optional[int] = None
    path: str = ""
    digest: str = ""
    digest_algorithm: str = "sha256"
