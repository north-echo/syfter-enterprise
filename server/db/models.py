"""
SQLAlchemy database models.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Product(Base):
    """Product model - represents a Red Hat product."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), default="Red Hat")
    cpe_vendor: Mapped[str] = mapped_column(String(100), default="redhat")
    cpe_product: Mapped[Optional[str]] = mapped_column(String(255))
    purl_namespace: Mapped[str] = mapped_column(String(100), default="redhat")
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(back_populates="product", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_product_name_version"),
    )

    @property
    def full_name(self) -> str:
        return f"{self.name}-{self.version}"


class System(Base):
    """System model - represents a host/server in infrastructure."""

    __tablename__ = "systems"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length
    tag: Mapped[Optional[str]] = mapped_column(String(255))  # For CMDB linking, grouping
    os_name: Mapped[Optional[str]] = mapped_column(String(255))  # e.g., "Red Hat Enterprise Linux"
    os_version: Mapped[Optional[str]] = mapped_column(String(100))  # e.g., "10.0"
    arch: Mapped[Optional[str]] = mapped_column(String(50))  # e.g., "x86_64"
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scans: Mapped[List["Scan"]] = relationship(back_populates="system", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_system_hostname", "hostname"),
        Index("idx_system_tag", "tag"),
        Index("idx_system_ip", "ip_address"),
    )


class Scan(Base):
    """Scan model - represents a single SBOM scan."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # Either product_id OR system_id should be set, not both
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), default="directory")
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    syft_version: Mapped[Optional[str]] = mapped_column(String(50))

    # User-provided scan label/version (for systems, defaults to scan date)
    scan_label: Mapped[Optional[str]] = mapped_column(String(100))

    # Container image metadata (for container scans)
    image_id: Mapped[Optional[str]] = mapped_column(String(100))  # sha256 of image
    image_layers_json: Mapped[Optional[str]] = mapped_column(Text)  # JSON: [{layer_id, index, source_image}]

    # Storage references (instead of storing blobs)
    original_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)
    modified_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)

    # Stats
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    original_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    modified_size_bytes: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    product: Mapped[Optional["Product"]] = relationship(back_populates="scans")
    system: Mapped[Optional["System"]] = relationship(back_populates="scans")
    packages: Mapped[List["Package"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    image_layers: Mapped[List["ImageLayer"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_product", "product_id"),
        Index("idx_scan_system", "system_id"),
        Index("idx_scan_timestamp", "scan_timestamp"),
    )


class ImageLayer(Base):
    """ImageLayer model - maps container layer IDs to source images."""

    __tablename__ = "image_layers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)

    layer_id: Mapped[str] = mapped_column(String(100), nullable=False)  # sha256 digest
    layer_index: Mapped[int] = mapped_column(Integer, nullable=False)  # position (0=bottom)
    source_image: Mapped[Optional[str]] = mapped_column(String(500))  # image reference

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="image_layers")

    __table_args__ = (
        Index("idx_image_layer_scan", "scan_id"),
        Index("idx_image_layer_id", "layer_id"),
        UniqueConstraint("scan_id", "layer_id", name="uq_scan_layer"),
    )


class Package(Base):
    """Package model - indexed package information for querying."""

    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Either product_id OR system_id should be set
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    name: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(200))
    release: Mapped[Optional[str]] = mapped_column(String(200))
    arch: Mapped[Optional[str]] = mapped_column(String(50))
    epoch: Mapped[Optional[str]] = mapped_column(String(20))
    source_rpm: Mapped[Optional[str]] = mapped_column(String(500))
    license: Mapped[Optional[str]] = mapped_column(Text)
    purl: Mapped[Optional[str]] = mapped_column(String(1000))
    cpes: Mapped[Optional[str]] = mapped_column(Text)  # JSON array

    # Container layer tracking (for container scans)
    layer_id: Mapped[Optional[str]] = mapped_column(String(100))  # sha256 digest of layer
    layer_index: Mapped[Optional[int]] = mapped_column(Integer)  # position in layer stack (0=bottom)
    source_image: Mapped[Optional[str]] = mapped_column(String(500))  # image that introduced this package

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="packages")
    files: Mapped[List["File"]] = relationship(back_populates="package", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_package_name", "name"),
        Index("idx_package_product", "product_id"),
        Index("idx_package_system", "system_id"),
        Index("idx_package_purl", "purl"),
        Index("idx_package_scan", "scan_id"),
        Index("idx_package_layer", "layer_id"),
        Index("idx_package_source_image", "source_image"),
    )


class File(Base):
    """File model - indexed file information for querying."""

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    # Either product_id OR system_id should be set
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)

    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    digest: Mapped[Optional[str]] = mapped_column(String(200))
    digest_algorithm: Mapped[Optional[str]] = mapped_column(String(20), default="sha256")

    # Relationships
    package: Mapped["Package"] = relationship(back_populates="files")

    __table_args__ = (
        Index("idx_file_path", "path"),
        Index("idx_file_product", "product_id"),
        Index("idx_file_system", "system_id"),
        Index("idx_file_digest", "digest"),
        Index("idx_file_scan", "scan_id"),
    )


class Job(Base):
    """Job model - tracks async import jobs."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    product_id: Mapped[Optional[int]] = mapped_column(ForeignKey("products.id"), nullable=True)
    system_id: Mapped[Optional[int]] = mapped_column(ForeignKey("systems.id"), nullable=True)
    scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scans.id"), nullable=True)

    # Job type: "product_import" or "system_import"
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, processing, complete, failed
    job_type: Mapped[str] = mapped_column(String(50), default="product_import")

    # S3 keys for uploaded files
    original_sbom_key: Mapped[Optional[str]] = mapped_column(String(500))
    modified_sbom_key: Mapped[Optional[str]] = mapped_column(String(500))
    packages_tsv_key: Mapped[Optional[str]] = mapped_column(String(500))
    files_tsv_key: Mapped[Optional[str]] = mapped_column(String(500))

    # Metadata - for products
    product_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    product_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Metadata - for systems
    system_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    system_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    system_tag: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scan_label: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Common metadata
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), default="directory")
    syft_version: Mapped[Optional[str]] = mapped_column(String(50))
    image_layers_json: Mapped[Optional[str]] = mapped_column(Text)  # Container layer chain

    # Progress tracking
    total_packages: Mapped[int] = mapped_column(Integer, default=0)
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    processed_packages: Mapped[int] = mapped_column(Integer, default=0)
    processed_files: Mapped[int] = mapped_column(Integer, default=0)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    __table_args__ = (
        Index("idx_job_status", "status"),
        Index("idx_job_product", "product_id"),
        Index("idx_job_system", "system_id"),
        Index("idx_job_created", "created_at"),
    )
