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


class Scan(Base):
    """Scan model - represents a single SBOM scan."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), default="directory")
    scan_timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    syft_version: Mapped[Optional[str]] = mapped_column(String(50))

    # Storage references (instead of storing blobs)
    original_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)
    modified_sbom_key: Mapped[str] = mapped_column(String(500), nullable=False)

    # Stats
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    original_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    modified_size_bytes: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    product: Mapped["Product"] = relationship(back_populates="scans")
    packages: Mapped[List["Package"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_product", "product_id"),
        Index("idx_scan_timestamp", "scan_timestamp"),
    )


class Package(Base):
    """Package model - indexed package information for querying."""

    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(200))
    release: Mapped[Optional[str]] = mapped_column(String(200))
    arch: Mapped[Optional[str]] = mapped_column(String(50))
    epoch: Mapped[Optional[str]] = mapped_column(String(20))
    source_rpm: Mapped[Optional[str]] = mapped_column(String(500))
    license: Mapped[Optional[str]] = mapped_column(Text)
    purl: Mapped[Optional[str]] = mapped_column(String(1000))
    cpes: Mapped[Optional[str]] = mapped_column(Text)  # JSON array

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="packages")
    files: Mapped[List["File"]] = relationship(back_populates="package", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_package_name", "name"),
        Index("idx_package_product", "product_id"),
        Index("idx_package_purl", "purl"),
        Index("idx_package_scan", "scan_id"),
    )


class File(Base):
    """File model - indexed file information for querying."""

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"), nullable=False)

    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    digest: Mapped[Optional[str]] = mapped_column(String(200))
    digest_algorithm: Mapped[Optional[str]] = mapped_column(String(20), default="sha256")

    # Relationships
    package: Mapped["Package"] = relationship(back_populates="files")

    __table_args__ = (
        Index("idx_file_path", "path"),
        Index("idx_file_product", "product_id"),
        Index("idx_file_digest", "digest"),
        Index("idx_file_scan", "scan_id"),
    )
