"""
Query API endpoints for searching packages and files.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db, Product, System, Package, File
from .schemas import PackageResponse, FileResponse, StatsResponse
from ..config import get_config

router = APIRouter()


# ============================================================================
# System-based package/file response schemas (inline for now)
# ============================================================================
from pydantic import BaseModel


class SystemPackageResponse(BaseModel):
    """Schema for package search response in system context."""
    id: int
    name: str
    version: Optional[str]
    release: Optional[str]
    arch: Optional[str]
    epoch: Optional[str]
    source_rpm: Optional[str]
    license: Optional[str]
    purl: Optional[str]
    cpes: Optional[str]
    system_hostname: str
    system_tag: Optional[str]

    class Config:
        from_attributes = True


class SystemFileResponse(BaseModel):
    """Schema for file search response in system context."""
    id: int
    path: str
    digest: Optional[str]
    digest_algorithm: Optional[str]
    package_name: str
    package_version: Optional[str]
    system_hostname: str
    system_tag: Optional[str]

    class Config:
        from_attributes = True


@router.get("/packages", response_model=List[PackageResponse])
def search_packages(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    product_version: Optional[str] = Query(default=None, description="Filter by product version"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for packages across all products."""
    query = (
        db.query(Package, Product.name, Product.version)
        .join(Product, Package.product_id == Product.id)
    )

    if name:
        query = query.filter(Package.name.like(name))
    if product_name:
        query = query.filter(Product.name == product_name)
    if product_version:
        query = query.filter(Product.version == product_version)

    query = query.order_by(Package.name).offset(offset).limit(limit)
    results = query.all()

    return [
        PackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            epoch=pkg.epoch,
            source_rpm=pkg.source_rpm,
            license=pkg.license,
            purl=pkg.purl,
            cpes=pkg.cpes,
            product_name=pname,
            product_version=pversion,
            layer_id=pkg.layer_id,
            layer_index=pkg.layer_index,
            source_image=pkg.source_image,
        )
        for pkg, pname, pversion in results
    ]


@router.get("/files", response_model=List[FileResponse])
def search_files(
    path: Optional[str] = Query(default=None, description="File path pattern (use % as wildcard)"),
    digest: Optional[str] = Query(default=None, description="File digest (exact match)"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    product_version: Optional[str] = Query(default=None, description="Filter by product version"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for files across all products."""
    query = (
        db.query(File, Package.name, Package.version, Package.source_image, Product.name, Product.version)
        .join(Package, File.package_id == Package.id)
        .join(Product, File.product_id == Product.id)
    )

    if path:
        query = query.filter(File.path.like(path))
    if digest:
        query = query.filter(File.digest == digest)
    if product_name:
        query = query.filter(Product.name == product_name)
    if product_version:
        query = query.filter(Product.version == product_version)

    query = query.order_by(File.path).offset(offset).limit(limit)
    results = query.all()

    return [
        FileResponse(
            id=f.id,
            path=f.path,
            digest=f.digest,
            digest_algorithm=f.digest_algorithm,
            package_name=pkg_name,
            package_version=pkg_version,
            product_name=prod_name,
            product_version=prod_version,
            source_image=source_img,
        )
        for f, pkg_name, pkg_version, source_img, prod_name, prod_version in results
    ]


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Get database statistics."""
    from ..db import Scan

    config = get_config()

    product_count = db.query(Product).count()
    system_count = db.query(System).count()
    scan_count = db.query(Scan).count()
    package_count = db.query(Package).count()
    file_count = db.query(File).count()

    return StatsResponse(
        products=product_count,
        systems=system_count,
        scans=scan_count,
        packages=package_count,
        files=file_count,
        storage_type=config.storage.type,
        database_type=config.database.type,
    )


@router.get("/list/packages/{product_name}/{product_version}")
def list_all_packages(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
):
    """
    List all packages for a product version.

    Returns a simple list suitable for piping to grep, etc.
    Includes source_image and layer_id for container scans.
    """
    query = (
        db.query(
            Package.name, Package.version, Package.release, Package.arch,
            Package.source_image, Package.layer_id
        )
        .join(Product, Package.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(Package.name)
    )

    return [
        {
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
            "source_image": source_image,
            "layer_id": layer_id,
        }
        for name, version, release, arch, source_image, layer_id in query.all()
    ]


@router.get("/list/files/{product_name}/{product_version}")
def list_all_files(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
):
    """
    List all file paths for a product version.

    Returns a simple list of file paths suitable for piping to grep, etc.
    """
    query = (
        db.query(File.path)
        .join(Product, File.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(File.path)
    )

    return [path for (path,) in query.all()]


# ============================================================================
# System-based queries (infrastructure mode)
# ============================================================================

@router.get("/systems/packages", response_model=List[SystemPackageResponse])
def search_system_packages(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    hostname: Optional[str] = Query(default=None, description="Filter by hostname"),
    tag: Optional[str] = Query(default=None, description="Filter by system tag"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for packages across all systems."""
    query = (
        db.query(Package, System.hostname, System.tag)
        .join(System, Package.system_id == System.id)
    )

    if name:
        query = query.filter(Package.name.like(name))
    if hostname:
        query = query.filter(System.hostname == hostname)
    if tag:
        query = query.filter(System.tag == tag)

    query = query.order_by(Package.name).offset(offset).limit(limit)
    results = query.all()

    return [
        SystemPackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            epoch=pkg.epoch,
            source_rpm=pkg.source_rpm,
            license=pkg.license,
            purl=pkg.purl,
            cpes=pkg.cpes,
            system_hostname=hostname,
            system_tag=tag,
        )
        for pkg, hostname, tag in results
    ]


@router.get("/systems/files", response_model=List[SystemFileResponse])
def search_system_files(
    path: Optional[str] = Query(default=None, description="File path pattern (use % as wildcard)"),
    digest: Optional[str] = Query(default=None, description="File digest (exact match)"),
    hostname: Optional[str] = Query(default=None, description="Filter by hostname"),
    tag: Optional[str] = Query(default=None, description="Filter by system tag"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """Search for files across all systems."""
    query = (
        db.query(File, Package.name, Package.version, System.hostname, System.tag)
        .join(Package, File.package_id == Package.id)
        .join(System, File.system_id == System.id)
    )

    if path:
        query = query.filter(File.path.like(path))
    if digest:
        query = query.filter(File.digest == digest)
    if hostname:
        query = query.filter(System.hostname == hostname)
    if tag:
        query = query.filter(System.tag == tag)

    query = query.order_by(File.path).offset(offset).limit(limit)
    results = query.all()

    return [
        SystemFileResponse(
            id=f.id,
            path=f.path,
            digest=f.digest,
            digest_algorithm=f.digest_algorithm,
            package_name=pkg_name,
            package_version=pkg_version,
            system_hostname=hostname,
            system_tag=tag,
        )
        for f, pkg_name, pkg_version, hostname, tag in results
    ]


@router.get("/systems/list/packages/{hostname}")
def list_system_packages(
    hostname: str,
    db: Session = Depends(get_db),
):
    """
    List all packages for a system.

    Returns a simple list suitable for piping to grep, etc.
    """
    query = (
        db.query(Package.name, Package.version, Package.release, Package.arch)
        .join(System, Package.system_id == System.id)
        .filter(System.hostname == hostname)
        .order_by(Package.name)
    )

    return [
        {
            "name": name,
            "version": version,
            "release": release,
            "arch": arch,
        }
        for name, version, release, arch in query.all()
    ]


@router.get("/systems/list/files/{hostname}")
def list_system_files(
    hostname: str,
    db: Session = Depends(get_db),
):
    """
    List all file paths for a system.

    Returns a simple list of file paths suitable for piping to grep, etc.
    """
    query = (
        db.query(File.path)
        .join(System, File.system_id == System.id)
        .filter(System.hostname == hostname)
        .order_by(File.path)
    )

    return [path for (path,) in query.all()]
