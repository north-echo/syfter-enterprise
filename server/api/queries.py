"""
Query API endpoints for searching packages and files.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db, Product, Package, File
from .schemas import PackageResponse, FileResponse, StatsResponse
from ..config import get_config

router = APIRouter()


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
        db.query(File, Package.name, Package.version, Product.name, Product.version)
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
        )
        for f, pkg_name, pkg_version, prod_name, prod_version in results
    ]


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Get database statistics."""
    from ..db import Scan

    config = get_config()

    product_count = db.query(Product).count()
    scan_count = db.query(Scan).count()
    package_count = db.query(Package).count()
    file_count = db.query(File).count()

    return StatsResponse(
        products=product_count,
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
    """
    query = (
        db.query(Package.name, Package.version, Package.release, Package.arch)
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
        }
        for name, version, release, arch in query.all()
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
