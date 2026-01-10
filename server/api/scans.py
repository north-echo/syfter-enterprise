"""
Scan API endpoints.
"""

import gzip
import json
import logging
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package, File as FileModel
from ..storage import get_storage
from .schemas import (
    ScanResponse,
    ScanMetadata,
    PackageCreate,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _generate_storage_key(product_name: str, product_version: str, scan_id: int, suffix: str) -> str:
    """Generate a storage key for an SBOM."""
    return f"{product_name}/{product_version}/{scan_id}/{suffix}"


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    product_name: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List scans, optionally filtered by product."""
    query = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
    )

    if product_name:
        query = query.filter(Product.name == product_name)

    query = query.order_by(Scan.scan_timestamp.desc()).offset(offset).limit(limit)
    results = query.all()

    return [
        ScanResponse(
            id=scan.id,
            product_id=scan.product_id,
            product_name=pname,
            product_version=pversion,
            source_path=scan.source_path,
            source_type=scan.source_type,
            scan_timestamp=scan.scan_timestamp,
            syft_version=scan.syft_version,
            package_count=scan.package_count,
            file_count=scan.file_count,
            original_size_bytes=scan.original_size_bytes,
            modified_size_bytes=scan.modified_size_bytes,
        )
        for scan, pname, pversion in results
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a specific scan."""
    result = (
        db.query(Scan, Product.name, Product.version)
        .join(Product, Scan.product_id == Product.id)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, pname, pversion = result
    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=pname,
        product_version=pversion,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
    )


@router.post("/upload", response_model=ScanResponse, status_code=201)
async def upload_scan(
    product_name: str = Form(...),
    product_version: str = Form(...),
    source_path: str = Form(...),
    source_type: str = Form("directory"),
    syft_version: Optional[str] = Form(None),
    original_sbom: UploadFile = File(..., description="Original syft-json SBOM (gzip compressed)"),
    modified_sbom: UploadFile = File(..., description="Modified syft-json SBOM (gzip compressed)"),
    packages_json: UploadFile = File(..., description="Package index JSON (gzip compressed)"),
    db: Session = Depends(get_db),
):
    """
    Upload a complete scan with SBOMs and package index.

    All files should be gzip compressed JSON.
    If a scan already exists for this product, it will be replaced.
    """
    start_time = time.time()
    logger.info(f"Starting upload for {product_name}-{product_version}")
    
    storage = get_storage()

    # Get or create product
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        product = Product(
            name=product_name,
            version=product_version,
            cpe_product=product_name,
        )
        db.add(product)
        db.commit()
        db.refresh(product)
    logger.info(f"Product resolved: id={product.id}")

    # Delete existing scan for this product (replace behavior)
    existing_scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .first()
    )
    if existing_scan:
        logger.info(f"Deleting existing scan {existing_scan.id}")
        # Delete old SBOM files from storage
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass  # Ignore storage errors
        # Explicitly delete related records
        db.query(FileModel).filter(FileModel.scan_id == existing_scan.id).delete()
        db.query(Package).filter(Package.scan_id == existing_scan.id).delete()
        db.delete(existing_scan)
        db.commit()
        logger.info("Existing scan deleted")

    # Read uploaded files
    logger.info("Reading uploaded files...")
    original_data = await original_sbom.read()
    modified_data = await modified_sbom.read()
    packages_data = await packages_json.read()
    logger.info(f"Files read: original={len(original_data)/1024/1024:.1f}MB, modified={len(modified_data)/1024/1024:.1f}MB, packages={len(packages_data)/1024:.1f}KB")

    # Parse packages for indexing
    logger.info("Parsing packages JSON...")
    try:
        packages_json_str = gzip.decompress(packages_data).decode("utf-8")
        packages_list = json.loads(packages_json_str)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON: {e}")
    
    total_files = sum(len(p.get("files", [])) for p in packages_list)
    logger.info(f"Parsed {len(packages_list)} packages with {total_files} files")

    # Create scan record first to get ID
    scan = Scan(
        product_id=product.id,
        source_path=source_path,
        source_type=source_type,
        syft_version=syft_version,
        original_sbom_key="",  # Will update after
        modified_sbom_key="",
        package_count=len(packages_list),
        file_count=total_files,
        original_size_bytes=len(original_data),
        modified_size_bytes=len(modified_data),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    logger.info(f"Scan record created: id={scan.id}")

    # Generate storage keys and store SBOMs
    logger.info("Storing SBOMs to object storage...")
    original_key = _generate_storage_key(product_name, product_version, scan.id, "original.json.gz")
    modified_key = _generate_storage_key(product_name, product_version, scan.id, "modified.json.gz")

    storage.put(original_key, original_data)
    storage.put(modified_key, modified_data)
    logger.info("SBOMs stored successfully")

    # Update scan with storage keys
    scan.original_sbom_key = original_key
    scan.modified_sbom_key = modified_key

    # Index packages and files in batches for better performance
    logger.info("Indexing packages and files...")
    batch_size = 100
    packages_indexed = 0
    files_indexed = 0
    
    for i, pkg_data in enumerate(packages_list):
        package = Package(
            scan_id=scan.id,
            product_id=product.id,
            name=pkg_data.get("name", ""),
            version=pkg_data.get("version"),
            release=pkg_data.get("release"),
            arch=pkg_data.get("arch"),
            epoch=pkg_data.get("epoch"),
            source_rpm=pkg_data.get("source_rpm"),
            license=pkg_data.get("license"),
            purl=pkg_data.get("purl"),
            cpes=pkg_data.get("cpes"),
        )
        db.add(package)
        db.flush()  # Get package ID
        packages_indexed += 1

        # Index files
        for file_data in pkg_data.get("files", []):
            file_obj = FileModel(
                package_id=package.id,
                scan_id=scan.id,
                product_id=product.id,
                path=file_data.get("path", ""),
                digest=file_data.get("digest"),
                digest_algorithm=file_data.get("digest_algorithm", "sha256"),
            )
            db.add(file_obj)
            files_indexed += 1
        
        # Periodic commit and progress logging
        if (i + 1) % batch_size == 0:
            db.commit()
            logger.info(f"Progress: {packages_indexed}/{len(packages_list)} packages, {files_indexed}/{total_files} files")

    # Final commit
    db.commit()
    
    elapsed = time.time() - start_time
    logger.info(f"Upload complete: {packages_indexed} packages, {files_indexed} files in {elapsed:.1f}s")

    return ScanResponse(
        id=scan.id,
        product_id=scan.product_id,
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        scan_timestamp=scan.scan_timestamp,
        syft_version=scan.syft_version,
        package_count=scan.package_count,
        file_count=scan.file_count,
        original_size_bytes=scan.original_size_bytes,
        modified_size_bytes=scan.modified_size_bytes,
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and its associated data."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Delete from storage
    storage = get_storage()
    try:
        storage.delete(scan.original_sbom_key)
        storage.delete(scan.modified_sbom_key)
    except Exception:
        pass  # Ignore storage errors during deletion

    # Explicitly delete related records (in case cascade doesn't work)
    db.query(FileModel).filter(FileModel.scan_id == scan_id).delete()
    db.query(Package).filter(Package.scan_id == scan_id).delete()
    db.delete(scan)
    db.commit()
