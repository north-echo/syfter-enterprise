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
        delete_start = time.time()
        
        # Delete old SBOM files from storage
        try:
            storage.delete(existing_scan.original_sbom_key)
            storage.delete(existing_scan.modified_sbom_key)
        except Exception:
            pass  # Ignore storage errors
        
        # Use raw SQL for fast deletion (ORM is extremely slow for millions of rows)
        connection = db.connection()
        raw_conn = connection.connection.dbapi_connection
        cursor = raw_conn.cursor()
        
        # Check if PostgreSQL or SQLite
        is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
        param = '%s' if is_postgres else '?'
        
        # Delete files first (foreign key), then packages, then scan
        logger.info("Deleting files...")
        cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (existing_scan.id,))
        logger.info(f"Files deleted in {time.time() - delete_start:.1f}s")
        
        logger.info("Deleting packages...")
        cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (existing_scan.id,))
        logger.info(f"Packages deleted in {time.time() - delete_start:.1f}s")
        
        logger.info("Deleting scan record...")
        cursor.execute(f"DELETE FROM scans WHERE id = {param}", (existing_scan.id,))
        raw_conn.commit()
        
        # Refresh ORM session
        db.expire_all()
        
        logger.info(f"Existing scan deleted in {time.time() - delete_start:.1f}s")

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

    # Index packages and files using raw SQL for maximum performance
    logger.info("Indexing packages and files...")
    
    # Use raw connection for fast bulk inserts
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    
    # Check if PostgreSQL or SQLite by looking at the connection type
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
    
    # Insert packages and get their IDs
    logger.info(f"Inserting {len(packages_list)} packages...")
    bulk_start = time.time()
    
    # Build package tuples
    package_tuples = [
        (
            scan.id,
            product.id,
            pkg.get("name", ""),
            pkg.get("version"),
            pkg.get("release"),
            pkg.get("arch"),
            pkg.get("epoch"),
            pkg.get("source_rpm"),
            pkg.get("license"),
            pkg.get("purl"),
            pkg.get("cpes"),
        )
        for pkg in packages_list
    ]
    
    if is_postgres:
        # Use PostgreSQL's execute_values for fast bulk insert
        from psycopg2.extras import execute_values
        cursor = raw_conn.cursor()
        execute_values(
            cursor,
            """INSERT INTO packages (scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes)
               VALUES %s""",
            package_tuples,
            page_size=1000
        )
        raw_conn.commit()
    else:
        # SQLite - use executemany
        cursor = raw_conn.cursor()
        cursor.executemany(
            """INSERT INTO packages (scan_id, product_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            package_tuples
        )
        raw_conn.commit()
    
    logger.info(f"Packages inserted in {time.time() - bulk_start:.1f}s")
    
    # Get package IDs
    logger.info("Retrieving package IDs...")
    cursor = raw_conn.cursor()
    cursor.execute("SELECT id, name, version, arch FROM packages WHERE scan_id = %s" if is_postgres else 
                   "SELECT id, name, version, arch FROM packages WHERE scan_id = ?", (scan.id,))
    packages_by_key = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}
    
    # Build file tuples
    logger.info("Preparing file records...")
    file_tuples = []
    for pkg in packages_list:
        key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
        package_id = packages_by_key.get(key)
        if package_id:
            for f in pkg.get("files", []):
                file_tuples.append((
                    package_id,
                    scan.id,
                    product.id,
                    f.get("path", ""),
                    f.get("digest"),
                    f.get("digest_algorithm", "sha256"),
                ))
    
    logger.info(f"Inserting {len(file_tuples)} files...")
    bulk_start = time.time()
    
    if is_postgres:
        # Use COPY for maximum PostgreSQL performance (10-100x faster than INSERT)
        import io
        # Create CSV-like data in memory
        buffer = io.StringIO()
        for t in file_tuples:
            # Escape for COPY format: NULL as \N, tab-separated
            line = '\t'.join(
                '\\N' if v is None else str(v).replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n')
                for v in t
            )
            buffer.write(line + '\n')
        buffer.seek(0)
        
        cursor = raw_conn.cursor()
        cursor.copy_from(
            buffer,
            'files',
            columns=('package_id', 'scan_id', 'product_id', 'path', 'digest', 'digest_algorithm'),
            null='\\N'
        )
        raw_conn.commit()
    else:
        # SQLite - use executemany in batches
        cursor = raw_conn.cursor()
        batch_size = 50000
        for i in range(0, len(file_tuples), batch_size):
            batch = file_tuples[i:i + batch_size]
            cursor.executemany(
                """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                batch
            )
            if (i + batch_size) % 500000 == 0:
                raw_conn.commit()
                logger.info(f"Files progress: {min(i + batch_size, len(file_tuples))}/{len(file_tuples)}")
        raw_conn.commit()
    
    logger.info(f"Files inserted in {time.time() - bulk_start:.1f}s")
    
    # Refresh session to pick up raw SQL changes
    db.expire_all()
    
    elapsed = time.time() - start_time
    logger.info(f"Upload complete: {len(packages_list)} packages, {len(file_tuples)} files in {elapsed:.1f}s")

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

    # Use raw SQL for fast deletion
    connection = db.connection()
    raw_conn = connection.connection.dbapi_connection
    cursor = raw_conn.cursor()
    
    is_postgres = 'psycopg' in type(raw_conn).__module__ or 'postgresql' in str(db.bind.url)
    param = '%s' if is_postgres else '?'
    
    cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (scan_id,))
    cursor.execute(f"DELETE FROM scans WHERE id = {param}", (scan_id,))
    raw_conn.commit()
    db.expire_all()
