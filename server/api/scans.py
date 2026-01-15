"""
Scan API endpoints.
"""

import gzip
import io
import json
import logging
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session

from ..config import get_config
from ..db import get_db, Product, Scan, Package, File as FileModel
from ..storage import get_storage
from .schemas import (
    ScanResponse,
    ScanMetadata,
    PackageCreate,
)

logger = logging.getLogger(__name__)
router = APIRouter()

# Maximum decompressed size to prevent zip bombs (4GB)
_MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_gzip_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Safely decompress gzip data with size limit to prevent decompression bombs.
    """
    decompressor = gzip.GzipFile(fileobj=io.BytesIO(data))
    chunks = []
    total_size = 0

    while True:
        chunk = decompressor.read(1024 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB"
            )
        chunks.append(chunk)

    return b''.join(chunks)


def _validate_sbom_json(data: bytes, name: str = "SBOM") -> dict:
    """
    Validate that compressed data is valid gzip JSON.

    Args:
        data: Compressed gzip data
        name: Name for error messages

    Returns:
        Parsed JSON dict

    Raises:
        HTTPException: If data is invalid
    """
    try:
        decompressed = _safe_gzip_decompress(data)
    except gzip.BadGzipFile:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid gzip data")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: {e}")

    try:
        return json.loads(decompressed.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid JSON - {e}")
    except UnicodeDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid {name}: not valid UTF-8 - {e}")


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
        # Commit after each to release locks and let PostgreSQL reclaim space
        logger.info("Deleting files...")
        cursor.execute(f"DELETE FROM files WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        files_time = time.time() - delete_start
        logger.info(f"Files deleted in {files_time:.1f}s")

        logger.info("Deleting packages...")
        pkg_start = time.time()
        cursor.execute(f"DELETE FROM packages WHERE scan_id = {param}", (existing_scan.id,))
        raw_conn.commit()
        logger.info(f"Packages deleted in {time.time() - pkg_start:.1f}s")

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

    # Validate SBOM files are proper gzip JSON (quick validation, not full parsing)
    # We validate the compressed data can be decompressed, but don't parse the full SBOM
    # to avoid memory issues with large SBOMs
    logger.info("Validating SBOM files...")
    try:
        # Quick validation - try to decompress first few bytes to check format
        _safe_gzip_decompress(original_data[:1024*10] if len(original_data) > 1024*10 else original_data, max_size=_MAX_DECOMPRESSED_SIZE)
        _safe_gzip_decompress(modified_data[:1024*10] if len(modified_data) > 1024*10 else modified_data, max_size=_MAX_DECOMPRESSED_SIZE)
    except (gzip.BadGzipFile, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid SBOM file format: {e}")

    # Parse packages for indexing - use streaming with size limit
    logger.info("Parsing packages JSON...")
    try:
        # Decompress with size limit
        packages_json_bytes = _safe_gzip_decompress(packages_data)
        # Free the compressed data immediately
        del packages_data

        # Parse JSON
        packages_list = json.loads(packages_json_bytes.decode("utf-8"))
        # Free the JSON bytes immediately
        del packages_json_bytes

        import gc
        gc.collect()
        logger.info(f"JSON parsed, memory cleaned up")
    except MemoryError:
        logger.error("Out of memory parsing packages JSON")
        raise HTTPException(status_code=507, detail="Server out of memory processing this upload. Try again or contact admin.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Packages JSON too large: {e}")
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid packages JSON format: {e}")
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
    packages_count = len(packages_list)
    logger.info(f"Inserting {packages_count} packages...")
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

    # Check if we should skip file indexing for large scans
    config = get_config()
    skip_threshold = config.skip_file_index_threshold

    if skip_threshold > 0 and total_files > skip_threshold:
        logger.info(f"Skipping file indexing: {total_files} files exceeds threshold of {skip_threshold}")
        logger.info("File search will not be available for this scan, but packages are indexed")
        file_count_actual = 0
    else:
        # Get package IDs
        logger.info("Retrieving package IDs...")
        cursor = raw_conn.cursor()
        cursor.execute("SELECT id, name, version, arch FROM packages WHERE scan_id = %s" if is_postgres else
                       "SELECT id, name, version, arch FROM packages WHERE scan_id = ?", (scan.id,))
        packages_by_key = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}

        logger.info(f"Inserting {total_files} files...")
        bulk_start = time.time()
        file_count_actual = 0

        if is_postgres:
            # Stream files directly to a temp file, then COPY - avoids holding all in memory
            import tempfile
            import os

            logger.info("Writing files to temp file for COPY...")
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as tmp:
                tmp_path = tmp.name
                for pkg in packages_list:
                    key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                    package_id = packages_by_key.get(key)
                    if package_id:
                        for f in pkg.get("files", []):
                            # Format for COPY: tab-separated, \N for NULL
                            path = f.get("path", "")
                            digest = f.get("digest")
                            algo = f.get("digest_algorithm", "sha256")

                            # Escape special chars
                            path = path.replace('\\', '\\\\').replace('\t', '\\t').replace('\n', '\\n') if path else ''
                            digest_str = digest.replace('\\', '\\\\') if digest else '\\N'
                            algo_str = algo.replace('\\', '\\\\') if algo else '\\N'

                            tmp.write(f"{package_id}\t{scan.id}\t{product.id}\t{path}\t{digest_str}\t{algo_str}\n")
                            file_count_actual += 1

                            # Log progress periodically
                            if file_count_actual % 1000000 == 0:
                                logger.info(f"Files written to temp: {file_count_actual}/{total_files}")

            logger.info(f"Temp file written: {file_count_actual} files, {os.path.getsize(tmp_path)/1024/1024:.1f}MB")

            # Free packages_list memory before COPY
            del packages_list
            import gc
            gc.collect()
            logger.info("Memory freed, starting COPY...")

            # COPY from file
            cursor = raw_conn.cursor()
            with open(tmp_path, 'r') as f:
                cursor.copy_from(
                    f,
                    'files',
                    columns=('package_id', 'scan_id', 'product_id', 'path', 'digest', 'digest_algorithm'),
                    null='\\N'
                )
            raw_conn.commit()

            # Clean up temp file
            os.unlink(tmp_path)
            logger.info(f"COPY complete")
        else:
            # SQLite - stream directly without building full list
            cursor = raw_conn.cursor()
            batch = []
            batch_size = 50000

            for pkg in packages_list:
                key = (pkg.get("name", ""), pkg.get("version"), pkg.get("arch"))
                package_id = packages_by_key.get(key)
                if package_id:
                    for f in pkg.get("files", []):
                        batch.append((
                            package_id,
                            scan.id,
                            product.id,
                            f.get("path", ""),
                            f.get("digest"),
                            f.get("digest_algorithm", "sha256"),
                        ))
                        file_count_actual += 1

                        if len(batch) >= batch_size:
                            cursor.executemany(
                                """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                batch
                            )
                            batch = []
                            if file_count_actual % 500000 == 0:
                                raw_conn.commit()
                                logger.info(f"Files progress: {file_count_actual}/{total_files}")

            # Insert remaining
            if batch:
                cursor.executemany(
                    """INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    batch
                )
            raw_conn.commit()

        logger.info(f"Files inserted in {time.time() - bulk_start:.1f}s")

    # Refresh session to pick up raw SQL changes
    db.expire_all()

    elapsed = time.time() - start_time
    logger.info(f"Upload complete: {packages_count} packages, {file_count_actual} files indexed in {elapsed:.1f}s")

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
