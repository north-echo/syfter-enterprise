"""
Job API endpoints for async import processing.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import func
from sqlalchemy.orm import Session

from server.db.session import get_db
from server.db.models import Job, Product, System, Scan, Package, File
from server.storage.base import get_storage
from server.config import get_config
from server.api.schemas import (
    JobCreate,
    SystemJobCreate,
    JobUploadUrls,
    JobResponse,
    JobListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/jobs", tags=["jobs"])

# Maximum decompressed size to prevent zip bombs (4GB)
MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024 * 1024  # 4GB for large distros like RHEL


def _safe_gzip_decompress(data: bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
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
    import gzip
    import io

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
                f"Decompressed data ({total_size // (1024*1024)}MB so far) exceeds maximum size limit of {max_size // (1024*1024*1024)}GB. "
                "This may indicate a malicious file (zip bomb)."
            )
        chunks.append(chunk)

    return b''.join(chunks)


@router.post("", response_model=JobUploadUrls)
async def create_job(
    job_data: JobCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new product import job and get presigned URLs for file uploads.

    Flow:
    1. Client calls this to create a job and get upload URLs
    2. Client uploads files to the presigned URLs
    3. Client calls POST /jobs/{job_id}/start to begin processing
    """
    job_id = str(uuid.uuid4())

    # Create storage keys
    base_key = f"jobs/{job_id}"
    original_sbom_key = f"{base_key}/original_sbom.json.gz"
    modified_sbom_key = f"{base_key}/modified_sbom.json.gz"
    packages_tsv_key = f"{base_key}/packages.tsv.gz"
    files_tsv_key = f"{base_key}/files.tsv.gz"

    # Create job record
    job = Job(
        id=job_id,
        status="pending",
        job_type="product_import",
        product_name=job_data.product_name,
        product_version=job_data.product_version,
        source_path=job_data.source_path,
        source_type=job_data.source_type,
        syft_version=job_data.syft_version,
        total_packages=job_data.total_packages,
        total_files=job_data.total_files,
        image_layers_json=job_data.image_layers_json,
        original_sbom_key=original_sbom_key,
        modified_sbom_key=modified_sbom_key,
        packages_tsv_key=packages_tsv_key,
        files_tsv_key=files_tsv_key,
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    # Get presigned upload URLs
    storage = get_storage()

    return JobUploadUrls(
        job_id=job_id,
        original_sbom_url=storage.get_presigned_upload_url(original_sbom_key),
        modified_sbom_url=storage.get_presigned_upload_url(modified_sbom_key),
        packages_tsv_url=storage.get_presigned_upload_url(packages_tsv_key),
        files_tsv_url=storage.get_presigned_upload_url(files_tsv_key),
        expires_in=3600,
    )


@router.post("/system", response_model=JobUploadUrls)
async def create_system_job(
    job_data: SystemJobCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new system import job and get presigned URLs for file uploads.

    This is for infrastructure mode - scanning hosts instead of products.

    Flow:
    1. Client calls this to create a job and get upload URLs
    2. Client uploads files to the presigned URLs
    3. Client calls POST /jobs/{job_id}/start to begin processing
    """
    job_id = str(uuid.uuid4())

    # Create storage keys
    base_key = f"jobs/{job_id}"
    original_sbom_key = f"{base_key}/original_sbom.json.gz"
    modified_sbom_key = f"{base_key}/modified_sbom.json.gz"
    packages_tsv_key = f"{base_key}/packages.tsv.gz"
    files_tsv_key = f"{base_key}/files.tsv.gz"

    # Create job record for system import
    job = Job(
        id=job_id,
        status="pending",
        job_type="system_import",
        system_hostname=job_data.hostname,
        system_ip=job_data.ip_address,
        system_tag=job_data.tag,
        # Store OS info in source_path for now (it will be applied to system record later)
        source_path=f"host:{job_data.hostname}",
        source_type="host",
        syft_version=job_data.syft_version,
        total_packages=job_data.total_packages,
        total_files=job_data.total_files,
        original_sbom_key=original_sbom_key,
        modified_sbom_key=modified_sbom_key,
        packages_tsv_key=packages_tsv_key,
        files_tsv_key=files_tsv_key,
    )

    # Store additional OS info as scan_label temporarily
    # Format: os_name|os_version|architecture
    os_parts = [
        job_data.os_name or "",
        job_data.os_version or "",
        job_data.architecture or "",
    ]
    job.scan_label = "|".join(os_parts)

    db.add(job)
    db.commit()
    db.refresh(job)

    # Get presigned upload URLs
    storage = get_storage()

    return JobUploadUrls(
        job_id=job_id,
        original_sbom_url=storage.get_presigned_upload_url(original_sbom_key),
        modified_sbom_url=storage.get_presigned_upload_url(modified_sbom_key),
        packages_tsv_url=storage.get_presigned_upload_url(packages_tsv_key),
        files_tsv_url=storage.get_presigned_upload_url(files_tsv_key),
        expires_in=3600,
    )


@router.post("/{job_id}/start", response_model=JobResponse)
async def start_job(
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Start processing an uploaded job.

    Files must be uploaded to the presigned URLs before calling this.
    Processing happens in the background.
    """
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Job is already {job.status}, cannot start"
        )

    # Verify files exist in storage
    storage = get_storage()
    missing = []
    for key_name, key in [
        ("original_sbom", job.original_sbom_key),
        ("modified_sbom", job.modified_sbom_key),
        ("packages_tsv", job.packages_tsv_key),
    ]:
        if not storage.exists(key):
            missing.append(key_name)

    # files_tsv is optional (might be skipped for small scans)

    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing uploaded files: {', '.join(missing)}"
        )

    # Update job status
    job.status = "processing"
    job.started_at = datetime.utcnow()
    db.commit()

    # Queue background processing
    background_tasks.add_task(process_job, job_id)

    db.refresh(job)
    return _job_to_response(job)


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Get job status and details."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return _job_to_response(job)


@router.get("", response_model=JobListResponse)
async def list_jobs(
    status: Optional[str] = None,
    product_name: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List jobs with optional filtering."""
    query = db.query(Job)

    if status:
        query = query.filter(Job.status == status)
    if product_name:
        query = query.filter(Job.product_name == product_name)

    total = query.count()
    jobs = query.order_by(Job.created_at.desc()).offset(offset).limit(limit).all()

    return JobListResponse(
        jobs=[_job_to_response(j) for j in jobs],
        total=total,
    )


@router.delete("/{job_id}")
async def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
):
    """Cancel a pending job and clean up its files."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status == "processing":
        raise HTTPException(
            status_code=400,
            detail="Cannot cancel a job that is currently processing"
        )

    # Clean up storage
    storage = get_storage()
    for key in [job.original_sbom_key, job.modified_sbom_key,
                job.packages_tsv_key, job.files_tsv_key]:
        if key:
            try:
                storage.delete(key)
            except Exception:
                pass  # Ignore errors, file might not exist

    db.delete(job)
    db.commit()

    return {"status": "cancelled", "job_id": job_id}


def _job_to_response(job: Job) -> JobResponse:
    """Convert Job model to response schema."""
    return JobResponse(
        id=job.id,
        status=job.status,
        job_type=job.job_type,
        product_name=job.product_name,
        product_version=job.product_version,
        system_hostname=job.system_hostname,
        system_ip=job.system_ip,
        system_tag=job.system_tag,
        scan_label=job.scan_label,
        source_path=job.source_path,
        source_type=job.source_type,
        syft_version=job.syft_version,
        total_packages=job.total_packages,
        total_files=job.total_files,
        processed_packages=job.processed_packages,
        processed_files=job.processed_files,
        error_message=job.error_message,
        scan_id=job.scan_id,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
    )


def _get_or_create_product(db: Session, job: Job) -> Product:
    """Get or create product for a job."""
    product = db.query(Product).filter(
        Product.name == job.product_name,
        Product.version == job.product_version
    ).first()

    if not product:
        product = Product(
            name=job.product_name,
            version=job.product_version,
        )
        db.add(product)
        db.commit()
        db.refresh(product)

    return product


def _get_or_create_system(db: Session, job: Job) -> System:
    """Get or create system for a job."""
    # Parse OS info from scan_label (format: os_name|os_version|architecture)
    os_name = None
    os_version = None
    architecture = None
    if job.scan_label and "|" in job.scan_label:
        parts = job.scan_label.split("|")
        os_name = parts[0] if len(parts) > 0 and parts[0] else None
        os_version = parts[1] if len(parts) > 1 and parts[1] else None
        architecture = parts[2] if len(parts) > 2 and parts[2] else None

    system = db.query(System).filter(
        System.hostname == job.system_hostname
    ).first()

    if not system:
        system = System(
            hostname=job.system_hostname,
            ip_address=job.system_ip,
            tag=job.system_tag,
            os_name=os_name,
            os_version=os_version,
            arch=architecture,
        )
        db.add(system)
        db.commit()
        db.refresh(system)
    else:
        # Update system info if provided
        if job.system_ip:
            system.ip_address = job.system_ip
        if job.system_tag:
            system.tag = job.system_tag
        if os_name:
            system.os_name = os_name
        if os_version:
            system.os_version = os_version
        if architecture:
            system.arch = architecture
        db.commit()
        db.refresh(system)

    return system


def process_job(job_id: str):
    """
    Background task to process an import job.

    This runs PostgreSQL COPY commands directly from the TSV files.
    Handles both product imports and system imports.
    """
    from server.db.session import get_session_factory

    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        storage = get_storage()
        config = get_config()

        # Determine if this is a product or system import
        is_system_import = job.job_type == "system_import"

        if is_system_import:
            logger.info(f"Processing system job {job_id}: {job.system_hostname}")
            product = None
            system = _get_or_create_system(db, job)
            job.system_id = system.id
            entity_id = system.id
            entity_type = "system"
        else:
            logger.info(f"Processing product job {job_id}: {job.product_name}-{job.product_version}")
            system = None
            product = _get_or_create_product(db, job)
            job.product_id = product.id
            entity_id = product.id
            entity_type = "product"

        db.commit()

        # Delete existing scans for this product/system
        if is_system_import:
            existing_scans = db.query(Scan).filter(Scan.system_id == system.id).all()
            entity_name = system.hostname
        else:
            existing_scans = db.query(Scan).filter(Scan.product_id == product.id).all()
            entity_name = product.full_name

        if existing_scans:
            logger.info(f"Deleting {len(existing_scans)} existing scan(s) for {entity_name}")

            # Use a separate raw connection for deletions to avoid session conflicts
            from server.db.session import get_engine
            engine = get_engine()
            is_postgres = 'postgresql' in str(engine.url)

            for old_scan in existing_scans:
                if is_postgres:
                    # Get a fresh connection for deletion
                    del_conn = engine.raw_connection()
                    try:
                        cursor = del_conn.cursor()
                        param = (old_scan.id,)

                        # Disable triggers for fast deletion (avoids FK cascade checks)
                        cursor.execute("SET session_replication_role = replica;")

                        # Delete files
                        logger.info(f"Deleting files for scan {old_scan.id}...")
                        cursor.execute("DELETE FROM files WHERE scan_id = %s", param)
                        del_conn.commit()
                        logger.info("Files deleted")

                        # Delete packages
                        logger.info(f"Deleting packages for scan {old_scan.id}...")
                        cursor.execute("DELETE FROM packages WHERE scan_id = %s", param)
                        del_conn.commit()
                        logger.info("Packages deleted")

                        # Delete scan
                        cursor.execute("DELETE FROM scans WHERE id = %s", param)
                        del_conn.commit()

                        # Re-enable triggers (not strictly needed as connection will close)
                        cursor.execute("SET session_replication_role = DEFAULT;")
                        del_conn.commit()
                    finally:
                        del_conn.close()
                else:
                    # SQLite - use session connection
                    raw_conn = db.connection().connection.dbapi_connection
                    cursor = raw_conn.cursor()
                    param = (old_scan.id,)
                    cursor.execute("DELETE FROM files WHERE scan_id = ?", param)
                    raw_conn.commit()
                    cursor.execute("DELETE FROM packages WHERE scan_id = ?", param)
                    raw_conn.commit()
                    cursor.execute("DELETE FROM scans WHERE id = ?", param)
                    raw_conn.commit()

                # Delete from storage
                try:
                    storage.delete(old_scan.original_sbom_key)
                    storage.delete(old_scan.modified_sbom_key)
                except Exception:
                    pass

                logger.info(f"Scan {old_scan.id} deleted")

            # Refresh the SQLAlchemy session to pick up changes
            db.expire_all()

        # Move SBOMs to permanent location
        if is_system_import:
            scan_base = f"systems/{system.id}/scans"
        else:
            scan_base = f"scans/{product.id}"
        final_original_key = f"{scan_base}/original_sbom.json.gz"
        final_modified_key = f"{scan_base}/modified_sbom.json.gz"

        # Copy from job location to scan location
        storage.copy(job.original_sbom_key, final_original_key)
        storage.copy(job.modified_sbom_key, final_modified_key)

        # Get sizes
        original_size = storage.get_size(final_original_key)
        modified_size = storage.get_size(final_modified_key)

        # Create scan record
        scan = Scan(
            product_id=product.id if product else None,
            system_id=system.id if system else None,
            source_path=job.source_path,
            source_type=job.source_type,
            syft_version=job.syft_version,
            original_sbom_key=final_original_key,
            modified_sbom_key=final_modified_key,
            package_count=job.total_packages,
            file_count=job.total_files,
            original_size_bytes=original_size,
            modified_size_bytes=modified_size,
            image_layers_json=job.image_layers_json,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        job.scan_id = scan.id
        db.commit()

        # Update system last_scan_at if this is a system import
        if is_system_import and system:
            system.last_scan_at = datetime.utcnow()
            db.commit()

        logger.info(f"Created scan {scan.id}, importing packages...")

        # Import packages and files from TSV
        # Use a separate connection for heavy import to avoid session issues
        from server.db.session import get_engine
        engine = get_engine()
        is_postgres = 'postgresql' in str(engine.url)

        if is_postgres:
            # Get a raw psycopg2 connection for COPY operations
            import_conn = engine.raw_connection()
            try:
                _import_tsv_postgres(db, import_conn, storage, job, scan, product, system)
            finally:
                import_conn.close()
        else:
            raw_conn = db.connection().connection.dbapi_connection
            _import_tsv_sqlite(db, raw_conn, storage, job, scan, product, system)

        # Update job as complete
        job.status = "complete"
        job.completed_at = datetime.utcnow()
        job.processed_packages = job.total_packages
        job.processed_files = job.total_files
        db.commit()

        # Clean up job files from storage (keep only the final SBOM locations)
        for key in [job.original_sbom_key, job.modified_sbom_key,
                    job.packages_tsv_key, job.files_tsv_key]:
            if key:
                try:
                    storage.delete(key)
                except Exception:
                    pass

        logger.info(f"Job {job_id} complete: {job.total_packages} packages, {job.total_files} files")

    except Exception as e:
        logger.exception(f"Job {job_id} failed: {e}")
        try:
            job = db.query(Job).filter(Job.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)[:1000]
                job.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def _import_tsv_postgres(db, raw_conn, storage, job, scan, product, system):
    """Import TSV files directly into PostgreSQL using COPY."""
    import gzip
    import tempfile
    import os

    cursor = raw_conn.cursor()

    # Determine if this is a product or system import
    product_id = product.id if product else "\\N"
    system_id = system.id if system else "\\N"

    # Track temp files for cleanup
    pkg_tmp_path = None
    files_tmp_path = None

    try:
        # Download and decompress packages TSV
        logger.info("Downloading packages TSV...")
        packages_data = storage.get(job.packages_tsv_key)
        packages_tsv = _safe_gzip_decompress(packages_data).decode('utf-8')

        # Write to temp file with scan_id, product_id, and system_id prepended
        logger.info("Preparing packages for COPY...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as f:
            pkg_tmp_path = f.name
            pkg_count = 0
            for line in packages_tsv.strip().split('\n'):
                if line:
                    # Prepend scan_id, product_id, system_id
                    f.write(f"{scan.id}\t{product_id}\t{system_id}\t{line}\n")
                    pkg_count += 1

        del packages_tsv
        del packages_data

        logger.info(f"Importing {pkg_count} packages via COPY...")
        with open(pkg_tmp_path, 'r') as f:
            cursor.copy_from(
                f,
                'packages',
                columns=('scan_id', 'product_id', 'system_id', 'name', 'version', 'release',
                         'arch', 'epoch', 'source_rpm', 'license', 'purl', 'cpes',
                         'layer_id', 'layer_index', 'source_image'),
                null='\\N'
            )
        raw_conn.commit()

        # Clean up packages temp file immediately after use
        os.unlink(pkg_tmp_path)
        pkg_tmp_path = None

        job.processed_packages = pkg_count
        db.commit()

        # Get package ID mapping
        logger.info("Building package ID mapping...")
        cursor.execute(
            "SELECT id, name, version, arch FROM packages WHERE scan_id = %s",
            (scan.id,)
        )
        pkg_id_map = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}

        # Check if files TSV exists
        if not storage.exists(job.files_tsv_key):
            logger.info("No files TSV found, skipping file import")
            return

        # Download and decompress files TSV
        logger.info("Downloading files TSV...")
        files_data = storage.get(job.files_tsv_key)
        files_tsv = _safe_gzip_decompress(files_data).decode('utf-8')

        # Write to temp file with IDs resolved
        logger.info("Preparing files for COPY...")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as f:
            files_tmp_path = f.name
            file_count = 0
            for line in files_tsv.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    # TSV format: pkg_name, pkg_version, pkg_arch, path, digest, digest_algo
                    pkg_key = (parts[0], parts[1] if parts[1] != '\\N' else None,
                              parts[2] if parts[2] != '\\N' else None)
                    pkg_id = pkg_id_map.get(pkg_key)
                    if pkg_id:
                        # Write: package_id, scan_id, product_id, system_id, path, digest, digest_algo
                        f.write(f"{pkg_id}\t{scan.id}\t{product_id}\t{system_id}\t{parts[3]}\t{parts[4]}\t{parts[5]}\n")
                        file_count += 1

                        if file_count % 1000000 == 0:
                            logger.info(f"Files prepared: {file_count}")

        del files_tsv
        del files_data
        del pkg_id_map

        logger.info(f"Importing {file_count} files via COPY...")
        with open(files_tmp_path, 'r') as f:
            cursor.copy_from(
                f,
                'files',
                columns=('package_id', 'scan_id', 'product_id', 'system_id', 'path', 'digest', 'digest_algorithm'),
                null='\\N'
            )
        raw_conn.commit()

        # Clean up files temp file immediately after use
        os.unlink(files_tmp_path)
        files_tmp_path = None

        job.processed_files = file_count
        db.commit()

        logger.info(f"Import complete: {pkg_count} packages, {file_count} files")

    finally:
        # Ensure temp files are cleaned up even on error
        if pkg_tmp_path and os.path.exists(pkg_tmp_path):
            try:
                os.unlink(pkg_tmp_path)
            except OSError:
                pass
        if files_tmp_path and os.path.exists(files_tmp_path):
            try:
                os.unlink(files_tmp_path)
            except OSError:
                pass


def _import_tsv_sqlite(db, raw_conn, storage, job, scan, product, system):
    """Import TSV files into SQLite."""
    cursor = raw_conn.cursor()

    # Determine if this is a product or system import
    product_id = product.id if product else None
    system_id = system.id if system else None

    # Download and decompress packages TSV (with size limit)
    logger.info("Downloading packages TSV...")
    packages_data = storage.get(job.packages_tsv_key)
    packages_tsv = _safe_gzip_decompress(packages_data).decode('utf-8')

    logger.info("Importing packages...")
    pkg_count = 0
    for line in packages_tsv.strip().split('\n'):
        if line:
            parts = line.split('\t')
            # Convert \N to None
            parts = [None if p == '\\N' else p for p in parts]
            # Handle layer_index conversion (should be int or None)
            if len(parts) >= 11 and parts[10] is not None:
                try:
                    parts[10] = int(parts[10])
                except (ValueError, TypeError):
                    parts[10] = None
            cursor.execute(
                """INSERT INTO packages
                   (scan_id, product_id, system_id, name, version, release, arch, epoch, source_rpm, license, purl, cpes, layer_id, layer_index, source_image)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan.id, product_id, system_id, *parts)
            )
            pkg_count += 1
    raw_conn.commit()

    del packages_tsv
    del packages_data

    job.processed_packages = pkg_count
    db.commit()

    # Get package ID mapping
    cursor.execute(
        "SELECT id, name, version, arch FROM packages WHERE scan_id = ?",
        (scan.id,)
    )
    pkg_id_map = {(row[1], row[2], row[3]): row[0] for row in cursor.fetchall()}

    # Check if files TSV exists
    if not storage.exists(job.files_tsv_key):
        logger.info("No files TSV found, skipping file import")
        return

    # Download and decompress files TSV (with size limit)
    logger.info("Downloading files TSV...")
    files_data = storage.get(job.files_tsv_key)
    files_tsv = _safe_gzip_decompress(files_data).decode('utf-8')

    logger.info("Importing files...")
    file_count = 0
    for line in files_tsv.strip().split('\n'):
        if line:
            parts = line.split('\t')
            parts = [None if p == '\\N' else p for p in parts]
            pkg_key = (parts[0], parts[1], parts[2])
            pkg_id = pkg_id_map.get(pkg_key)
            if pkg_id:
                cursor.execute(
                    """INSERT INTO files
                       (package_id, scan_id, product_id, system_id, path, digest, digest_algorithm)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (pkg_id, scan.id, product_id, system_id, parts[3], parts[4], parts[5])
                )
                file_count += 1

                if file_count % 100000 == 0:
                    raw_conn.commit()
                    logger.info(f"Files imported: {file_count}")

    raw_conn.commit()

    del files_tsv
    del files_data

    job.processed_files = file_count
    db.commit()

    logger.info(f"Import complete: {pkg_count} packages, {file_count} files")
