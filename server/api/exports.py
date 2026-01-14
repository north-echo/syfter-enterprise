"""
Export API endpoints for retrieving SBOMs.
"""

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan
from ..storage import get_storage
from .schemas import ExportResponse

router = APIRouter()


def _sanitize_filename(name: str) -> str:
    """
    Sanitize a string for use in Content-Disposition filename.

    Removes or replaces characters that could break HTTP headers or cause
    path traversal issues.
    """
    # Replace any non-alphanumeric chars (except dash, underscore, dot) with underscore
    sanitized = re.sub(r'[^\w\-.]', '_', name)
    # Remove any leading/trailing dots or dashes
    sanitized = sanitized.strip('.-')
    # Collapse multiple underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    # Ensure it's not empty
    return sanitized or "export"


@router.get("/{product_name}/{product_version}")
def get_sbom(
    product_name: str,
    product_version: str,
    format: str = Query(default="syft-json", description="Output format"),
    db: Session = Depends(get_db),
):
    """
    Get the SBOM for a product.

    For syft-json format, returns the compressed SBOM directly.
    For other formats, returns a download URL (conversion done client-side).
    """
    # Find the latest scan for this product
    result = (
        db.query(Scan)
        .join(Product, Scan.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="No SBOM found for this product")

    scan = result
    storage = get_storage()

    # Sanitize product name/version for use in filename
    safe_name = _sanitize_filename(product_name)
    safe_version = _sanitize_filename(product_version)

    if format == "syft-json":
        # Return the modified SBOM directly
        try:
            data = storage.get(scan.modified_sbom_key)
            return Response(
                content=data,
                media_type="application/gzip",
                headers={
                    "Content-Disposition": f'attachment; filename="{safe_name}-{safe_version}.syft.json.gz"'
                },
            )
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="SBOM file not found in storage")

    elif format == "original":
        # Return the original SBOM
        try:
            data = storage.get(scan.original_sbom_key)
            return Response(
                content=data,
                media_type="application/gzip",
                headers={
                    "Content-Disposition": f'attachment; filename="{safe_name}-{safe_version}.original.json.gz"'
                },
            )
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="SBOM file not found in storage")

    else:
        # For other formats, return URL to download syft-json
        # Client will convert using syft convert
        url = storage.get_url(scan.modified_sbom_key, expires_in=3600)
        return ExportResponse(
            download_url=url,
            format="syft-json",
            expires_in=3600,
        )


@router.get("/{product_name}/{product_version}/url")
def get_sbom_url(
    product_name: str,
    product_version: str,
    expires_in: int = Query(default=3600, le=86400, description="URL expiration in seconds"),
    db: Session = Depends(get_db),
):
    """Get a presigned URL to download the SBOM."""
    # Find the latest scan for this product
    result = (
        db.query(Scan)
        .join(Product, Scan.product_id == Product.id)
        .filter(Product.name == product_name, Product.version == product_version)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="No SBOM found for this product")

    scan = result
    storage = get_storage()

    return ExportResponse(
        download_url=storage.get_url(scan.modified_sbom_key, expires_in=expires_in),
        format="syft-json",
        expires_in=expires_in,
    )
