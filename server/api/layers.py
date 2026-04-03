"""
Container layer tracking API endpoints.

Enables queries like:
- "What base image does product X use?"
- "Which packages came from the base image?"
- "Which products consume openssl from their base image?"
- "What did the app layer add on top of the base?"
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, distinct, collate
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package, ImageLayer

router = APIRouter()


# --- Response schemas ---

class LayerResponse(BaseModel):
    layer_id: str
    layer_index: int
    source_image: Optional[str]
    is_base: bool
    command: Optional[str]
    package_count: int = 0

    class Config:
        from_attributes = True


class LayerSummaryResponse(BaseModel):
    product_name: str
    product_version: str
    source_path: str
    source_type: str
    total_layers: int
    base_layers: int
    app_layers: int
    layers: List[LayerResponse]


class LayerPackageResponse(BaseModel):
    id: int
    name: str
    version: Optional[str]
    release: Optional[str]
    arch: Optional[str]
    source_rpm: Optional[str]
    layer_id: Optional[str]
    layer_index: Optional[int]
    source_image: Optional[str]
    is_base: Optional[bool] = None

    class Config:
        from_attributes = True


# --- Endpoints ---

@router.get("/{product_name}/{product_version}")
def get_layers(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
) -> LayerSummaryResponse:
    """Get container layer chain for a product with package counts per layer."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scans found for this product")

    # Get layers with package counts
    layer_counts = (
        db.query(
            ImageLayer,
            func.count(Package.id).label("pkg_count"),
        )
        .outerjoin(Package, Package.layer_id == ImageLayer.layer_id)
        .filter(ImageLayer.scan_id == scan.id)
        .group_by(ImageLayer.id)
        .order_by(ImageLayer.layer_index)
        .all()
    )

    if not layer_counts:
        raise HTTPException(status_code=404, detail="No layer information available (not a container scan)")

    layers = [
        LayerResponse(
            layer_id=layer.layer_id,
            layer_index=layer.layer_index,
            source_image=layer.source_image,
            is_base=layer.is_base,
            command=layer.command,
            package_count=pkg_count,
        )
        for layer, pkg_count in layer_counts
    ]

    base_count = sum(1 for l in layers if l.is_base)

    return LayerSummaryResponse(
        product_name=product.name,
        product_version=product.version,
        source_path=scan.source_path,
        source_type=scan.source_type,
        total_layers=len(layers),
        base_layers=base_count,
        app_layers=len(layers) - base_count,
        layers=layers,
    )


@router.get("/{product_name}/{product_version}/packages")
def get_layer_packages(
    product_name: str,
    product_version: str,
    layer_type: Optional[str] = Query(
        default=None,
        description="Filter by layer type: 'base' or 'app'",
    ),
    limit: int = Query(default=1000, le=10000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> List[LayerPackageResponse]:
    """
    List packages for a product, optionally filtered by layer type.

    - layer_type=base: packages from the base image only
    - layer_type=app: packages added by the application layer
    - omit layer_type: all packages with layer attribution
    """
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    query = (
        db.query(Package, ImageLayer.is_base)
        .outerjoin(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        .filter(Package.product_id == product.id)
    )

    if layer_type == "base":
        query = query.filter(ImageLayer.is_base == True)
    elif layer_type == "app":
        query = query.filter(ImageLayer.is_base == False)

    query = query.order_by(Package.name).offset(offset).limit(limit)
    results = query.all()

    return [
        LayerPackageResponse(
            id=pkg.id,
            name=pkg.name,
            version=pkg.version,
            release=pkg.release,
            arch=pkg.arch,
            source_rpm=pkg.source_rpm,
            layer_id=pkg.layer_id,
            layer_index=pkg.layer_index,
            source_image=pkg.source_image,
            is_base=is_base,
        )
        for pkg, is_base in results
    ]


@router.get("/{product_name}/{product_version}/base-image")
def get_base_image(
    product_name: str,
    product_version: str,
    db: Session = Depends(get_db),
):
    """Get the base image(s) used by a product."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scans found")

    base_images = (
        db.query(distinct(ImageLayer.source_image))
        .filter(ImageLayer.scan_id == scan.id, ImageLayer.is_base == True)
        .all()
    )

    return {
        "product_name": product.name,
        "product_version": product.version,
        "base_images": [img for (img,) in base_images if img],
    }


@router.get("/search/packages")
def search_packages_by_layer(
    name: Optional[str] = Query(default=None, description="Package name pattern (use % as wildcard)"),
    pkg_version: Optional[str] = Query(default=None, description="Package version pattern"),
    layer_type: Optional[str] = Query(default=None, description="'base' or 'app'"),
    product_name: Optional[str] = Query(default=None, description="Filter by product name"),
    limit: int = Query(default=100, le=1000, description="Maximum results"),
    offset: int = Query(default=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    """
    Search packages across products with layer type filter.

    Example: "Which products ship openssl from their base image?"
      GET /api/v1/layers/search/packages?name=openssl%&layer_type=base
    """
    from .queries import _apply_like_filter

    inner = db.query(Package.id)

    if product_name:
        inner = inner.join(Product, Package.product_id == Product.id)
        inner = inner.filter(Product.name == product_name)

    if layer_type:
        inner = inner.join(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        if layer_type == "base":
            inner = inner.filter(ImageLayer.is_base == True)
        elif layer_type == "app":
            inner = inner.filter(ImageLayer.is_base == False)

    inner = _apply_like_filter(inner, Package.name, name)
    inner = _apply_like_filter(inner, Package.version, pkg_version)
    inner = inner.order_by(collate(Package.name, "C")).offset(offset).limit(limit)
    pkg_ids = inner.subquery()

    results = (
        db.query(
            Package.name,
            Package.version,
            Package.arch,
            Package.source_image,
            ImageLayer.is_base,
            Product.name.label("product_name"),
            Product.version.label("product_version"),
        )
        .join(pkg_ids, Package.id == pkg_ids.c.id)
        .join(Product, Package.product_id == Product.id)
        .outerjoin(
            ImageLayer,
            (Package.layer_id == ImageLayer.layer_id) & (Package.scan_id == ImageLayer.scan_id),
        )
        .order_by(Package.name, Product.name)
        .all()
    )

    return [
        {
            "package_name": pkg_name,
            "package_version": pkg_ver,
            "arch": arch,
            "source_image": src_img,
            "is_base": is_base,
            "product_name": prod_name,
            "product_version": prod_ver,
        }
        for pkg_name, pkg_ver, arch, src_img, is_base, prod_name, prod_ver in results
    ]
