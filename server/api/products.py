"""
Product API endpoints.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package, File, ImageLayer, Job
from .schemas import ProductCreate, ProductResponse

router = APIRouter()


@router.get("/", response_model=List[ProductResponse])
def list_products(db: Session = Depends(get_db)):
    """List all products with scan, package, and file counts."""
    # Get all products first
    products_list = db.query(Product).order_by(Product.name, Product.version).all()

    products = []
    for product in products_list:
        scan_count = db.query(func.count(Scan.id)).filter(Scan.product_id == product.id).scalar() or 0
        total_packages = db.query(func.count(Package.id)).filter(Package.product_id == product.id).scalar() or 0
        total_files = db.query(func.count(File.id)).filter(File.product_id == product.id).scalar() or 0

        # Get source_type from the most recent scan
        latest_scan = (
            db.query(Scan)
            .filter(Scan.product_id == product.id)
            .order_by(Scan.scan_timestamp.desc())
            .first()
        )
        source_type = latest_scan.source_type if latest_scan else None

        products.append(ProductResponse(
            id=product.id,
            name=product.name,
            version=product.version,
            vendor=product.vendor,
            cpe_vendor=product.cpe_vendor,
            cpe_product=product.cpe_product,
            purl_namespace=product.purl_namespace,
            description=product.description,
            created_at=product.created_at,
            scan_count=scan_count,
            total_packages=total_packages,
            total_files=total_files,
            source_type=source_type,
        ))

    return products


@router.get("/{product_name}/{product_version}", response_model=ProductResponse)
def get_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get a specific product."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    scan_count = db.query(func.count(Scan.id)).filter(Scan.product_id == product.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.product_id == product.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.product_id == product.id).scalar() or 0

    return ProductResponse(
        id=product.id,
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product,
        purl_namespace=product.purl_namespace,
        description=product.description,
        created_at=product.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.post("/", response_model=ProductResponse, status_code=201)
def create_product(product: ProductCreate, db: Session = Depends(get_db)):
    """Create a new product."""
    # Check if product already exists
    existing = (
        db.query(Product)
        .filter(Product.name == product.name, Product.version == product.version)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Product already exists")

    db_product = Product(
        name=product.name,
        version=product.version,
        vendor=product.vendor,
        cpe_vendor=product.cpe_vendor,
        cpe_product=product.cpe_product or product.name,
        purl_namespace=product.purl_namespace,
        description=product.description,
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    return ProductResponse(
        id=db_product.id,
        name=db_product.name,
        version=db_product.version,
        vendor=db_product.vendor,
        cpe_vendor=db_product.cpe_vendor,
        cpe_product=db_product.cpe_product,
        purl_namespace=db_product.purl_namespace,
        description=db_product.description,
        created_at=db_product.created_at,
        scan_count=0,
        total_packages=0,
        total_files=0,
    )


@router.get("/{product_name}/{product_version}/layers")
def get_product_layers(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get container layer chain for a product (for container scans only)."""
    import json

    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Get the latest scan with layer info
    scan = (
        db.query(Scan)
        .filter(Scan.product_id == product.id)
        .order_by(Scan.scan_timestamp.desc())
        .first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="No scans found for this product")

    if not scan.image_layers_json:
        raise HTTPException(status_code=404, detail="No layer information available (not a container scan)")

    layers = json.loads(scan.image_layers_json)
    return {
        "product_name": product.name,
        "product_version": product.version,
        "source_path": scan.source_path,
        "source_type": scan.source_type,
        "layers": layers,
    }


@router.delete("/{product_name}/{product_version}", status_code=204)
def delete_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Delete a product and all its scans, packages, and files."""
    from sqlalchemy import text

    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    product_id = product.id

    # Use raw SQL to ensure proper deletion order
    # Delete in order to respect foreign key constraints:
    # jobs (by scan_id) -> jobs (by product_id) -> files -> packages -> image_layers -> scans -> product
    
    # Delete jobs that reference scans for this product
    db.execute(text("""
        DELETE FROM jobs WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    
    # Delete jobs that reference the product directly
    db.execute(text("DELETE FROM jobs WHERE product_id = :product_id"), {"product_id": product_id})
    
    # Delete files
    db.execute(text("DELETE FROM files WHERE product_id = :product_id"), {"product_id": product_id})
    
    # Delete packages
    db.execute(text("DELETE FROM packages WHERE product_id = :product_id"), {"product_id": product_id})
    
    # Delete image layers
    db.execute(text("""
        DELETE FROM image_layers WHERE scan_id IN (
            SELECT id FROM scans WHERE product_id = :product_id
        )
    """), {"product_id": product_id})
    
    # Delete scans
    db.execute(text("DELETE FROM scans WHERE product_id = :product_id"), {"product_id": product_id})
    
    # Delete product
    db.execute(text("DELETE FROM products WHERE id = :product_id"), {"product_id": product_id})
    
    db.commit()
