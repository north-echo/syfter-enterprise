"""
Product API endpoints.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db, Product, Scan, Package
from .schemas import ProductCreate, ProductResponse

router = APIRouter()


@router.get("/", response_model=List[ProductResponse])
def list_products(db: Session = Depends(get_db)):
    """List all products with scan and package counts."""
    results = (
        db.query(
            Product,
            func.count(func.distinct(Scan.id)).label("scan_count"),
            func.count(Package.id).label("total_packages"),
        )
        .outerjoin(Scan, Product.id == Scan.product_id)
        .outerjoin(Package, Product.id == Package.product_id)
        .group_by(Product.id)
        .all()
    )

    products = []
    for product, scan_count, total_packages in results:
        product_dict = {
            "id": product.id,
            "name": product.name,
            "version": product.version,
            "vendor": product.vendor,
            "cpe_vendor": product.cpe_vendor,
            "cpe_product": product.cpe_product,
            "purl_namespace": product.purl_namespace,
            "description": product.description,
            "created_at": product.created_at,
            "scan_count": scan_count or 0,
            "total_packages": total_packages or 0,
        }
        products.append(ProductResponse(**product_dict))

    return products


@router.get("/{product_name}/{product_version}", response_model=ProductResponse)
def get_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Get a specific product."""
    result = (
        db.query(
            Product,
            func.count(func.distinct(Scan.id)).label("scan_count"),
            func.count(Package.id).label("total_packages"),
        )
        .outerjoin(Scan, Product.id == Scan.product_id)
        .outerjoin(Package, Product.id == Package.product_id)
        .filter(Product.name == product_name, Product.version == product_version)
        .group_by(Product.id)
        .first()
    )

    if not result:
        raise HTTPException(status_code=404, detail="Product not found")

    product, scan_count, total_packages = result
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
        scan_count=scan_count or 0,
        total_packages=total_packages or 0,
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
    )


@router.delete("/{product_name}/{product_version}", status_code=204)
def delete_product(product_name: str, product_version: str, db: Session = Depends(get_db)):
    """Delete a product and all its scans."""
    product = (
        db.query(Product)
        .filter(Product.name == product_name, Product.version == product_version)
        .first()
    )
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    db.delete(product)
    db.commit()
