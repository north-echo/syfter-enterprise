"""
System API endpoints for infrastructure scanning mode.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..db import get_db, System, Scan, Package, File
from .schemas import SystemCreate, SystemResponse

router = APIRouter()


@router.get("/", response_model=List[SystemResponse])
def list_systems(
    tag: str = None,
    db: Session = Depends(get_db),
):
    """List all systems with scan, package, and file counts."""
    query = db.query(System).order_by(System.hostname)

    if tag:
        query = query.filter(System.tag == tag)

    systems_list = query.all()

    systems = []
    for system in systems_list:
        scan_count = db.query(func.count(Scan.id)).filter(Scan.system_id == system.id).scalar() or 0
        total_packages = db.query(func.count(Package.id)).filter(Package.system_id == system.id).scalar() or 0
        total_files = db.query(func.count(File.id)).filter(File.system_id == system.id).scalar() or 0

        systems.append(SystemResponse(
            id=system.id,
            hostname=system.hostname,
            ip_address=system.ip_address,
            tag=system.tag,
            os_name=system.os_name,
            os_version=system.os_version,
            arch=system.arch,
            last_scan_at=system.last_scan_at,
            created_at=system.created_at,
            scan_count=scan_count,
            total_packages=total_packages,
            total_files=total_files,
        ))

    return systems


@router.get("/{hostname}", response_model=SystemResponse)
def get_system(hostname: str, db: Session = Depends(get_db)):
    """Get a specific system by hostname."""
    system = db.query(System).filter(System.hostname == hostname).first()

    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    scan_count = db.query(func.count(Scan.id)).filter(Scan.system_id == system.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.system_id == system.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.system_id == system.id).scalar() or 0

    return SystemResponse(
        id=system.id,
        hostname=system.hostname,
        ip_address=system.ip_address,
        tag=system.tag,
        os_name=system.os_name,
        os_version=system.os_version,
        arch=system.arch,
        last_scan_at=system.last_scan_at,
        created_at=system.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.post("/", response_model=SystemResponse, status_code=201)
def create_system(system: SystemCreate, db: Session = Depends(get_db)):
    """Create a new system."""
    # Check if system already exists
    existing = db.query(System).filter(System.hostname == system.hostname).first()
    if existing:
        raise HTTPException(status_code=409, detail="System already exists")

    db_system = System(
        hostname=system.hostname,
        ip_address=system.ip_address,
        tag=system.tag,
        os_name=system.os_name,
        os_version=system.os_version,
        arch=system.arch,
    )
    db.add(db_system)
    db.commit()
    db.refresh(db_system)

    return SystemResponse(
        id=db_system.id,
        hostname=db_system.hostname,
        ip_address=db_system.ip_address,
        tag=db_system.tag,
        os_name=db_system.os_name,
        os_version=db_system.os_version,
        arch=db_system.arch,
        last_scan_at=db_system.last_scan_at,
        created_at=db_system.created_at,
        scan_count=0,
        total_packages=0,
        total_files=0,
    )


@router.put("/{hostname}", response_model=SystemResponse)
def update_system(hostname: str, system: SystemCreate, db: Session = Depends(get_db)):
    """Update a system's metadata."""
    db_system = db.query(System).filter(System.hostname == hostname).first()
    if not db_system:
        raise HTTPException(status_code=404, detail="System not found")

    # Update fields
    db_system.ip_address = system.ip_address
    db_system.tag = system.tag
    db_system.os_name = system.os_name
    db_system.os_version = system.os_version
    db_system.arch = system.arch

    db.commit()
    db.refresh(db_system)

    scan_count = db.query(func.count(Scan.id)).filter(Scan.system_id == db_system.id).scalar() or 0
    total_packages = db.query(func.count(Package.id)).filter(Package.system_id == db_system.id).scalar() or 0
    total_files = db.query(func.count(File.id)).filter(File.system_id == db_system.id).scalar() or 0

    return SystemResponse(
        id=db_system.id,
        hostname=db_system.hostname,
        ip_address=db_system.ip_address,
        tag=db_system.tag,
        os_name=db_system.os_name,
        os_version=db_system.os_version,
        arch=db_system.arch,
        last_scan_at=db_system.last_scan_at,
        created_at=db_system.created_at,
        scan_count=scan_count,
        total_packages=total_packages,
        total_files=total_files,
    )


@router.delete("/{hostname}", status_code=204)
def delete_system(hostname: str, db: Session = Depends(get_db)):
    """Delete a system and all its scans."""
    system = db.query(System).filter(System.hostname == hostname).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    db.delete(system)
    db.commit()


@router.get("/tags/", response_model=List[str])
def list_tags(db: Session = Depends(get_db)):
    """List all unique system tags."""
    tags = db.query(System.tag).filter(System.tag.isnot(None)).distinct().all()
    return [t[0] for t in tags]
