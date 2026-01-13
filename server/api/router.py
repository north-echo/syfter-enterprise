"""
Main API router combining all route modules.
"""

from fastapi import APIRouter

from . import products, systems, scans, queries, exports, jobs

api_router = APIRouter()

api_router.include_router(products.router, prefix="/products", tags=["products"])
api_router.include_router(systems.router, prefix="/systems", tags=["systems"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(queries.router, prefix="/query", tags=["queries"])
api_router.include_router(exports.router, prefix="/export", tags=["exports"])
api_router.include_router(jobs.router, tags=["jobs"])