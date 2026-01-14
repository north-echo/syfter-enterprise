"""
Main FastAPI application.
"""

import logging
import time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .api import api_router
from .config import get_config, ServerConfig
from .db import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Large SBOM uploads can be 500MB+ compressed
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1GB

app = FastAPI(
    title="RH-Syfter API",
    description="SBOM generation and management API for Red Hat products",
    version="0.2.0",
)

# Add CORS middleware for browser-based clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with timing."""
    start_time = time.time()

    # Log request start
    content_length = request.headers.get("content-length", "unknown")
    logger.info(f"Request started: {request.method} {request.url.path} (size: {content_length})")

    try:
        response = await call_next(request)
        elapsed = time.time() - start_time
        logger.info(f"Request completed: {request.method} {request.url.path} -> {response.status_code} ({elapsed:.2f}s)")
        return response
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Request failed: {request.method} {request.url.path} -> {type(e).__name__}: {e} ({elapsed:.2f}s)")
        raise


# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()


@app.get("/")
def root():
    """Root endpoint with API info."""
    config = get_config()
    return {
        "name": "RH-Syfter API",
        "version": "0.2.0",
        "database": config.database.type,
        "storage": config.storage.type,
    }


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "healthy"}


def run_server():
    """Run the server (entry point for CLI)."""
    config = get_config()
    uvicorn.run(
        "server.main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
        workers=1 if config.debug else config.workers,
    )


if __name__ == "__main__":
    run_server()
