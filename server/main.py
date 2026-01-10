"""
Main FastAPI application.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import api_router
from .config import get_config, ServerConfig
from .db import init_db

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
