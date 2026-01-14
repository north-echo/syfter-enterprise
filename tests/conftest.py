"""
Pytest configuration and shared fixtures for syfter tests.

Usage:
    # Run tests in local mode (default, fast)
    pytest
    
    # Run tests against server (set env var)
    SYFTER_TEST_SERVER=http://localhost:8000 pytest -m "server_only"
    
    # Run only local tests
    pytest -m "not server_only"
    
    # Run only server tests
    SYFTER_TEST_SERVER=http://localhost:8000 pytest -m "server_only"
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Generator

import pytest


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--keep-data",
        action="store_true",
        default=False,
        help="Keep test data after tests complete (for debugging)",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "server_only: mark test to run only in server mode"
    )
    config.addinivalue_line(
        "markers", "local_only: mark test to run only in local mode"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


@pytest.fixture(scope="session")
def server_url() -> Optional[str]:
    """Get server URL from environment variable."""
    return os.environ.get("SYFTER_TEST_SERVER")


@pytest.fixture(scope="session")
def is_server_mode() -> bool:
    """Check if we're running in server mode."""
    return os.environ.get("SYFTER_TEST_SERVER") is not None


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Path to test data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def temp_dir(request) -> Generator[Path, None, None]:
    """Create a temporary directory for test artifacts."""
    tmpdir = Path(tempfile.mkdtemp(prefix="syfter-test-"))
    yield tmpdir
    
    # Clean up unless --keep-data was specified
    if not request.config.getoption("--keep-data"):
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="function")
def local_db(temp_dir) -> Generator[Path, None, None]:
    """Create a fresh SQLite database for each test."""
    db_path = temp_dir / f"test_{os.getpid()}_{id(object())}.db"
    
    # Set environment variable so Storage uses this database
    old_db = os.environ.get("SYFTER_DB")
    os.environ["SYFTER_DB"] = str(db_path)
    
    yield db_path
    
    # Restore original
    if old_db:
        os.environ["SYFTER_DB"] = old_db
    else:
        os.environ.pop("SYFTER_DB", None)
    
    # Clean up database
    if db_path.exists():
        db_path.unlink()


@pytest.fixture(scope="function")
def storage(local_db):
    """Get a Storage instance using the test database."""
    from syfter.storage import Storage
    return Storage(db_path=local_db)


@pytest.fixture(scope="function")
def client(server_url, is_server_mode):
    """Get a SyfterClient instance (only in server mode)."""
    if not is_server_mode:
        pytest.skip("Test requires server mode (set SYFTER_TEST_SERVER)")
    
    from syfter.client import SyfterClient
    with SyfterClient(server_url) as client:
        yield client


@pytest.fixture(scope="session")
def sample_sbom(test_data_dir) -> dict:
    """Load the sample SBOM for testing."""
    import json
    sbom_path = test_data_dir / "sample_sbom.json"
    if not sbom_path.exists():
        pytest.skip(f"Sample SBOM not found at {sbom_path}")
    
    with open(sbom_path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def sample_packages(sample_sbom) -> list:
    """Extract packages from sample SBOM."""
    from syfter.manipulator import extract_packages
    return extract_packages(sample_sbom, skip_files=True)


# Helper functions for tests
def skip_if_no_syft():
    """Skip test if syft is not installed."""
    if shutil.which("syft") is None:
        pytest.skip("syft not installed")


def skip_if_no_skopeo():
    """Skip test if skopeo is not installed."""
    if shutil.which("skopeo") is None:
        pytest.skip("skopeo not installed")
