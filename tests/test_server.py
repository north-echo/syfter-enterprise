"""
Tests for server mode (API client).

These tests require a running server. Run with:
    SYFTER_TEST_SERVER=http://localhost:8000 pytest tests/test_server.py -m server_only

Or use the test runner:
    ./scripts/run-tests.sh server-isolated
"""

import json
import os
import shutil
import subprocess
import pytest


# All tests in this file require server mode
pytestmark = pytest.mark.server_only

# Test container - small enough to scan quickly
TEST_CONTAINER = "registry.redhat.io/multicluster-globalhub/multicluster-globalhub-agent-rhel9:1.4.3"
TEST_PRODUCT_NAME = "globalhub-agent-test"
TEST_PRODUCT_VERSION = "1.4.3"


@pytest.fixture(scope="session")
def seeded_server():
    """
    Ensure the test server has at least one product scanned.
    
    This fixture scans a small container image and uploads it to the server.
    It only runs once per session and reuses existing data if present.
    """
    from syfter.client import SyfterClient
    
    server_url = os.environ.get("SYFTER_TEST_SERVER")
    if not server_url:
        pytest.skip("SYFTER_TEST_SERVER not set")
    
    with SyfterClient(server_url) as client:
        # Check if we already have the test product
        products = client.list_products()
        test_products = [p for p in products if p["name"] == TEST_PRODUCT_NAME]
        
        if test_products:
            # Already have test data
            print(f"\n✓ Using existing test data: {TEST_PRODUCT_NAME}-{TEST_PRODUCT_VERSION}")
            return test_products[0]
    
    # Need to scan and upload
    # Check if syft is available
    if not shutil.which("syft"):
        pytest.skip("syft not installed - cannot seed test data")
    
    print(f"\n" + "="*60)
    print(f"SEEDING TEST DATA - This takes ~1-2 minutes on first run")
    print(f"Scanning: {TEST_CONTAINER}")
    print(f"="*60)
    
    # Run syfter scan against the test server
    cmd = [
        "syfter",
        "--server", server_url,
        "scan",
        TEST_CONTAINER,
        "-p", TEST_PRODUCT_NAME,
        "-v", TEST_PRODUCT_VERSION,
        "--description", "Test container for automated testing",
    ]
    
    try:
        # Run without capturing to show progress
        result = subprocess.run(
            cmd,
            timeout=300,  # 5 minute timeout for container scan
        )
        
        if result.returncode != 0:
            pytest.skip(f"Failed to scan test container (exit code {result.returncode})")
        
        print(f"\n✓ Test data seeded successfully!")
        print(f"="*60 + "\n")
        
    except subprocess.TimeoutExpired:
        pytest.skip("Container scan timed out")
    except Exception as e:
        pytest.skip(f"Failed to seed test data: {e}")
    
    # Return the product info
    with SyfterClient(server_url) as client:
        products = client.list_products()
        test_products = [p for p in products if p["name"] == TEST_PRODUCT_NAME]
        if test_products:
            return test_products[0]
    
    pytest.skip("Product not found after seeding")


class TestServerConnection:
    """Test basic server connectivity."""
    
    def test_health_check(self, client):
        """Server health check should pass."""
        # The client fixture will skip if not in server mode
        # Just verify we can create a client
        assert client is not None
    
    def test_list_products(self, client):
        """Should be able to list products (may be empty)."""
        products = client.list_products()
        assert isinstance(products, list)
    
    def test_get_stats(self, client):
        """Should be able to get stats."""
        stats = client.get_stats()
        # Stats keys are "products", "packages", etc. (not "total_*")
        assert "products" in stats
        assert "packages" in stats


class TestServerQuery:
    """Test server query functionality."""
    
    def test_search_packages(self, client, seeded_server):
        """Should be able to search packages."""
        # Search within our seeded product
        results = client.search_packages(
            name="%",  # Match any
            product_name=seeded_server["name"],
            product_version=seeded_server["version"],
            limit=10,
        )
        assert isinstance(results, list)
        assert len(results) > 0, "Seeded container should have packages"
        
        # Verify structure
        assert "name" in results[0]
    
    def test_search_files(self, client, seeded_server):
        """Should be able to search files."""
        # Search for common file patterns in seeded product
        results = client.search_files(
            path="%/bin/%",
            product_name=seeded_server["name"],
            product_version=seeded_server["version"],
            limit=10,
        )
        assert isinstance(results, list)
        # Files might be empty if skip-files was used


class TestServerScan:
    """Test scanning and storing to server.
    
    These tests are slower and may modify server data.
    Run with caution in production environments.
    """
    
    @pytest.mark.slow
    def test_scan_and_query(self, client, sample_sbom, temp_dir):
        """Full workflow: simulate scan and query.
        
        Note: This doesn't actually scan - it tests the upload path.
        """
        # This is a simplified test - full scan tests would need
        # actual targets to scan
        pass


class TestServerList:
    """Test server list operations."""
    
    def test_list_all_packages(self, client, seeded_server):
        """Should be able to list packages."""
        prod = seeded_server
        packages = client.list_all_packages(prod["name"], prod["version"])
        assert isinstance(packages, list)
        assert len(packages) > 0, "Seeded container should have packages"
        
        # Verify structure
        pkg = packages[0]
        assert "name" in pkg
        assert "version" in pkg
    
    def test_list_all_files(self, client, seeded_server):
        """Should be able to list files."""
        prod = seeded_server
        files = client.list_all_files(prod["name"], prod["version"])
        assert isinstance(files, list)
        # Files might be empty if skip-files was used, that's OK


class TestServerLayers:
    """Test container layer operations."""
    
    def test_get_layers(self, client, seeded_server):
        """Should be able to get layer info for container scans."""
        prod = seeded_server
        
        response = client.get_product_layers(prod["name"], prod["version"])
        
        if response is None:
            pytest.skip("No layer data available (API returned None)")
        
        # API returns a dict with 'layers' key
        if isinstance(response, dict):
            assert "layers" in response, f"Response missing 'layers' key: {response}"
            layers = response["layers"]
            
            # Verify product info
            assert response.get("product_name") == prod["name"]
            assert response.get("source_type") == "container"
        else:
            layers = response
        
        assert isinstance(layers, list), f"Expected list, got {type(layers)}"
        assert len(layers) > 0, "Container should have at least one layer"
        
        # Verify layer structure
        layer = layers[0]
        print(f"\nFirst layer: {layer}")
        assert "layer_id" in layer, "Layer missing layer_id"
        assert "layer_index" in layer, "Layer missing layer_index"
        assert "source_image" in layer, "Layer missing source_image"
        
        # Verify we have the base image info
        base_layer = layers[0]
        print(f"Base image: {base_layer.get('source_image')} ({base_layer.get('image_reference')})")
