"""
Tests for the local SQLite storage module.

These tests run in local mode only (no server required).
"""

import json
import pytest
from syfter.models import Product
from syfter.manipulator import modify_sbom, extract_packages


class TestStorageBasics:
    """Test basic storage operations."""
    
    def test_creates_database(self, storage, local_db):
        """Storage should create database file on init."""
        assert local_db.exists()
    
    def test_list_products_empty(self, storage):
        """Empty database should return no products."""
        products = storage.list_products()
        assert products == []
    
    def test_stats_empty(self, storage):
        """Empty database should have zero stats."""
        stats = storage.get_stats()
        assert stats["products"] == 0
        assert stats["scans"] == 0
        assert stats["packages"] == 0


class TestStoreScan:
    """Test storing and retrieving scans."""
    
    @pytest.fixture
    def product(self):
        return Product(
            name="test-product",
            version="1.0",
            vendor="Test Vendor",
            cpe_vendor="test",
            purl_namespace="test",
        )
    
    def test_store_and_retrieve_scan(self, storage, sample_sbom, product):
        """Should be able to store and retrieve a scan."""
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=False)
        
        # Get or create product first
        product_id = storage.get_or_create_product(product)
        
        # Store the scan
        scan_id = storage.store_scan(
            product_id=product_id,
            source_path="/test/path",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        
        assert scan_id is not None
        assert scan_id > 0
        
        # Retrieve product
        products = storage.list_products()
        assert len(products) == 1
        assert products[0]["name"] == "test-product"
        assert products[0]["version"] == "1.0"
    
    def test_store_multiple_products(self, storage, sample_sbom):
        """Should handle multiple products."""
        for i in range(3):
            product = Product(
                name=f"product-{i}",
                version="1.0",
                vendor="Test",
                cpe_vendor="test",
                purl_namespace="test",
            )
            modified = modify_sbom(sample_sbom, product)
            packages = extract_packages(modified, skip_files=True)
            
            product_id = storage.get_or_create_product(product)
            storage.store_scan(
                product_id=product_id,
                source_path=f"/test/path/{i}",
                source_type="directory",
                syft_version="1.0.0",
                original_sbom=sample_sbom,
                modified_sbom=modified,
                packages=packages,
            )
        
        products = storage.list_products()
        assert len(products) == 3
    
    def test_replace_existing_scan(self, storage, sample_sbom, product):
        """Re-scanning same product should replace existing data."""
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=True)
        
        product_id = storage.get_or_create_product(product)
        
        # First scan
        scan_id1 = storage.store_scan(
            product_id=product_id,
            source_path="/test/path",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        
        # Second scan (should replace)
        scan_id2 = storage.store_scan(
            product_id=product_id,
            source_path="/test/path2",
            source_type="directory",
            syft_version="1.0.1",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        
        # Should still have only 1 product
        products = storage.list_products()
        assert len(products) == 1
        
        # Scan ID should be different (new record)
        assert scan_id2 != scan_id1


class TestPackageSearch:
    """Test package search functionality."""
    
    @pytest.fixture
    def populated_storage(self, storage, sample_sbom):
        """Storage with a scan already stored."""
        product = Product(
            name="search-test",
            version="1.0",
            vendor="Test",
            cpe_vendor="test",
            purl_namespace="test",
        )
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=False)
        
        product_id = storage.get_or_create_product(product)
        storage.store_scan(
            product_id=product_id,
            source_path="/test",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        return storage
    
    def test_search_by_exact_name(self, populated_storage):
        """Search by exact package name."""
        results = populated_storage.search_packages(name_pattern="bash")
        assert len(results) == 1
        assert results[0]["name"] == "bash"
    
    def test_search_by_wildcard(self, populated_storage):
        """Search with wildcard pattern."""
        results = populated_storage.search_packages(name_pattern="open%")
        assert len(results) == 1
        assert results[0]["name"] == "openssl"
    
    def test_search_no_results(self, populated_storage):
        """Search returning no results."""
        results = populated_storage.search_packages(name_pattern="nonexistent")
        assert len(results) == 0
    
    def test_search_by_product(self, populated_storage):
        """Search filtered by product."""
        results = populated_storage.search_packages(
            name_pattern="bash",
            product_name="search-test",
            product_version="1.0",
        )
        assert len(results) == 1
        
        # Wrong product should return nothing
        results = populated_storage.search_packages(
            name_pattern="bash",
            product_name="wrong-product",
        )
        assert len(results) == 0


class TestFileSearch:
    """Test file search functionality."""
    
    @pytest.fixture
    def populated_storage(self, storage, sample_sbom):
        """Storage with a scan including files."""
        product = Product(
            name="file-test",
            version="1.0",
            vendor="Test",
            cpe_vendor="test",
            purl_namespace="test",
        )
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=False)
        
        product_id = storage.get_or_create_product(product)
        storage.store_scan(
            product_id=product_id,
            source_path="/test",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        return storage
    
    def test_search_by_path(self, populated_storage):
        """Search files by path pattern."""
        results = populated_storage.search_files(path_pattern="%/bin/bash")
        assert len(results) >= 1
        assert any("/bin/bash" in r["path"] for r in results)
    
    def test_search_by_digest(self, populated_storage):
        """Search files by digest."""
        results = populated_storage.search_files(digest="abc123")
        assert len(results) >= 1


class TestListOperations:
    """Test listing operations."""
    
    @pytest.fixture
    def populated_storage(self, storage, sample_sbom):
        """Storage with a scan already stored."""
        product = Product(
            name="list-test",
            version="1.0",
            vendor="Test",
            cpe_vendor="test",
            purl_namespace="test",
        )
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=False)
        
        product_id = storage.get_or_create_product(product)
        storage.store_scan(
            product_id=product_id,
            source_path="/test",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        return storage
    
    def test_list_all_packages(self, populated_storage):
        """List all packages for a product."""
        packages = list(populated_storage.list_all_packages("list-test", "1.0"))
        assert len(packages) == 3  # bash, openssl, curl
        
        names = [p["name"] for p in packages]
        assert "bash" in names
        assert "openssl" in names
        assert "curl" in names
    
    def test_list_all_files(self, populated_storage):
        """List all files for a product."""
        files = list(populated_storage.list_all_files("list-test", "1.0"))
        assert len(files) >= 5  # At least 5 files in sample
        
        # Should include bash binary
        assert any("/bin/bash" in f for f in files)


class TestSbomRetrieval:
    """Test SBOM retrieval."""
    
    @pytest.fixture
    def populated_storage(self, storage, sample_sbom):
        """Storage with a scan already stored."""
        product = Product(
            name="sbom-test",
            version="1.0",
            vendor="Test",
            cpe_vendor="test",
            purl_namespace="test",
        )
        modified = modify_sbom(sample_sbom, product)
        packages = extract_packages(modified, skip_files=False)
        
        product_id = storage.get_or_create_product(product)
        storage.store_scan(
            product_id=product_id,
            source_path="/test",
            source_type="directory",
            syft_version="1.0.0",
            original_sbom=sample_sbom,
            modified_sbom=modified,
            packages=packages,
        )
        return storage, sample_sbom, modified
    
    def test_get_product_sbom(self, populated_storage):
        """Get modified SBOM for a product."""
        storage, original, modified = populated_storage
        
        retrieved = storage.get_product_sbom("sbom-test", "1.0")
        assert retrieved is not None
        
        # Should have same artifacts
        assert len(retrieved["artifacts"]) == len(modified["artifacts"])
