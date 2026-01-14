"""
Tests for the SBOM manipulator module.

These tests run in local mode only (no server required).
"""

import pytest
from syfter.models import Product
from syfter.manipulator import (
    modify_sbom,
    extract_packages,
    _is_debug_package,
)


class TestDebugPackageDetection:
    """Test debug package filtering."""
    
    def test_detects_debuginfo(self):
        assert _is_debug_package("kernel-debuginfo") is True
        assert _is_debug_package("bash-debuginfo-5.1.8") is True
        
    def test_detects_debugsource(self):
        assert _is_debug_package("kernel-debugsource") is True
        assert _is_debug_package("openssl-debugsource-3.0.7") is True
        
    def test_ignores_regular_packages(self):
        assert _is_debug_package("bash") is False
        assert _is_debug_package("kernel") is False
        assert _is_debug_package("debug-tools") is False  # Has "debug" but not debuginfo/debugsource


class TestModifySbom:
    """Test SBOM modification/enrichment."""
    
    @pytest.fixture
    def product(self):
        return Product(
            name="rhel",
            version="9.0",
            vendor="Red Hat",
            cpe_vendor="redhat",
            purl_namespace="redhat",
        )
    
    def test_adds_product_metadata(self, sample_sbom, product):
        modified = modify_sbom(sample_sbom, product)
        
        assert "descriptor" in modified
        assert "configuration" in modified["descriptor"]
        assert "syfter" in modified["descriptor"]["configuration"]
        
        rh_config = modified["descriptor"]["configuration"]["syfter"]
        assert rh_config["product"] == "rhel-9.0"
        assert rh_config["vendor"] == "Red Hat"
    
    def test_modifies_cpes(self, sample_sbom, product):
        modified = modify_sbom(sample_sbom, product)
        
        for artifact in modified["artifacts"]:
            cpes = artifact.get("cpes", [])
            assert len(cpes) > 0
            # Should have redhat vendor in CPE
            for cpe in cpes:
                assert "redhat" in cpe
    
    def test_modifies_purls(self, sample_sbom, product):
        modified = modify_sbom(sample_sbom, product)
        
        for artifact in modified["artifacts"]:
            purl = artifact.get("purl", "")
            if purl:
                # Should have distro qualifier
                assert "distro=rhel-9.0" in purl or "redhat" in purl
    
    def test_preserves_artifact_count(self, sample_sbom, product):
        original_count = len(sample_sbom["artifacts"])
        modified = modify_sbom(sample_sbom, product, exclude_debug=False)
        
        assert len(modified["artifacts"]) == original_count


class TestExtractPackages:
    """Test package extraction from SBOMs."""
    
    def test_extracts_basic_info(self, sample_sbom):
        packages = extract_packages(sample_sbom, skip_files=True)
        
        assert len(packages) == 3
        
        # Find bash package
        bash = next(p for p in packages if p["name"] == "bash")
        assert bash["version"] == "5.1.8-9.el9"
        assert bash["arch"] == "x86_64"
    
    def test_extracts_files(self, sample_sbom):
        packages = extract_packages(sample_sbom, skip_files=False)
        
        # Bash should have 2 files
        bash = next(p for p in packages if p["name"] == "bash")
        assert len(bash["files"]) == 2
        
        # Check file structure
        bash_file = bash["files"][0]
        assert "path" in bash_file
        assert "digest" in bash_file
    
    def test_skip_files_reduces_data(self, sample_sbom):
        with_files = extract_packages(sample_sbom, skip_files=False)
        without_files = extract_packages(sample_sbom, skip_files=True)
        
        # Same number of packages
        assert len(with_files) == len(without_files)
        
        # But no files in skip_files version
        for pkg in without_files:
            assert len(pkg.get("files", [])) == 0
    
    def test_handles_epoch(self, sample_sbom):
        packages = extract_packages(sample_sbom, skip_files=True)
        
        # OpenSSL has epoch 1
        openssl = next(p for p in packages if p["name"] == "openssl")
        assert openssl["epoch"] == "1"
        
        # Bash has epoch 0 - stored as empty string (0 is falsy)
        bash = next(p for p in packages if p["name"] == "bash")
        assert bash["epoch"] in ("", "0")  # Either empty or "0" is acceptable
