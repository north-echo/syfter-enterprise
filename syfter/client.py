"""
API client for communicating with the RH-Syfter server.
"""

import gzip
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import httpx
from rich.console import Console

console = Console()


class APIError(Exception):
    """Raised when an API call fails."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


class SyfterClient:
    """Client for the RH-Syfter API."""

    def __init__(self, base_url: str, timeout: float = 600.0):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the API server (e.g., http://localhost:8000)
            timeout: Request timeout in seconds (default: 600 for large uploads)
        """
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.timeout = timeout
        # Use longer timeouts for uploads - large SBOMs can take minutes
        # Force HTTP/1.1 for large uploads - HTTP/2 can have issues with very large requests
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=30.0, read=timeout, write=timeout),
            http2=False,  # Disable HTTP/2 for more reliable large uploads
        )

    def _url(self, path: str) -> str:
        """Build full URL for an API path."""
        return f"{self.api_url}{path}"

    def _handle_response(self, response: httpx.Response) -> dict:
        """Handle API response, raising on errors."""
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise APIError(response.status_code, detail)
        return response.json() if response.text else {}

    def health_check(self) -> bool:
        """Check if the server is healthy."""
        try:
            response = self.client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception:
            return False

    def get_stats(self) -> dict:
        """Get server statistics."""
        response = self.client.get(self._url("/query/stats"))
        return self._handle_response(response)

    # Product operations
    def list_products(self) -> list:
        """List all products."""
        response = self.client.get(self._url("/products/"))
        return self._handle_response(response)

    def get_product(self, name: str, version: str) -> dict:
        """Get a specific product."""
        response = self.client.get(self._url(f"/products/{name}/{version}"))
        return self._handle_response(response)

    def create_product(
        self,
        name: str,
        version: str,
        vendor: str = "Red Hat",
        cpe_vendor: str = "redhat",
        purl_namespace: str = "redhat",
        description: str = "",
    ) -> dict:
        """Create a product."""
        response = self.client.post(
            self._url("/products/"),
            json={
                "name": name,
                "version": version,
                "vendor": vendor,
                "cpe_vendor": cpe_vendor,
                "purl_namespace": purl_namespace,
                "description": description,
            },
        )
        return self._handle_response(response)

    # Scan operations
    def list_scans(self, product_name: Optional[str] = None) -> list:
        """List scans, optionally filtered by product."""
        params = {}
        if product_name:
            params["product_name"] = product_name
        response = self.client.get(self._url("/scans/"), params=params)
        return self._handle_response(response)

    def upload_scan(
        self,
        product_name: str,
        product_version: str,
        source_path: str,
        source_type: str,
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list,
    ) -> dict:
        """
        Upload a complete scan.

        Args:
            product_name: Product name
            product_version: Product version
            source_path: Path that was scanned
            source_type: Type of source
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM dict
            modified_sbom: Modified SBOM dict
            packages: List of package dicts for indexing

        Returns:
            dict: Scan response
        """
        import tempfile
        import subprocess
        import os
        
        # Compress data to temp files for streaming upload
        console.print("[dim]Compressing data to temp files...[/dim]")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            original_path = Path(tmpdir) / "original.json.gz"
            modified_path = Path(tmpdir) / "modified.json.gz"
            packages_path = Path(tmpdir) / "packages.json.gz"
            
            # Write compressed data to files
            with gzip.open(original_path, 'wt', encoding='utf-8') as f:
                json.dump(original_sbom, f)
            with gzip.open(modified_path, 'wt', encoding='utf-8') as f:
                json.dump(modified_sbom, f)
            with gzip.open(packages_path, 'wt', encoding='utf-8') as f:
                json.dump(packages, f)
            
            original_size = original_path.stat().st_size
            modified_size = modified_path.stat().st_size
            packages_size = packages_path.stat().st_size
            total_size = original_size + modified_size + packages_size

            console.print(
                f"[dim]Uploading scan: "
                f"original={original_size/1024/1024:.1f}MB, "
                f"modified={modified_size/1024/1024:.1f}MB, "
                f"index={packages_size/1024:.1f}KB "
                f"(total: {total_size/1024/1024:.1f}MB)[/dim]"
            )
            console.print("[dim]Sending to server via curl (this may take a while for large uploads)...[/dim]")
            
            # Use curl for large uploads - more reliable for very large multipart uploads
            curl_cmd = [
                "curl", "-s", "-S", "-X", "POST",
                self._url("/scans/upload"),
                "-F", f"product_name={product_name}",
                "-F", f"product_version={product_version}",
                "-F", f"source_path={source_path}",
                "-F", f"source_type={source_type}",
                "-F", f"syft_version={syft_version or ''}",
                "-F", f"original_sbom=@{original_path};type=application/gzip",
                "-F", f"modified_sbom=@{modified_path};type=application/gzip",
                "-F", f"packages_json=@{packages_path};type=application/gzip",
                "--connect-timeout", "30",
                "--max-time", "3600",  # 1 hour max
            ]
            
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise APIError(500, f"Upload failed: {result.stderr}")
            
            try:
                response_data = json.loads(result.stdout)
                if "detail" in response_data:
                    raise APIError(400, response_data["detail"])
                return response_data
            except json.JSONDecodeError:
                raise APIError(500, f"Invalid response: {result.stdout}")

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan."""
        response = self.client.delete(self._url(f"/scans/{scan_id}"))
        if response.status_code >= 400:
            self._handle_response(response)

    # Query operations
    def search_packages(
        self,
        name: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for packages."""
        params = {"limit": limit}
        if name:
            params["name"] = name
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version

        response = self.client.get(self._url("/query/packages"), params=params)
        return self._handle_response(response)

    def search_files(
        self,
        path: Optional[str] = None,
        digest: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list:
        """Search for files."""
        params = {"limit": limit}
        if path:
            params["path"] = path
        if digest:
            params["digest"] = digest
        if product_name:
            params["product_name"] = product_name
        if product_version:
            params["product_version"] = product_version

        response = self.client.get(self._url("/query/files"), params=params)
        return self._handle_response(response)

    # Export operations
    def get_sbom(
        self,
        product_name: str,
        product_version: str,
        format: str = "syft-json",
    ) -> bytes:
        """
        Download an SBOM.

        Args:
            product_name: Product name
            product_version: Product version
            format: Output format (syft-json, original)

        Returns:
            bytes: Compressed SBOM data
        """
        response = self.client.get(
            self._url(f"/export/{product_name}/{product_version}"),
            params={"format": format},
        )
        if response.status_code >= 400:
            self._handle_response(response)
        return response.content

    def get_sbom_url(
        self,
        product_name: str,
        product_version: str,
        expires_in: int = 3600,
    ) -> str:
        """Get a presigned URL for downloading an SBOM."""
        response = self.client.get(
            self._url(f"/export/{product_name}/{product_version}/url"),
            params={"expires_in": expires_in},
        )
        data = self._handle_response(response)
        return data["download_url"]

    def close(self):
        """Close the client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def get_client(server_url: Optional[str] = None) -> SyfterClient:
    """
    Get a client instance.

    Args:
        server_url: Server URL (defaults to SYFTER_SERVER env var or http://localhost:8000)

    Returns:
        SyfterClient: Client instance
    """
    import os

    url = server_url or os.getenv("SYFTER_SERVER", "http://localhost:8000")
    return SyfterClient(url)
