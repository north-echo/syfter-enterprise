"""
Storage module - SQLite database for SBOM storage and querying.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterator

from rich.console import Console

from .models import Product, ScanRecord, PackageInfo, FileInfo

console = Console()

DEFAULT_DB_PATH = Path("~/.rh-syfter/syfter.db").expanduser()


class Storage:
    """SQLite-based storage for SBOMs and package data."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize storage with database path.

        Args:
            db_path: Path to SQLite database (defaults to ~/.rh-syfter/syfter.db)
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Products table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    vendor TEXT DEFAULT 'Red Hat',
                    cpe_vendor TEXT DEFAULT 'redhat',
                    cpe_product TEXT,
                    purl_namespace TEXT DEFAULT 'redhat',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)

            # Scans table - stores the full SBOM JSON
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    source_path TEXT NOT NULL,
                    source_type TEXT DEFAULT 'directory',
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    syft_version TEXT,
                    original_sbom TEXT NOT NULL,
                    modified_sbom TEXT NOT NULL,
                    package_count INTEGER DEFAULT 0,
                    file_count INTEGER DEFAULT 0,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Packages table - indexed for querying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    release TEXT,
                    arch TEXT,
                    epoch TEXT,
                    source_rpm TEXT,
                    license TEXT,
                    purl TEXT,
                    cpes TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Files table - indexed for querying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_id INTEGER NOT NULL,
                    scan_id INTEGER NOT NULL,
                    product_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    digest TEXT,
                    digest_algorithm TEXT DEFAULT 'sha256',
                    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                    FOREIGN KEY (product_id) REFERENCES products(id)
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_product ON packages(product_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_packages_purl ON packages(purl)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_product ON files(product_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_files_digest ON files(digest)
            """)

            conn.commit()

    def get_or_create_product(self, product: Product) -> int:
        """
        Get or create a product record.

        Args:
            product: Product object

        Returns:
            int: Product ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Try to find existing
            cursor.execute(
                "SELECT id FROM products WHERE name = ? AND version = ?",
                (product.name, product.version),
            )
            row = cursor.fetchone()
            if row:
                return row["id"]

            # Create new
            cursor.execute(
                """
                INSERT INTO products (name, version, vendor, cpe_vendor, cpe_product, purl_namespace, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product.name,
                    product.version,
                    product.vendor,
                    product.cpe_vendor,
                    product.cpe_product,
                    product.purl_namespace,
                    product.description,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def store_scan(
        self,
        product_id: int,
        source_path: str,
        source_type: str,
        syft_version: str,
        original_sbom: dict,
        modified_sbom: dict,
        packages: list[dict],
    ) -> int:
        """
        Store a scan result with indexed package data.

        Args:
            product_id: Product ID
            source_path: Path to scanned source
            source_type: Type of source (directory, container, etc.)
            syft_version: Version of syft used
            original_sbom: Original syft-json SBOM
            modified_sbom: Modified SBOM with product metadata
            packages: List of extracted package dictionaries

        Returns:
            int: Scan ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Count files
            file_count = sum(len(pkg.get("files", [])) for pkg in packages)

            # Insert scan record
            cursor.execute(
                """
                INSERT INTO scans (product_id, source_path, source_type, syft_version,
                                   original_sbom, modified_sbom, package_count, file_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    product_id,
                    source_path,
                    source_type,
                    syft_version,
                    json.dumps(original_sbom),
                    json.dumps(modified_sbom),
                    len(packages),
                    file_count,
                ),
            )
            scan_id = cursor.lastrowid

            # Insert packages and files
            for pkg in packages:
                cursor.execute(
                    """
                    INSERT INTO packages (scan_id, product_id, name, version, release,
                                         arch, epoch, source_rpm, license, purl, cpes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        product_id,
                        pkg.get("name", ""),
                        pkg.get("version", ""),
                        pkg.get("release", ""),
                        pkg.get("arch", ""),
                        pkg.get("epoch", ""),
                        pkg.get("source_rpm", ""),
                        pkg.get("license", ""),
                        pkg.get("purl", ""),
                        pkg.get("cpes", "[]"),
                    ),
                )
                package_id = cursor.lastrowid

                # Insert files
                for f in pkg.get("files", []):
                    cursor.execute(
                        """
                        INSERT INTO files (package_id, scan_id, product_id, path, digest, digest_algorithm)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            package_id,
                            scan_id,
                            product_id,
                            f.get("path", ""),
                            f.get("digest", ""),
                            f.get("digest_algorithm", "sha256"),
                        ),
                    )

            conn.commit()
            console.print(
                f"[green]Stored scan #{scan_id}: {len(packages)} packages, {file_count} files[/green]"
            )
            return scan_id

    def get_product_sbom(self, product_name: str, product_version: str) -> Optional[dict]:
        """
        Get the full modified SBOM for a product.

        Args:
            product_name: Product name (e.g., "rhel")
            product_version: Product version (e.g., "10.0")

        Returns:
            dict: Modified SBOM or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.modified_sbom
                FROM scans s
                JOIN products p ON s.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY s.scan_timestamp DESC
                LIMIT 1
                """,
                (product_name, product_version),
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row["modified_sbom"])
            return None

    def get_all_product_sboms(self, product_name: str, product_version: str) -> list[dict]:
        """
        Get all SBOMs for a product (in case of multiple scans).

        Args:
            product_name: Product name
            product_version: Product version

        Returns:
            list: List of SBOM dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.modified_sbom, s.source_path, s.scan_timestamp
                FROM scans s
                JOIN products p ON s.product_id = p.id
                WHERE p.name = ? AND p.version = ?
                ORDER BY s.scan_timestamp DESC
                """,
                (product_name, product_version),
            )
            return [
                {
                    "sbom": json.loads(row["modified_sbom"]),
                    "source_path": row["source_path"],
                    "scan_timestamp": row["scan_timestamp"],
                }
                for row in cursor.fetchall()
            ]

    def search_packages(
        self,
        name_pattern: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Search for packages across all products.

        Args:
            name_pattern: SQL LIKE pattern for package name (use % as wildcard)
            product_name: Filter by product name
            product_version: Filter by product version
            limit: Maximum results to return

        Returns:
            list: List of matching packages with product info
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT pkg.*, p.name as product_name, p.version as product_version
                FROM packages pkg
                JOIN products p ON pkg.product_id = p.id
                WHERE 1=1
            """
            params = []

            if name_pattern:
                query += " AND pkg.name LIKE ?"
                params.append(name_pattern)

            if product_name:
                query += " AND p.name = ?"
                params.append(product_name)

            if product_version:
                query += " AND p.version = ?"
                params.append(product_version)

            query += " ORDER BY pkg.name LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def search_files(
        self,
        path_pattern: Optional[str] = None,
        digest: Optional[str] = None,
        product_name: Optional[str] = None,
        product_version: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Search for files across all products.

        Args:
            path_pattern: SQL LIKE pattern for file path
            digest: Exact digest match
            product_name: Filter by product name
            product_version: Filter by product version
            limit: Maximum results to return

        Returns:
            list: List of matching files with package and product info
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT f.*, pkg.name as package_name, pkg.version as package_version,
                       p.name as product_name, p.version as product_version
                FROM files f
                JOIN packages pkg ON f.package_id = pkg.id
                JOIN products p ON f.product_id = p.id
                WHERE 1=1
            """
            params = []

            if path_pattern:
                query += " AND f.path LIKE ?"
                params.append(path_pattern)

            if digest:
                query += " AND f.digest = ?"
                params.append(digest)

            if product_name:
                query += " AND p.name = ?"
                params.append(product_name)

            if product_version:
                query += " AND p.version = ?"
                params.append(product_version)

            query += " ORDER BY f.path LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def list_products(self) -> list[dict]:
        """
        List all products in the database.

        Returns:
            list: List of product dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.*, COUNT(DISTINCT s.id) as scan_count,
                       SUM(s.package_count) as total_packages
                FROM products p
                LEFT JOIN scans s ON p.id = s.product_id
                GROUP BY p.id
                ORDER BY p.name, p.version
            """)
            return [dict(row) for row in cursor.fetchall()]

    def list_scans(self, product_name: Optional[str] = None) -> list[dict]:
        """
        List all scans, optionally filtered by product.

        Args:
            product_name: Optional product name filter

        Returns:
            list: List of scan dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT s.id, s.source_path, s.source_type, s.scan_timestamp,
                       s.syft_version, s.package_count, s.file_count,
                       p.name as product_name, p.version as product_version
                FROM scans s
                JOIN products p ON s.product_id = p.id
            """
            params = []

            if product_name:
                query += " WHERE p.name = ?"
                params.append(product_name)

            query += " ORDER BY s.scan_timestamp DESC"

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its associated packages and files.

        Args:
            scan_id: Scan ID to delete

        Returns:
            bool: True if deleted, False if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> dict:
        """
        Get database statistics.

        Returns:
            dict: Statistics about the database
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) as count FROM products")
            product_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM scans")
            scan_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM packages")
            package_count = cursor.fetchone()["count"]

            cursor.execute("SELECT COUNT(*) as count FROM files")
            file_count = cursor.fetchone()["count"]

            return {
                "products": product_count,
                "scans": scan_count,
                "packages": package_count,
                "files": file_count,
                "database_path": str(self.db_path),
            }
