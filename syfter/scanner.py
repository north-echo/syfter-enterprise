"""
Scanner module - runs Syft to generate SBOMs.
"""

import json
import subprocess
import shutil
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


class SyftNotFoundError(Exception):
    """Raised when syft is not installed or not in PATH."""

    pass


class ScanError(Exception):
    """Raised when a syft scan fails."""

    pass


def check_syft_installed() -> str:
    """
    Check if syft is installed and return its version.

    Returns:
        str: Syft version string

    Raises:
        SyftNotFoundError: If syft is not found in PATH
    """
    syft_path = shutil.which("syft")
    if not syft_path:
        raise SyftNotFoundError(
            "syft is not installed or not in PATH. "
            "Install it from: https://github.com/anchore/syft"
        )

    try:
        result = subprocess.run(
            ["syft", "version", "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        version_info = json.loads(result.stdout)
        return version_info.get("version", "unknown")
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        # Fallback to simple version check
        try:
            result = subprocess.run(
                ["syft", "version"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip().split()[-1] if result.stdout else "unknown"
        except subprocess.CalledProcessError:
            return "unknown"


def scan_target(
    target: str,
    output_format: str = "syft-json",
    catalogers: Optional[list[str]] = None,
    extra_args: Optional[list[str]] = None,
) -> dict:
    """
    Run syft against a target and return the SBOM as a dictionary.

    Args:
        target: Path to directory, container image, or other syft-supported target
        output_format: Output format (default: syft-json)
        catalogers: Optional list of catalogers to use (e.g., ["rpm"])
        extra_args: Optional additional arguments to pass to syft

    Returns:
        dict: Parsed SBOM JSON

    Raises:
        SyftNotFoundError: If syft is not installed
        ScanError: If the scan fails
    """
    syft_version = check_syft_installed()
    console.print(f"[dim]Using syft version: {syft_version}[/dim]")

    # Build command
    cmd = ["syft", target, "-o", output_format]

    # Add catalogers if specified
    if catalogers:
        for cataloger in catalogers:
            cmd.extend(["--catalogers", cataloger])

    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args)

    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ScanError(f"Syft scan failed: {e.stderr}") from e

    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"Failed to parse syft output as JSON: {e}") from e

    return sbom, syft_version


def scan_directory(
    directory: Path,
    catalogers: Optional[list[str]] = None,
) -> tuple[dict, str]:
    """
    Scan a directory of packages (typically RPMs).

    Args:
        directory: Path to the directory to scan
        catalogers: Optional list of catalogers (defaults to ["rpm"] for RPM dirs)

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    if not directory.exists():
        raise ScanError(f"Directory does not exist: {directory}")

    if not directory.is_dir():
        raise ScanError(f"Path is not a directory: {directory}")

    # Default to RPM cataloger for directories
    if catalogers is None:
        # Check if directory contains RPMs
        rpm_files = list(directory.glob("**/*.rpm"))
        if rpm_files:
            catalogers = ["rpm"]
            console.print(f"[green]Found {len(rpm_files)} RPM files[/green]")

    # Use dir: scheme for directory scanning
    target = f"dir:{directory}"

    return scan_target(target, catalogers=catalogers)


def scan_container(image: str) -> tuple[dict, str]:
    """
    Scan a container image.

    Args:
        image: Container image reference (e.g., "registry.redhat.io/rhel9:latest")

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    return scan_target(image)


def scan_archive(archive_path: Path) -> tuple[dict, str]:
    """
    Scan an archive file (tar, tar.gz, etc.).

    Args:
        archive_path: Path to the archive file

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    if not archive_path.exists():
        raise ScanError(f"Archive does not exist: {archive_path}")

    target = f"file:{archive_path}"
    return scan_target(target)


def get_source_type(target: str) -> str:
    """
    Determine the source type from the target string.

    Args:
        target: The scan target

    Returns:
        str: Source type (directory, container, archive, etc.)
    """
    if target.startswith("dir:"):
        return "directory"
    elif target.startswith("file:"):
        path = Path(target[5:])
        if path.suffix in (".tar", ".gz", ".tgz", ".zip"):
            return "archive"
        return "file"
    elif target.startswith("docker:") or target.startswith("podman:"):
        return "container"
    elif ":" in target and "/" in target:
        # Likely a container image reference
        return "container"
    elif Path(target).is_dir():
        return "directory"
    elif Path(target).is_file():
        return "file"
    else:
        return "unknown"
