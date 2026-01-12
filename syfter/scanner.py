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


# Patterns for debug packages to exclude from scans
# Patterns must start with './', '*/', or '**/' per syft requirements
DEBUG_EXCLUDE_PATTERNS = [
    "**/*-debuginfo-*",
    "**/*-debugsource-*",
]


def scan_target(
    target: str,
    output_format: str = "syft-json",
    catalogers: Optional[list[str]] = None,
    extra_args: Optional[list[str]] = None,
    show_progress: bool = True,
    name: Optional[str] = None,
    version: Optional[str] = None,
    exclude_debug: bool = True,
) -> dict:
    """
    Run syft against a target and return the SBOM as a dictionary.

    Args:
        target: Path to directory, container image, or other syft-supported target
        output_format: Output format (default: syft-json)
        catalogers: Optional list of catalogers to use (e.g., ["rpm"])
        extra_args: Optional additional arguments to pass to syft
        show_progress: Whether to show syft's progress output (default: True)
        name: Optional name for the source (avoids syft warning)
        version: Optional version for the source (avoids syft warning)
        exclude_debug: Whether to exclude debuginfo/debugsource packages (default: True)

    Returns:
        dict: Parsed SBOM JSON

    Raises:
        SyftNotFoundError: If syft is not installed
        ScanError: If the scan fails
    """
    import sys

    syft_version = check_syft_installed()
    console.print(f"[dim]Using syft version: {syft_version}[/dim]")

    # Build command
    cmd = ["syft", target, "-o", output_format]

    # Add name and version to avoid syft warnings about deriving from path
    if name:
        cmd.extend(["--source-name", name])
    if version:
        cmd.extend(["--source-version", version])

    # Add catalogers if specified
    # Use --override-default-catalogers to explicitly use only the catalogers we want
    if catalogers:
        # Use exact cataloger names (e.g., "rpm-db-cataloger" for RPMs)
        cataloger_names = []
        for c in catalogers:
            if c == "rpm":
                # RPM cataloger for scanning RPM files
                cataloger_names.append("rpm-archive-cataloger")
            else:
                cataloger_names.append(c)
        cmd.extend(["--override-default-catalogers", ",".join(cataloger_names)])

    # Exclude debug packages from scan
    if exclude_debug:
        for pattern in DEBUG_EXCLUDE_PATTERNS:
            cmd.extend(["--exclude", pattern])

    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args)

    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")

    if show_progress:
        # Use Popen to stream stderr (progress) while capturing stdout (SBOM)
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # Let progress output go directly to terminal
            text=True,
        )
        stdout, _ = process.communicate()

        if process.returncode != 0:
            raise ScanError(f"Syft scan failed with exit code {process.returncode}")

        result_stdout = stdout
    else:
        # Capture everything
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            result_stdout = result.stdout
        except subprocess.CalledProcessError as e:
            raise ScanError(f"Syft scan failed: {e.stderr}") from e

    try:
        sbom = json.loads(result_stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"Failed to parse syft output as JSON: {e}") from e

    return sbom, syft_version


def scan_directory(
    directory: Path,
    catalogers: Optional[list[str]] = None,
    show_progress: bool = True,
    name: Optional[str] = None,
    version: Optional[str] = None,
    exclude_debug: bool = True,
) -> tuple[dict, str]:
    """
    Scan a directory of packages (typically RPMs).

    Args:
        directory: Path to the directory to scan
        catalogers: Optional list of catalogers (defaults to ["rpm"] for RPM dirs)
        show_progress: Whether to show syft's progress output
        name: Optional name for the source
        version: Optional version for the source
        exclude_debug: Whether to exclude debuginfo/debugsource packages (default: True)

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
            # Count non-debug RPMs for display
            if exclude_debug:
                non_debug = [f for f in rpm_files if "-debuginfo-" not in f.name and "-debugsource-" not in f.name]
                console.print(f"[green]Found {len(rpm_files)} RPM files ({len(non_debug)} non-debug)[/green]")
            else:
                console.print(f"[green]Found {len(rpm_files)} RPM files[/green]")

    # Use dir: scheme for directory scanning
    target = f"dir:{directory}"

    return scan_target(
        target,
        catalogers=catalogers,
        show_progress=show_progress,
        name=name,
        version=version,
        exclude_debug=exclude_debug,
    )


def scan_container(
    image: str,
    source: Optional[str] = None,
    pull_first: bool = False,
    arch: Optional[str] = None,
    show_progress: bool = True,
    name: Optional[str] = None,
    version: Optional[str] = None,
    exclude_debug: bool = True,
) -> tuple[dict, str]:
    """
    Scan a container image.

    Args:
        image: Container image reference (e.g., "registry.redhat.io/rhel9:latest")
        source: Optional source scheme override (podman, registry, docker, skopeo)
                If not specified, will try to auto-detect the best option.
        pull_first: If True, pull the image to a local OCI directory first using
                    skopeo, then scan that. More reliable for authenticated registries.
        arch: Architecture to pull (e.g., "amd64", "arm64"). Defaults to amd64 for skopeo.
        show_progress: Whether to show syft's progress output
        name: Optional name for the source
        version: Optional version for the source
        exclude_debug: Whether to exclude debuginfo/debugsource packages (default: True)

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    # If image already has a scheme, use as-is
    if any(image.startswith(f"{s}:") for s in ["podman", "docker", "registry", "oci-dir", "oci-archive", "docker-archive"]):
        return scan_target(image, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)

    # If pull_first is set, use skopeo to pull to OCI dir first
    if pull_first or source == "skopeo":
        return _scan_via_skopeo(image, arch=arch, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)

    # If source explicitly specified, use it
    if source:
        target = f"{source}:{image}"
        console.print(f"[dim]Using source: {source}[/dim]")
        return scan_target(target, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)

    # Auto-detect: try registry first (most reliable), then skopeo
    # The 'registry:' source in syft pulls directly from OCI registry
    # It uses the same auth as podman/docker (~/.docker/config.json or containers auth.json)
    console.print("[dim]Using direct registry pull...[/dim]")
    target = f"registry:{image}"

    try:
        return scan_target(target, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)
    except ScanError as e:
        # If registry pull fails, try skopeo as fallback
        if shutil.which("skopeo"):
            console.print("[yellow]Registry pull failed, trying skopeo...[/yellow]")
            return _scan_via_skopeo(image, arch=arch, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)
        raise


def _scan_via_skopeo(
    image: str,
    arch: Optional[str] = None,
    show_progress: bool = True,
    name: Optional[str] = None,
    version: Optional[str] = None,
    exclude_debug: bool = True,
) -> tuple[dict, str]:
    """
    Pull image using skopeo to OCI directory, then scan.

    This is more reliable for authenticated registries as skopeo
    handles auth better and the result is a local directory.

    Args:
        image: Container image reference
        arch: Architecture to pull (e.g., "amd64", "arm64"). Defaults to amd64.
        show_progress: Whether to show syft's progress output
        name: Optional name for the source
        version: Optional version for the source
        exclude_debug: Whether to exclude debuginfo/debugsource packages (default: True)

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    import tempfile
    import atexit

    skopeo_path = shutil.which("skopeo")
    if not skopeo_path:
        raise ScanError(
            "skopeo is not installed. Install it to pull images from authenticated registries. "
            "On RHEL/Fedora: dnf install skopeo"
        )

    # Create temp directory for OCI image (don't auto-delete, we'll clean up after scan)
    tmpdir = tempfile.mkdtemp(prefix="rh-syfter-")
    oci_path = Path(tmpdir) / "image"

    # Register cleanup for when program exits
    def cleanup():
        import shutil as sh
        if Path(tmpdir).exists():
            sh.rmtree(tmpdir, ignore_errors=True)
    atexit.register(cleanup)

    # Default to amd64 if not specified (most common for server images)
    target_arch = arch or "amd64"
    console.print(f"[dim]Pulling image with skopeo (linux/{target_arch})...[/dim]")

    # Pull image to OCI directory format
    # Use --override-os linux to ensure we get Linux containers (not darwin)
    # Use --override-arch to specify architecture
    cmd = [
        "skopeo", "copy",
        "--override-os", "linux",
        "--override-arch", target_arch,
        f"docker://{image}",
        f"oci:{oci_path}",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        console.print("[green]Image pulled successfully[/green]")
    except subprocess.CalledProcessError as e:
        # Cleanup on failure
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ScanError(f"Failed to pull image with skopeo: {e.stderr}") from e

    # Scan the OCI directory
    target = f"oci-dir:{oci_path}"
    try:
        result = scan_target(target, show_progress=show_progress, name=name, version=version, exclude_debug=exclude_debug)
    finally:
        # Cleanup after scan
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


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
    # Check explicit prefixes first
    if target.startswith("dir:"):
        return "directory"
    elif target.startswith("file:"):
        path = Path(target[5:])
        if path.suffix in (".tar", ".gz", ".tgz", ".zip"):
            return "archive"
        return "file"
    elif target.startswith(("docker:", "podman:", "registry:", "oci-dir:", "oci-archive:", "docker-archive:")):
        return "container"

    # Check filesystem BEFORE container image detection
    # This ensures local paths are not mistaken for container images
    path = Path(target)
    if path.is_dir():
        return "directory"
    elif path.is_file():
        if path.suffix in (".tar", ".gz", ".tgz", ".zip"):
            return "archive"
        return "file"

    # Only check for container image if it's not a filesystem path
    if _looks_like_container_image(target):
        return "container"

    return "unknown"


def _looks_like_container_image(target: str) -> bool:
    """
    Check if a target string looks like a container image reference.

    Args:
        target: The target string

    Returns:
        bool: True if it looks like a container image
    """
    # Common registry patterns
    registry_patterns = [
        "registry.redhat.io/",
        "registry.access.redhat.com/",
        "quay.io/",
        "docker.io/",
        "ghcr.io/",
        "gcr.io/",
        "mcr.microsoft.com/",
        "public.ecr.aws/",
    ]

    # Check for common registry prefixes
    for pattern in registry_patterns:
        if target.startswith(pattern):
            return True

    # Check for image:tag pattern with a registry-like structure
    # e.g., "myregistry.com/namespace/image:tag"
    if "/" in target:
        parts = target.split("/")
        first_part = parts[0]
        # If first part has a dot (domain) or colon (port), it's likely a registry
        if "." in first_part or ":" in first_part:
            return True
        # Or if there are at least 2 slashes (registry/namespace/image)
        if len(parts) >= 3:
            return True

    return False
