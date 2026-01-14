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


# Note: We tried using syft's --exclude patterns to filter debug packages at scan time,
# but they don't work reliably for RPM directory scans. Instead, we filter debug packages
# in modify_sbom() after the scan completes. This is actually faster since syft doesn't
# have to evaluate exclusion patterns for every file.


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

    # Note: exclude_debug parameter is kept for API compatibility but syft's --exclude
    # doesn't work reliably for RPM scans. Debug filtering happens in modify_sbom() instead.

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


def get_container_layer_mapping(
    image: str,
    arch: str = "amd64",
) -> dict[str, str]:
    """
    Extract layer-to-source-image mapping from a container image.
    
    Uses skopeo to inspect the image config and parses the history
    to determine which source image contributed each layer.
    
    Args:
        image: Container image reference (e.g., "registry.redhat.io/rhel9/go-toolset:latest")
        arch: Architecture to inspect (default: amd64)
        
    Returns:
        dict: Mapping of layer_id (truncated digest) to source image name
              e.g., {"4e140ff8bd9a2": "ubi9/ubi", "abc123...": "s2i-core"}
    """
    import re
    
    skopeo_path = shutil.which("skopeo")
    if not skopeo_path:
        console.print("[yellow]Warning: skopeo not found, cannot extract layer mapping[/yellow]")
        return {}
    
    # Get image config using skopeo
    cmd = [
        "skopeo", "inspect",
        "--override-arch", arch,
        "--override-os", "linux",
        "--config",
        f"docker://{image}",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        config = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        console.print(f"[yellow]Warning: Could not inspect image config: {e}[/yellow]")
        return {}
    
    # Get layer digests from rootfs
    rootfs = config.get("rootfs", {})
    diff_ids = rootfs.get("diff_ids", [])
    
    if not diff_ids:
        return {}
    
    # Parse history to track image name changes
    # Each image in a multi-stage build sets LABEL commands including 'name'
    history = config.get("history", [])
    
    # Track name changes and map to layers
    layer_mapping = {}
    current_name = None
    layer_idx = 0
    
    for h in history:
        empty = h.get("empty_layer", False)
        cmd = h.get("created_by", "")
        
        # Look for name label in the command
        # Patterns: name="ubi9/ubi", name=ubi9/ubi, LABEL name=...
        name_match = re.search(r'(?:LABEL\s+)?name="([^"]+)"', cmd, re.IGNORECASE)
        if not name_match:
            name_match = re.search(r'(?:LABEL\s+)?name=([^\s"]+)', cmd, re.IGNORECASE)
        
        if name_match:
            new_name = name_match.group(1)
            # Skip display names like "Red Hat Universal Base Image 9"
            # Keep image paths like "ubi9/ubi", "rhel9/go-toolset"
            if "/" in new_name or not " " in new_name:
                current_name = new_name
        
        # When we hit a non-empty layer, record the current image name
        if not empty and layer_idx < len(diff_ids):
            layer_digest = diff_ids[layer_idx]
            # Truncate digest for lookup key (matches what extract_packages does)
            if layer_digest.startswith("sha256:"):
                layer_id = layer_digest[7:20]  # First 13 chars after prefix
            else:
                layer_id = layer_digest[:13]
            
            if current_name:
                layer_mapping[layer_id] = current_name
            
            layer_idx += 1
    
    if layer_mapping:
        console.print(f"[dim]Extracted layer mapping for {len(layer_mapping)} layers[/dim]")
        for layer_id, source in layer_mapping.items():
            console.print(f"[dim]  Layer {layer_id}... -> {source}[/dim]")
    
    return layer_mapping


def get_package_source_images(
    image: str,
    packages: list[dict],
    arch: str = "amd64",
) -> dict[str, str]:
    """
    Determine which source image each package came from by scanning base images.
    
    For RPM-based containers, packages are all detected from the rpmdb in the top
    layer, so we need to scan the base images and compare package lists to determine
    true provenance.
    
    Args:
        image: Container image reference
        packages: List of packages from the main scan
        arch: Architecture (default: amd64)
        
    Returns:
        dict: Mapping of package name to source image
              e.g., {"bash": "ubi9/ubi", "golang": "rhel9/go-toolset"}
    """
    import re
    
    skopeo_path = shutil.which("skopeo")
    if not skopeo_path:
        return {}
    
    # Get image config to find base image chain
    cmd = [
        "skopeo", "inspect",
        "--override-arch", arch,
        "--override-os", "linux",
        "--config",
        f"docker://{image}",
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        config = json.loads(result.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return {}
    
    # Extract image names from history (oldest to newest)
    history = config.get("history", [])
    image_chain = []
    current_name = None
    
    for h in history:
        cmd = h.get("created_by", "")
        name_match = re.search(r'name="([^"]+)"', cmd, re.IGNORECASE)
        if not name_match:
            name_match = re.search(r'name=([^\s"]+)', cmd, re.IGNORECASE)
        
        if name_match:
            new_name = name_match.group(1)
            if "/" in new_name and new_name != current_name:
                current_name = new_name
                if current_name not in image_chain:
                    image_chain.append(current_name)
    
    if len(image_chain) <= 1:
        # Single image or couldn't determine chain
        return {}
    
    console.print(f"[dim]Detected image chain: {' -> '.join(image_chain)}[/dim]")
    console.print(f"[dim]Scanning base images to determine package provenance...[/dim]")
    
    # Build set of packages in the scanned image
    scanned_packages = {pkg.get("name") for pkg in packages if pkg.get("name")}
    
    # Scan each base image (from oldest to newest, excluding the final image)
    # Track which packages are "new" in each image
    package_sources = {}
    previous_packages = set()
    
    # We need to get the full registry path for base images
    # Try to infer it from the original image
    registry = ""
    if "/" in image:
        parts = image.split("/")
        if "." in parts[0] or ":" in parts[0]:  # Looks like a registry
            registry = parts[0] + "/"
    
    for base_image_name in image_chain[:-1]:  # Exclude final image
        # Construct full image reference
        if "/" in base_image_name and not base_image_name.startswith(registry):
            base_ref = f"{registry}{base_image_name}"
        else:
            base_ref = base_image_name
        
        console.print(f"[dim]  Scanning base: {base_ref}...[/dim]")
        
        try:
            # Quick scan just to get package list
            base_sbom, _ = _quick_scan_for_packages(base_ref, arch)
            base_packages = {art.get("name") for art in base_sbom.get("artifacts", []) if art.get("name")}
            
            # Packages in this image but not in previous = introduced by this image
            new_packages = base_packages - previous_packages
            for pkg_name in new_packages:
                if pkg_name in scanned_packages:
                    package_sources[pkg_name] = base_image_name
            
            previous_packages = base_packages
            console.print(f"[dim]    Found {len(base_packages)} packages ({len(new_packages)} new)[/dim]")
            
        except Exception as e:
            console.print(f"[yellow]    Could not scan base image: {e}[/yellow]")
            continue
    
    # Packages not found in any base image = from the final image
    final_image_name = image_chain[-1]
    for pkg_name in scanned_packages:
        if pkg_name not in package_sources:
            package_sources[pkg_name] = final_image_name
    
    console.print(f"[dim]Determined source images for {len(package_sources)} packages[/dim]")
    
    return package_sources


def _quick_scan_for_packages(
    image: str,
    arch: str = "amd64",
) -> tuple[dict, str]:
    """
    Quick scan to get package list only (no file enumeration).
    
    Args:
        image: Image reference
        arch: Architecture
        
    Returns:
        tuple: (SBOM dict, syft version)
    """
    import tempfile
    
    # Pull image first with skopeo
    with tempfile.TemporaryDirectory(prefix="rh-syfter-base-") as tmpdir:
        oci_path = Path(tmpdir) / "image"
        
        cmd = [
            "skopeo", "copy",
            "--override-os", "linux",
            "--override-arch", arch,
            f"docker://{image}",
            f"oci:{oci_path}",
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise ScanError(f"Timeout pulling base image: {image}")
        except subprocess.CalledProcessError as e:
            raise ScanError(f"Failed to pull base image {image}: {e.stderr}")
        
        # Quick scan - packages only
        syft_cmd = [
            "syft",
            f"oci-dir:{oci_path}",
            "-o", "syft-json",
            "--select-catalogers", "rpm",  # Just RPM for speed
        ]
        
        try:
            result = subprocess.run(syft_cmd, capture_output=True, text=True, check=True, timeout=120)
            sbom = json.loads(result.stdout)
            return sbom, "unknown"
        except subprocess.TimeoutExpired:
            raise ScanError(f"Timeout scanning base image: {image}")
        except subprocess.CalledProcessError as e:
            raise ScanError(f"Failed to scan base image {image}: {e.stderr}")


def scan_localhost(
    show_progress: bool = True,
    exclude_debug: bool = True,
) -> tuple[dict, str]:
    """
    Scan the local host's installed packages.

    This uses Syft's ability to scan the local filesystem and detect
    installed packages from package managers (rpm, dpkg, apk, etc.).

    Args:
        show_progress: Whether to show syft's progress output
        exclude_debug: Whether to exclude debuginfo/debugsource packages

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    import socket
    import platform
    
    hostname = socket.gethostname()
    os_info = f"{platform.system()}-{platform.release()}"
    
    console.print(f"[dim]Scanning localhost ({hostname})...[/dim]")
    
    # Use Syft to scan the root filesystem
    # The 'dir:/' target scans the root filesystem
    # On Linux this will pick up RPM, dpkg, apk databases
    return scan_target(
        "dir:/",
        show_progress=show_progress,
        name=hostname,
        version=os_info,
        exclude_debug=exclude_debug,
    )


def scan_remote_host(
    host: str,
    user: Optional[str] = None,
    port: int = 22,
    identity_file: Optional[str] = None,
    show_progress: bool = True,
    exclude_debug: bool = True,
) -> tuple[dict, str]:
    """
    Scan a remote host via SSH.

    This SSHs into the remote host, runs syft there, and retrieves the SBOM.
    Requires syft to be installed on the remote host.

    Args:
        host: Remote hostname or IP address
        user: SSH username (defaults to current user)
        port: SSH port (default: 22)
        identity_file: Path to SSH private key
        show_progress: Whether to show progress output
        exclude_debug: Whether to exclude debuginfo/debugsource packages

    Returns:
        tuple: (SBOM dict, syft version string)
    """
    import getpass
    
    # Build SSH command
    ssh_user = user or getpass.getuser()
    ssh_target = f"{ssh_user}@{host}"
    
    ssh_opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if port != 22:
        ssh_opts.extend(["-p", str(port)])
    if identity_file:
        ssh_opts.extend(["-i", identity_file])
    
    console.print(f"[dim]Connecting to {ssh_target}...[/dim]")
    
    # First, check if syft is available on remote host
    check_cmd = ["ssh"] + ssh_opts + [ssh_target, "which syft"]
    result = subprocess.run(check_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ScanError(
            f"syft is not installed on {host}. "
            "Install it from: https://github.com/anchore/syft"
        )
    
    # Get syft version on remote host
    version_cmd = ["ssh"] + ssh_opts + [ssh_target, "syft version -o json 2>/dev/null || syft version"]
    result = subprocess.run(version_cmd, capture_output=True, text=True)
    try:
        version_info = json.loads(result.stdout)
        syft_version = version_info.get("version", "unknown")
    except json.JSONDecodeError:
        syft_version = result.stdout.strip().split()[-1] if result.stdout else "unknown"
    
    console.print(f"[dim]Remote syft version: {syft_version}[/dim]")
    
    # Build remote syft command
    remote_cmd = "syft dir:/ -o syft-json"
    if exclude_debug:
        # Syft doesn't have reliable exclude patterns, but we filter in modify_sbom
        pass
    
    console.print(f"[dim]Running remote scan on {host}...[/dim]")
    
    # Run syft on remote host and capture output
    scan_cmd = ["ssh"] + ssh_opts + [ssh_target, remote_cmd]
    
    if show_progress:
        # For remote scans, we can't easily separate stderr/stdout in real-time
        # Just capture everything
        result = subprocess.run(scan_cmd, capture_output=True, text=True)
    else:
        result = subprocess.run(scan_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise ScanError(f"Remote scan failed on {host}: {result.stderr}")
    
    try:
        sbom = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ScanError(f"Failed to parse remote syft output: {e}") from e
    
    console.print(f"[green]Remote scan complete[/green]")
    return sbom, syft_version


def get_host_info() -> dict:
    """
    Get information about the local host.

    Returns:
        dict: Host information including hostname, IP, OS details
    """
    import socket
    import platform
    
    hostname = socket.gethostname()
    
    # Try to get primary IP address
    try:
        # Connect to a public DNS to get our IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        ip_address = "127.0.0.1"
    
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os_name": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
    }


def get_remote_host_info(
    host: str,
    user: Optional[str] = None,
    port: int = 22,
    identity_file: Optional[str] = None,
) -> dict:
    """
    Get information about a remote host via SSH.

    Args:
        host: Remote hostname or IP address
        user: SSH username
        port: SSH port
        identity_file: Path to SSH private key

    Returns:
        dict: Host information
    """
    import getpass
    import socket
    
    ssh_user = user or getpass.getuser()
    ssh_target = f"{ssh_user}@{host}"
    
    ssh_opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"]
    if port != 22:
        ssh_opts.extend(["-p", str(port)])
    if identity_file:
        ssh_opts.extend(["-i", identity_file])
    
    # Resolve hostname to IP address
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        ip_address = host  # Fallback to provided host if resolution fails
    
    # Get hostname
    result = subprocess.run(
        ["ssh"] + ssh_opts + [ssh_target, "hostname"],
        capture_output=True, text=True
    )
    hostname = result.stdout.strip() if result.returncode == 0 else host
    
    # Get OS info
    result = subprocess.run(
        ["ssh"] + ssh_opts + [ssh_target, "uname -s"],
        capture_output=True, text=True
    )
    os_name = result.stdout.strip() if result.returncode == 0 else "Unknown"
    
    result = subprocess.run(
        ["ssh"] + ssh_opts + [ssh_target, "uname -r"],
        capture_output=True, text=True
    )
    os_version = result.stdout.strip() if result.returncode == 0 else ""
    
    result = subprocess.run(
        ["ssh"] + ssh_opts + [ssh_target, "uname -m"],
        capture_output=True, text=True
    )
    architecture = result.stdout.strip() if result.returncode == 0 else ""
    
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os_name": os_name,
        "os_version": os_version,
        "architecture": architecture,
    }


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
