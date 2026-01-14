"""
SBOM Manipulator - modifies CPEs and PURLs to add product-specific metadata.
"""

import copy
import json
import re
from typing import Optional

from packageurl import PackageURL
from rich.console import Console

from .models import Product

console = Console()

# Patterns for debug packages to exclude
DEBUG_PACKAGE_PATTERNS = [
    "debuginfo",
    "debugsource",
]


def _is_debug_package(name: str) -> bool:
    """Check if a package name indicates it's a debug package."""
    name_lower = name.lower()
    return any(pattern in name_lower for pattern in DEBUG_PACKAGE_PATTERNS)


def _is_debug_file(path: str) -> bool:
    """Check if a file path is a debug-related file (debuginfo/debugsource RPM or in debug directory)."""
    path_lower = path.lower()
    # Check for debug patterns in the path
    if any(pattern in path_lower for pattern in DEBUG_PACKAGE_PATTERNS):
        return True
    # Check if file is under a /debug/ directory
    if "/debug/" in path_lower:
        return True
    return False


def modify_sbom(sbom: dict, product: Product, exclude_debug: bool = True) -> dict:
    """
    Modify an SBOM to add product-specific metadata.

    This function:
    - Filters out debug packages (debuginfo, debugsource) if exclude_debug is True
    - Updates CPEs to include the product information
    - Updates PURLs to include the distro qualifier
    - Adds product metadata to the SBOM descriptor

    Args:
        sbom: The original syft-json SBOM
        product: The product metadata to apply
        exclude_debug: If True, exclude debuginfo and debugsource packages (default: True)

    Returns:
        dict: Modified SBOM with product metadata
    """
    modified = copy.deepcopy(sbom)

    # Add product info to descriptor
    if "descriptor" not in modified:
        modified["descriptor"] = {}

    modified["descriptor"]["configuration"] = modified["descriptor"].get("configuration", {})
    modified["descriptor"]["configuration"]["syfter"] = {
        "product": product.full_name,
        "vendor": product.vendor,
        "cpe_prefix": product.cpe_prefix,
        "purl_qualifier": product.purl_qualifier,
    }

    # Filter and process artifacts (packages)
    artifacts = modified.get("artifacts", [])

    if exclude_debug:
        original_count = len(artifacts)
        artifacts = [a for a in artifacts if not _is_debug_package(a.get("name", ""))]
        excluded_pkg_count = original_count - len(artifacts)
        modified["artifacts"] = artifacts
        if excluded_pkg_count > 0:
            console.print(f"[dim]Excluded {excluded_pkg_count} debug packages (debuginfo/debugsource)[/dim]")

        # Also filter source files (the .rpm file entries themselves)
        files = modified.get("files", [])
        if files:
            original_file_count = len(files)
            files = [f for f in files if not _is_debug_file(f.get("location", {}).get("path", ""))]
            excluded_file_count = original_file_count - len(files)
            modified["files"] = files
            if excluded_file_count > 0:
                console.print(f"[dim]Excluded {excluded_file_count} debug source files[/dim]")

    for artifact in artifacts:
        _modify_artifact_cpes(artifact, product)
        _modify_artifact_purl(artifact, product)

    console.print(f"[green]Modified {len(artifacts)} artifacts with product metadata[/green]")

    return modified


def _modify_artifact_cpes(artifact: dict, product: Product) -> None:
    """
    Modify CPEs for an artifact to include product information.

    Args:
        artifact: The artifact dictionary to modify
        product: The product metadata
    """
    cpes = artifact.get("cpes", [])

    if not cpes:
        # Generate CPE if none exist
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        if name and version:
            # Create a product-specific CPE
            new_cpe = (
                f"cpe:2.3:a:{product.cpe_vendor}:{name}:{version}:*:*:*:*:*:*:*"
            )
            artifact["cpes"] = [new_cpe]
    else:
        # Modify existing CPEs to include vendor
        modified_cpes = []
        for cpe in cpes:
            modified_cpe = _update_cpe_vendor(cpe, product)
            modified_cpes.append(modified_cpe)

        # Also add a distribution-level CPE for traceability
        artifact["cpes"] = modified_cpes

    # Add metadata about the source product
    if "metadata" not in artifact:
        artifact["metadata"] = {}

    if isinstance(artifact["metadata"], dict):
        artifact["metadata"]["rh-product"] = product.full_name
        artifact["metadata"]["rh-cpe-prefix"] = product.cpe_prefix


def _get_cpe_string(cpe) -> str:
    """
    Extract CPE string from various formats.

    Syft may output CPEs as:
    - Plain strings: "cpe:2.3:a:vendor:product:version:..."
    - Dictionaries: {"cpe": "cpe:2.3:...", "source": "..."} or {"value": "cpe:2.3:..."}

    Args:
        cpe: CPE in string or dict format

    Returns:
        str: The CPE string
    """
    if isinstance(cpe, str):
        return cpe
    elif isinstance(cpe, dict):
        # Try common keys used by syft
        return cpe.get("cpe", cpe.get("value", cpe.get("CPE", "")))
    return ""


def _update_cpe_vendor(cpe, product: Product):
    """
    Update a CPE to use the product's vendor.

    Args:
        cpe: Original CPE (string or dict)
        product: Product metadata

    Returns:
        Modified CPE in the same format as input
    """
    # Handle dict format
    if isinstance(cpe, dict):
        cpe_str = _get_cpe_string(cpe)
        updated_str = _update_cpe_string(cpe_str, product)
        # Return modified dict with updated CPE
        result = cpe.copy()
        if "cpe" in result:
            result["cpe"] = updated_str
        elif "value" in result:
            result["value"] = updated_str
        elif "CPE" in result:
            result["CPE"] = updated_str
        else:
            # Unknown format, add cpe key
            result["cpe"] = updated_str
        return result

    # Handle string format
    return _update_cpe_string(cpe, product)


def _update_cpe_string(cpe_str: str, product: Product) -> str:
    """
    Update a CPE string to use the product's vendor.

    Args:
        cpe_str: Original CPE string
        product: Product metadata

    Returns:
        str: Modified CPE string
    """
    if not cpe_str or not cpe_str.startswith("cpe:2.3:"):
        return cpe_str

    parts = cpe_str.split(":")
    if len(parts) >= 5:
        # Update vendor (index 3)
        parts[3] = product.cpe_vendor
    return ":".join(parts)


def _modify_artifact_purl(artifact: dict, product: Product) -> None:
    """
    Modify PURL for an artifact to include distro qualifier.

    Args:
        artifact: The artifact dictionary to modify
        product: The product metadata
    """
    purl_str = artifact.get("purl", "")

    if not purl_str:
        # Generate PURL if none exists
        metadata = artifact.get("metadata", {})
        if isinstance(metadata, dict):
            # For RPMs, try to construct a proper PURL
            name = artifact.get("name", "")
            version = artifact.get("version", "")
            arch = metadata.get("arch", metadata.get("architecture", ""))

            if name and version:
                qualifiers = {
                    "distro": f"{product.name}-{product.version}",
                }
                if arch:
                    qualifiers["arch"] = arch

                # Get epoch and release if available
                epoch = metadata.get("epoch")
                release = metadata.get("release")
                if epoch:
                    qualifiers["epoch"] = str(epoch)

                # Construct version with release
                full_version = version
                if release:
                    full_version = f"{version}-{release}"

                try:
                    purl = PackageURL(
                        type="rpm",
                        namespace=product.purl_namespace,
                        name=name,
                        version=full_version,
                        qualifiers=qualifiers,
                    )
                    artifact["purl"] = str(purl)
                except Exception:
                    pass
    else:
        # Modify existing PURL to add/update distro qualifier
        try:
            purl = PackageURL.from_string(purl_str)
            qualifiers = dict(purl.qualifiers) if purl.qualifiers else {}
            qualifiers["distro"] = f"{product.name}-{product.version}"

            # Update namespace if it's generic
            namespace = purl.namespace
            if not namespace or namespace in ("*", "unknown"):
                namespace = product.purl_namespace

            new_purl = PackageURL(
                type=purl.type,
                namespace=namespace,
                name=purl.name,
                version=purl.version,
                qualifiers=qualifiers,
                subpath=purl.subpath,
            )
            artifact["purl"] = str(new_purl)
        except Exception:
            # If we can't parse, leave as-is
            pass


def extract_packages(sbom: dict, skip_files: bool = False, layer_map: Optional[dict] = None) -> list[dict]:
    """
    Extract package information from an SBOM for indexing.

    Args:
        sbom: The syft-json SBOM
        skip_files: If True, don't extract file information (saves memory for large scans)
        layer_map: Optional dict mapping layer_id -> {index, source_image} for container scans

    Returns:
        list: List of package dictionaries with extracted info
    """
    packages = []
    artifacts = sbom.get("artifacts", [])

    for artifact in artifacts:
        metadata = artifact.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        # Normalize CPEs to string list for storage
        cpes = artifact.get("cpes", [])
        cpe_strings = [_get_cpe_string(cpe) for cpe in cpes]
        cpe_strings = [c for c in cpe_strings if c]  # Filter empty

        # Extract layer info from locations (for container scans)
        layer_id = None
        layer_index = None
        source_image = None
        locations = artifact.get("locations", [])
        if locations and isinstance(locations, list):
            for loc in locations:
                if isinstance(loc, dict) and "layerID" in loc:
                    layer_id = loc.get("layerID", "")
                    # Truncate sha256: prefix if present
                    if layer_id and layer_id.startswith("sha256:"):
                        layer_id = layer_id[7:20]  # Keep first 13 chars after prefix
                    break

        # Map layer_id to source image if layer_map provided
        if layer_id and layer_map and layer_id in layer_map:
            layer_info = layer_map[layer_id]
            layer_index = layer_info.get("index")
            source_image = layer_info.get("source_image")

        pkg = {
            "name": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "release": metadata.get("release", ""),
            "arch": metadata.get("arch", metadata.get("architecture", "")),
            "epoch": str(metadata.get("epoch") or ""),
            "source_rpm": metadata.get("sourceRpm", metadata.get("source_rpm", "")),
            "license": _extract_license(artifact),
            "purl": artifact.get("purl", ""),
            "cpes": json.dumps(cpe_strings),
            "files": [] if skip_files else _extract_files(artifact),
            "layer_id": layer_id,
            "layer_index": layer_index,
            "source_image": source_image,
        }
        packages.append(pkg)

    return packages


def extract_image_layers(sbom: dict) -> list[dict]:
    """
    Extract image layer information from a container SBOM.

    Args:
        sbom: The syft-json SBOM

    Returns:
        list: List of layer dicts with {layer_id, index, digest, size}
              Empty list if not a container scan
    """
    layers = []
    source = sbom.get("source", {})

    if source.get("type") != "image":
        return layers

    metadata = source.get("metadata", {})
    source_layers = metadata.get("layers", [])

    for index, layer in enumerate(source_layers):
        digest = layer.get("digest", "")
        # Truncate sha256: prefix for storage
        layer_id = digest[7:20] if digest.startswith("sha256:") else digest[:13]

        layers.append({
            "layer_id": layer_id,
            "full_digest": digest,
            "index": index,
            "size": layer.get("size", 0),
            "media_type": layer.get("mediaType", ""),
            "source_image": None,  # To be filled in by layer mapping
        })

    return layers


def build_layer_map(layers: list[dict]) -> dict:
    """
    Build a lookup map from layer_id to layer info.

    Args:
        layers: List from extract_image_layers()

    Returns:
        dict: {layer_id: {index, source_image, ...}}
    """
    return {layer["layer_id"]: layer for layer in layers}


def _extract_license(artifact: dict) -> str:
    """Extract license information from an artifact."""
    licenses = artifact.get("licenses", [])
    if not licenses:
        return ""

    # Handle both string and structured license formats
    license_strs = []
    for lic in licenses:
        if isinstance(lic, str):
            license_strs.append(lic)
        elif isinstance(lic, dict):
            # Syft uses "value" for the license string
            license_strs.append(lic.get("value", lic.get("name", str(lic))))

    return " AND ".join(license_strs) if license_strs else ""


def _extract_files(artifact: dict) -> list[dict]:
    """Extract file information from an artifact."""
    files = []
    metadata = artifact.get("metadata", {})

    if not isinstance(metadata, dict):
        return files

    # RPM packages may have files in metadata
    rpm_files = metadata.get("files") or []  # Handle None case
    if not isinstance(rpm_files, list):
        return files

    for f in rpm_files:
        if isinstance(f, dict):
            digest_info = f.get("digest")
            if isinstance(digest_info, dict):
                digest_value = digest_info.get("value", "")
                digest_algo = digest_info.get("algorithm", "sha256")
            else:
                digest_value = ""
                digest_algo = ""

            files.append({
                "path": f.get("path", ""),
                "digest": digest_value,
                "digest_algorithm": digest_algo,
            })
        elif isinstance(f, str):
            files.append({"path": f, "digest": "", "digest_algorithm": ""})

    return files


def get_product_from_purl(purl_str: str) -> Optional[tuple[str, str]]:
    """
    Extract product information from a PURL's distro qualifier.

    Args:
        purl_str: PURL string

    Returns:
        tuple: (product_name, version) or None if not found
    """
    try:
        purl = PackageURL.from_string(purl_str)
        distro = purl.qualifiers.get("distro", "") if purl.qualifiers else ""
        if distro:
            # Parse distro like "rhel-10.0"
            match = re.match(r"([a-zA-Z0-9_-]+)-(\d+\.?\d*)", distro)
            if match:
                return match.group(1), match.group(2)
    except Exception:
        pass
    return None


def parse_containerfile(path: str) -> list[str]:
    """
    Parse a Containerfile/Dockerfile to extract the FROM chain.

    Handles multi-stage builds by returning all FROM images in order.

    Args:
        path: Path to Containerfile/Dockerfile

    Returns:
        list: List of image references from FROM statements (oldest first)
    """
    from pathlib import Path

    images = []
    try:
        content = Path(path).read_text()
        # Match FROM statements (handles ARG substitution as-is)
        # Pattern: FROM [--platform=...] image[:tag] [AS name]
        from_pattern = re.compile(
            r'^FROM\s+(?:--platform=\S+\s+)?(\S+?)(?:\s+AS\s+\S+)?\s*$',
            re.MULTILINE | re.IGNORECASE
        )

        for match in from_pattern.finditer(content):
            image = match.group(1)
            # Skip ARG variables (start with $)
            if not image.startswith("$"):
                images.append(image)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not parse Containerfile: {e}[/yellow]")

    return images


def map_layers_to_images(
    final_layers: list[dict],
    base_image_layers: dict[str, list[dict]],
) -> dict:
    """
    Map layer IDs to their source images by comparing layer lists.

    Args:
        final_layers: Layers from the scanned image (from extract_image_layers)
        base_image_layers: Dict of {image_ref: layers_list} for each base image

    Returns:
        dict: Updated layer map with source_image filled in
    """
    layer_map = {}

    # Build a set of layer IDs for each base image
    image_layer_sets = {}
    for image_ref, layers in base_image_layers.items():
        image_layer_sets[image_ref] = set(layer["layer_id"] for layer in layers)

    # For each layer in the final image, find which base image it came from
    # Process images from most derived to base (reverse order of FROM chain)
    # A layer belongs to the most derived image that contains it

    for layer in final_layers:
        layer_id = layer["layer_id"]
        layer_info = layer.copy()

        # Find the most specific image that has this layer
        # (The image that is closest to the final image in the chain)
        for image_ref in reversed(list(base_image_layers.keys())):
            if layer_id in image_layer_sets[image_ref]:
                layer_info["source_image"] = image_ref
                break

        layer_map[layer_id] = layer_info

    return layer_map
