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


def modify_sbom(sbom: dict, product: Product) -> dict:
    """
    Modify an SBOM to add product-specific metadata.

    This function:
    - Updates CPEs to include the product information
    - Updates PURLs to include the distro qualifier
    - Adds product metadata to the SBOM descriptor

    Args:
        sbom: The original syft-json SBOM
        product: The product metadata to apply

    Returns:
        dict: Modified SBOM with product metadata
    """
    modified = copy.deepcopy(sbom)

    # Add product info to descriptor
    if "descriptor" not in modified:
        modified["descriptor"] = {}

    modified["descriptor"]["configuration"] = modified["descriptor"].get("configuration", {})
    modified["descriptor"]["configuration"]["rh-syfter"] = {
        "product": product.full_name,
        "vendor": product.vendor,
        "cpe_prefix": product.cpe_prefix,
        "purl_qualifier": product.purl_qualifier,
    }

    # Process artifacts (packages)
    artifacts = modified.get("artifacts", [])
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


def extract_packages(sbom: dict) -> list[dict]:
    """
    Extract package information from an SBOM for indexing.

    Args:
        sbom: The syft-json SBOM

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

        pkg = {
            "name": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "release": metadata.get("release", ""),
            "arch": metadata.get("arch", metadata.get("architecture", "")),
            "epoch": str(metadata.get("epoch", "")),
            "source_rpm": metadata.get("sourceRpm", metadata.get("source_rpm", "")),
            "license": _extract_license(artifact),
            "purl": artifact.get("purl", ""),
            "cpes": json.dumps(cpe_strings),
            "files": _extract_files(artifact),
        }
        packages.append(pkg)

    return packages


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
