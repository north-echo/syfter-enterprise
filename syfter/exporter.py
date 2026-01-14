"""
Exporter module - converts syft-json to SPDX and CycloneDX formats.

Uses syft's built-in conversion capabilities for accurate format conversion.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Literal, Optional

from rich.console import Console

from .scanner import check_syft_installed, SyftNotFoundError

console = Console()

OutputFormat = Literal[
    "spdx-json",
    "spdx-tag-value",
    "cyclonedx-json",
    "cyclonedx-xml",
]


class ExportError(Exception):
    """Raised when export fails."""

    pass


def export_sbom(
    sbom: dict,
    output_format: OutputFormat,
    output_path: Optional[Path] = None,
) -> str:
    """
    Export a syft-json SBOM to another format.

    Uses syft's native conversion by piping the JSON through syft convert.

    Args:
        sbom: The syft-json SBOM dictionary
        output_format: Target format (spdx-json, spdx-tag-value, cyclonedx-json, cyclonedx-xml)
        output_path: Optional path to write output (returns string if not provided)

    Returns:
        str: The converted SBOM as a string

    Raises:
        ExportError: If conversion fails
        SyftNotFoundError: If syft is not installed
    """
    check_syft_installed()

    # Write SBOM to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp_input:
        json.dump(sbom, tmp_input)
        tmp_input_path = tmp_input.name

    try:
        # Use syft convert command
        cmd = ["syft", "convert", tmp_input_path, "-o", output_format]

        console.print(f"[dim]Converting to {output_format}...[/dim]")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for conversion
            )
        except subprocess.TimeoutExpired:
            raise ExportError(f"SBOM conversion to {output_format} timed out after 5 minutes")

        if result.returncode != 0:
            raise ExportError(f"Syft convert failed: {result.stderr}")

        output = result.stdout

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output)

        return output

    finally:
        # Clean up temp file
        Path(tmp_input_path).unlink(missing_ok=True)


def export_to_spdx_json(sbom: dict, output_path: Optional[Path] = None) -> str:
    """
    Export to SPDX JSON format.

    Args:
        sbom: The syft-json SBOM
        output_path: Optional output file path

    Returns:
        str: SPDX JSON string
    """
    return export_sbom(sbom, "spdx-json", output_path)


def export_to_spdx_tv(sbom: dict, output_path: Optional[Path] = None) -> str:
    """
    Export to SPDX Tag-Value format.

    Args:
        sbom: The syft-json SBOM
        output_path: Optional output file path

    Returns:
        str: SPDX Tag-Value string
    """
    return export_sbom(sbom, "spdx-tag-value", output_path)


def export_to_cyclonedx_json(sbom: dict, output_path: Optional[Path] = None) -> str:
    """
    Export to CycloneDX JSON format.

    Args:
        sbom: The syft-json SBOM
        output_path: Optional output file path

    Returns:
        str: CycloneDX JSON string
    """
    return export_sbom(sbom, "cyclonedx-json", output_path)


def export_to_cyclonedx_xml(sbom: dict, output_path: Optional[Path] = None) -> str:
    """
    Export to CycloneDX XML format.

    Args:
        sbom: The syft-json SBOM
        output_path: Optional output file path

    Returns:
        str: CycloneDX XML string
    """
    return export_sbom(sbom, "cyclonedx-xml", output_path)


def batch_export(
    sbom: dict,
    output_dir: Path,
    base_name: str,
    formats: Optional[list[OutputFormat]] = None,
) -> dict[str, Path]:
    """
    Export an SBOM to multiple formats at once.

    Args:
        sbom: The syft-json SBOM
        output_dir: Directory to write output files
        base_name: Base filename (without extension)
        formats: List of formats to export (defaults to all)

    Returns:
        dict: Mapping of format to output file path
    """
    if formats is None:
        formats = ["spdx-json", "spdx-tag-value", "cyclonedx-json", "cyclonedx-xml"]

    output_dir.mkdir(parents=True, exist_ok=True)

    format_extensions = {
        "spdx-json": ".spdx.json",
        "spdx-tag-value": ".spdx",
        "cyclonedx-json": ".cdx.json",
        "cyclonedx-xml": ".cdx.xml",
    }

    results = {}
    for fmt in formats:
        ext = format_extensions.get(fmt, f".{fmt}")
        output_path = output_dir / f"{base_name}{ext}"
        try:
            export_sbom(sbom, fmt, output_path)
            results[fmt] = output_path
        except ExportError as e:
            console.print(f"[red]Failed to export {fmt}: {e}[/red]")

    return results
