"""
CLI interface for RH-Syfter.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from . import __version__
from .models import Product
from .scanner import (
    scan_directory,
    scan_container,
    scan_target,
    get_source_type,
    check_syft_installed,
    SyftNotFoundError,
    ScanError,
)
from .manipulator import modify_sbom, extract_packages
from .storage import Storage, DEFAULT_DB_PATH
from .exporter import (
    export_to_spdx_json,
    export_to_spdx_tv,
    export_to_cyclonedx_json,
    export_to_cyclonedx_xml,
    batch_export,
    ExportError,
)

console = Console()


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--db",
    "db_path",
    type=click.Path(path_type=Path),
    default=None,
    envvar="SYFTER_DB",
    help="Path to database file (default: ~/.rh-syfter/syfter.db)",
)
@click.pass_context
def main(ctx, db_path: Optional[Path]):
    """
    RH-Syfter: SBOM generation and management for Red Hat products.

    Scan RPM directories, containers, and other artifacts to generate SBOMs,
    enrich them with product metadata, and query across all your products.
    """
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db_path


@main.command()
@click.argument("target", type=str)
@click.option(
    "-p", "--product",
    required=True,
    help="Product name (e.g., 'rhel')",
)
@click.option(
    "-v", "--version",
    "product_version",
    required=True,
    help="Product version (e.g., '10.0')",
)
@click.option(
    "--vendor",
    default="Red Hat",
    help="Vendor name (default: 'Red Hat')",
)
@click.option(
    "--cpe-vendor",
    default="redhat",
    help="CPE vendor string (default: 'redhat')",
)
@click.option(
    "--purl-namespace",
    default="redhat",
    help="PURL namespace (default: 'redhat')",
)
@click.option(
    "--description",
    default="",
    help="Product description",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    help="Write modified SBOM to file (in addition to storing)",
)
@click.option(
    "--original-output",
    type=click.Path(path_type=Path),
    help="Write original (unmodified) SBOM to file",
)
@click.option(
    "--no-store",
    is_flag=True,
    help="Don't store in database (just output)",
)
@click.option(
    "-s", "--source",
    type=click.Choice(["auto", "podman", "docker", "registry", "skopeo"]),
    default="auto",
    help="Container image source (default: auto-detect). Use 'podman' to pull via podman, "
         "'registry' for direct OCI registry pull, 'docker' for docker daemon, "
         "'skopeo' to pull via skopeo (most reliable for authenticated registries).",
)
@click.option(
    "--pull-first",
    is_flag=True,
    help="Pull image with skopeo to local OCI directory before scanning. "
         "Most reliable method for authenticated registries like registry.redhat.io.",
)
@click.option(
    "--arch",
    type=click.Choice(["amd64", "arm64", "ppc64le", "s390x"]),
    default=None,
    help="Architecture to pull for container images (default: amd64). "
         "Use when pulling multi-arch images with skopeo.",
)
@click.pass_context
def scan(
    ctx,
    target: str,
    product: str,
    product_version: str,
    vendor: str,
    cpe_vendor: str,
    purl_namespace: str,
    description: str,
    output: Optional[Path],
    original_output: Optional[Path],
    no_store: bool,
    source: str,
    pull_first: bool,
    arch: Optional[str],
):
    """
    Scan a target and store the SBOM with product metadata.

    TARGET can be:
    - A directory path (e.g., /path/to/rpms)
    - A container image (e.g., registry.redhat.io/rhel9:latest)
    - A prefixed path (e.g., dir:/path, podman:image:tag)

    Examples:

        rh-syfter scan /path/to/rpms -p rhel -v 10.0

        rh-syfter scan registry.redhat.io/rhel9:latest -p rhel -v 9.0

        rh-syfter scan registry.redhat.io/ubi9:latest -p ubi -v 9.0 --source podman

        rh-syfter scan ./packages -p openshift -v 4.14 --description "OCP 4.14"
    """
    try:
        check_syft_installed()
    except SyftNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Create product
    prod = Product(
        name=product,
        version=product_version,
        vendor=vendor,
        cpe_vendor=cpe_vendor,
        purl_namespace=purl_namespace,
        description=description,
    )

    console.print(Panel(
        f"[bold]Scanning:[/bold] {target}\n"
        f"[bold]Product:[/bold] {prod.full_name}\n"
        f"[bold]CPE Prefix:[/bold] {prod.cpe_prefix}\n"
        f"[bold]PURL Qualifier:[/bold] {prod.purl_qualifier}",
        title="RH-Syfter Scan",
        box=box.ROUNDED,
    ))

    # Determine source type and scan
    source_type = get_source_type(target)
    console.print(f"[dim]Source type: {source_type}[/dim]")

    try:
        if source_type == "directory":
            path = Path(target.replace("dir:", ""))
            original_sbom, syft_version = scan_directory(path)
        elif source_type == "container":
            # Pass source if not auto, otherwise let scan_container auto-detect
            container_source = None if source == "auto" else source
            original_sbom, syft_version = scan_container(
                target, source=container_source, pull_first=pull_first, arch=arch
            )
        else:
            original_sbom, syft_version = scan_target(target)
    except ScanError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)

    # Save original if requested
    if original_output:
        original_output.write_text(json.dumps(original_sbom, indent=2))
        console.print(f"[green]Wrote original SBOM to {original_output}[/green]")

    # Modify SBOM with product metadata
    modified_sbom = modify_sbom(original_sbom, prod)

    # Extract packages for indexing
    packages = extract_packages(modified_sbom)

    # Save modified SBOM if requested
    if output:
        output.write_text(json.dumps(modified_sbom, indent=2))
        console.print(f"[green]Wrote modified SBOM to {output}[/green]")

    # Store in database
    if not no_store:
        storage = Storage(ctx.obj.get("db_path"))
        product_id = storage.get_or_create_product(prod)
        scan_id = storage.store_scan(
            product_id=product_id,
            source_path=target,
            source_type=source_type,
            syft_version=syft_version,
            original_sbom=original_sbom,
            modified_sbom=modified_sbom,
            packages=packages,
        )
        console.print(f"[green]✓ Scan #{scan_id} stored successfully[/green]")
    else:
        console.print("[yellow]Skipped database storage (--no-store)[/yellow]")


@main.command("query")
@click.option(
    "-n", "--name",
    help="Package name pattern (use % as wildcard)",
)
@click.option(
    "-f", "--file",
    "file_path",
    help="File path pattern (use % as wildcard)",
)
@click.option(
    "-d", "--digest",
    help="File digest (exact match)",
)
@click.option(
    "-p", "--product",
    help="Filter by product name",
)
@click.option(
    "-v", "--version",
    "product_version",
    help="Filter by product version",
)
@click.option(
    "--limit",
    type=int,
    default=50,
    help="Maximum results (default: 50)",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output as JSON",
)
@click.pass_context
def query(
    ctx,
    name: Optional[str],
    file_path: Optional[str],
    digest: Optional[str],
    product: Optional[str],
    product_version: Optional[str],
    limit: int,
    output_json: bool,
):
    """
    Query packages and files across all products.

    Examples:

        rh-syfter query -n "kernel%"

        rh-syfter query -f "%/bin/bash"

        rh-syfter query -n "openssl%" -p rhel -v 10.0

        rh-syfter query -d "sha256:abc123..."
    """
    storage = Storage(ctx.obj.get("db_path"))

    if file_path or digest:
        # Search files
        results = storage.search_files(
            path_pattern=file_path,
            digest=digest,
            product_name=product,
            product_version=product_version,
            limit=limit,
        )

        if output_json:
            click.echo(json.dumps(results, indent=2))
            return

        if not results:
            console.print("[yellow]No files found matching criteria[/yellow]")
            return

        table = Table(title="File Search Results", box=box.SIMPLE)
        table.add_column("Path", style="cyan")
        table.add_column("Package", style="green")
        table.add_column("Product", style="magenta")
        table.add_column("Digest", style="dim", max_width=20)

        for row in results:
            table.add_row(
                row["path"],
                f"{row['package_name']}-{row['package_version']}",
                f"{row['product_name']}-{row['product_version']}",
                (row["digest"][:20] + "...") if row["digest"] else "",
            )

        console.print(table)

    elif name:
        # Search packages
        results = storage.search_packages(
            name_pattern=name,
            product_name=product,
            product_version=product_version,
            limit=limit,
        )

        if output_json:
            click.echo(json.dumps(results, indent=2))
            return

        if not results:
            console.print("[yellow]No packages found matching criteria[/yellow]")
            return

        table = Table(title="Package Search Results", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Arch", style="yellow")
        table.add_column("Product", style="magenta")
        table.add_column("PURL", style="dim", max_width=40)

        for row in results:
            version = row["version"]
            if row["release"]:
                version = f"{version}-{row['release']}"

            table.add_row(
                row["name"],
                version,
                row["arch"] or "",
                f"{row['product_name']}-{row['product_version']}",
                (row["purl"][:40] + "...") if len(row["purl"]) > 40 else row["purl"],
            )

        console.print(table)

    else:
        console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")
        sys.exit(1)


@main.command("export")
@click.option(
    "-p", "--product",
    required=True,
    help="Product name",
)
@click.option(
    "-v", "--version",
    "product_version",
    required=True,
    help="Product version",
)
@click.option(
    "-f", "--format",
    "output_format",
    type=click.Choice(["syft-json", "spdx-json", "spdx-tv", "cyclonedx-json", "cyclonedx-xml", "all"]),
    default="spdx-json",
    help="Output format (default: spdx-json)",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    help="Output file or directory (for 'all' format)",
)
@click.pass_context
def export_cmd(
    ctx,
    product: str,
    product_version: str,
    output_format: str,
    output: Optional[Path],
):
    """
    Export a product's SBOM to various formats.

    Examples:

        rh-syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.spdx.json

        rh-syfter export -p rhel -v 10.0 -f all -o ./sboms/

        rh-syfter export -p openshift -v 4.14 -f cyclonedx-json
    """
    storage = Storage(ctx.obj.get("db_path"))

    # Get the SBOM
    sbom = storage.get_product_sbom(product, product_version)
    if not sbom:
        console.print(f"[red]No SBOM found for {product}-{product_version}[/red]")
        sys.exit(1)

    if output_format == "syft-json":
        # Just output the stored syft-json
        output_str = json.dumps(sbom, indent=2)
        if output:
            output.write_text(output_str)
            console.print(f"[green]Wrote syft-json to {output}[/green]")
        else:
            click.echo(output_str)
        return

    if output_format == "all":
        # Export to all formats
        if not output:
            output = Path(".")
        output.mkdir(parents=True, exist_ok=True)

        base_name = f"{product}-{product_version}"
        results = batch_export(sbom, output, base_name)

        console.print(f"[green]Exported to {len(results)} formats:[/green]")
        for fmt, path in results.items():
            console.print(f"  - {fmt}: {path}")
        return

    # Export to specific format
    try:
        format_map = {
            "spdx-json": export_to_spdx_json,
            "spdx-tv": export_to_spdx_tv,
            "cyclonedx-json": export_to_cyclonedx_json,
            "cyclonedx-xml": export_to_cyclonedx_xml,
        }

        export_func = format_map[output_format]
        result = export_func(sbom, output)

        if not output:
            click.echo(result)

    except ExportError as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


@main.command("products")
@click.pass_context
def list_products(ctx):
    """List all products in the database."""
    storage = Storage(ctx.obj.get("db_path"))
    products = storage.list_products()

    if not products:
        console.print("[yellow]No products found. Run 'rh-syfter scan' to add one.[/yellow]")
        return

    table = Table(title="Products", box=box.SIMPLE)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Vendor", style="yellow")
    table.add_column("Scans", justify="right")
    table.add_column("Packages", justify="right")

    for p in products:
        table.add_row(
            p["name"],
            p["version"],
            p["vendor"],
            str(p["scan_count"] or 0),
            str(p["total_packages"] or 0),
        )

    console.print(table)


@main.command("scans")
@click.option(
    "-p", "--product",
    help="Filter by product name",
)
@click.pass_context
def list_scans(ctx, product: Optional[str]):
    """List all scans in the database."""
    storage = Storage(ctx.obj.get("db_path"))
    scans = storage.list_scans(product_name=product)

    if not scans:
        console.print("[yellow]No scans found.[/yellow]")
        return

    table = Table(title="Scans", box=box.SIMPLE)
    table.add_column("ID", justify="right")
    table.add_column("Product", style="cyan")
    table.add_column("Source", style="green", max_width=40)
    table.add_column("Type", style="yellow")
    table.add_column("Packages", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Timestamp")

    for s in scans:
        source = s["source_path"]
        if len(source) > 40:
            source = "..." + source[-37:]

        table.add_row(
            str(s["id"]),
            f"{s['product_name']}-{s['product_version']}",
            source,
            s["source_type"],
            str(s["package_count"]),
            str(s["file_count"]),
            s["scan_timestamp"][:19] if s["scan_timestamp"] else "",
        )

    console.print(table)


@main.command("stats")
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    storage = Storage(ctx.obj.get("db_path"))
    s = storage.get_stats()

    console.print(Panel(
        f"[bold]Database:[/bold] {s['database_path']}\n"
        f"[bold]Products:[/bold] {s['products']}\n"
        f"[bold]Scans:[/bold] {s['scans']}\n"
        f"[bold]Packages:[/bold] {s['packages']}\n"
        f"[bold]Files:[/bold] {s['files']}",
        title="Database Statistics",
        box=box.ROUNDED,
    ))


@main.command("delete-scan")
@click.argument("scan_id", type=int)
@click.option(
    "--yes",
    is_flag=True,
    help="Skip confirmation",
)
@click.pass_context
def delete_scan(ctx, scan_id: int, yes: bool):
    """Delete a scan by ID."""
    storage = Storage(ctx.obj.get("db_path"))

    if not yes:
        if not click.confirm(f"Delete scan #{scan_id}?"):
            console.print("[yellow]Cancelled[/yellow]")
            return

    if storage.delete_scan(scan_id):
        console.print(f"[green]Deleted scan #{scan_id}[/green]")
    else:
        console.print(f"[red]Scan #{scan_id} not found[/red]")


@main.command("check")
def check():
    """Check if syft is installed and show version."""
    try:
        version = check_syft_installed()
        console.print(f"[green]✓ Syft is installed (version {version})[/green]")
    except SyftNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
