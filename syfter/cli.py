"""
CLI interface for RH-Syfter.

Supports two modes:
- Server mode: Uses API server (set SYFTER_SERVER env var)
- Local mode: Direct SQLite access (for development/testing)
"""

import gzip
import json
import os
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
from .exporter import (
    export_to_spdx_json,
    export_to_spdx_tv,
    export_to_cyclonedx_json,
    export_to_cyclonedx_xml,
    batch_export,
    ExportError,
)

console = Console()


def get_server_url() -> Optional[str]:
    """Get the server URL from environment or None for local mode."""
    return os.getenv("SYFTER_SERVER")


def is_server_mode() -> bool:
    """Check if running in server mode."""
    return get_server_url() is not None


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--server",
    "server_url",
    envvar="SYFTER_SERVER",
    help="API server URL (default: local mode)",
)
@click.option(
    "--local",
    "force_local",
    is_flag=True,
    help="Force local mode even if SYFTER_SERVER is set",
)
@click.pass_context
def main(ctx, server_url: Optional[str], force_local: bool):
    """
    RH-Syfter: SBOM generation and management for Red Hat products.

    Scan RPM directories, containers, and other artifacts to generate SBOMs,
    enrich them with product metadata, and query across all your products.

    Modes:
      - Server mode: Set SYFTER_SERVER=http://server:8000 or use --server
      - Local mode: Uses local SQLite database (default, or use --local)
    """
    ctx.ensure_object(dict)
    ctx.obj["server_url"] = None if force_local else server_url
    ctx.obj["local_mode"] = force_local or server_url is None


@main.command()
@click.argument("target", type=str)
@click.option("-p", "--product", required=True, help="Product name (e.g., 'rhel')")
@click.option("-v", "--version", "product_version", required=True, help="Product version (e.g., '10.0')")
@click.option("--vendor", default="Red Hat", help="Vendor name")
@click.option("--cpe-vendor", default="redhat", help="CPE vendor string")
@click.option("--purl-namespace", default="redhat", help="PURL namespace")
@click.option("--description", default="", help="Product description")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Write SBOM to file")
@click.option("--no-store", is_flag=True, help="Don't store (just output)")
@click.option("-s", "--source", type=click.Choice(["auto", "podman", "docker", "registry", "skopeo"]), default="auto")
@click.option("--pull-first", is_flag=True, help="Pull image with skopeo first")
@click.option("--arch", type=click.Choice(["amd64", "arm64", "ppc64le", "s390x"]), default=None)
@click.option("-q", "--quiet", is_flag=True, help="Suppress progress output")
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
    no_store: bool,
    source: str,
    pull_first: bool,
    arch: Optional[str],
    quiet: bool,
):
    """Scan a target and store the SBOM with product metadata."""
    try:
        check_syft_installed()
    except SyftNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

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
        f"[bold]Mode:[/bold] {'Server' if not ctx.obj['local_mode'] else 'Local'}",
        title="RH-Syfter Scan",
        box=box.ROUNDED,
    ))

    source_type = get_source_type(target)
    console.print(f"[dim]Source type: {source_type}[/dim]")

    try:
        if source_type == "directory":
            path = Path(target.replace("dir:", ""))
            original_sbom, syft_version = scan_directory(
                path, show_progress=not quiet, name=prod.full_name, version=product_version
            )
        elif source_type == "container":
            container_source = None if source == "auto" else source
            original_sbom, syft_version = scan_container(
                target, source=container_source, pull_first=pull_first,
                arch=arch, show_progress=not quiet, name=prod.full_name, version=product_version
            )
        else:
            original_sbom, syft_version = scan_target(
                target, show_progress=not quiet, name=prod.full_name, version=product_version
            )
    except ScanError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        sys.exit(1)

    modified_sbom = modify_sbom(original_sbom, prod)
    packages = extract_packages(modified_sbom)

    if output:
        output.write_text(json.dumps(modified_sbom, indent=2))
        console.print(f"[green]Wrote SBOM to {output}[/green]")

    if no_store:
        console.print("[yellow]Skipped storage (--no-store)[/yellow]")
        return

    if ctx.obj["local_mode"]:
        _store_local(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages)
    else:
        _store_server(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages)


def _store_local(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages):
    """Store scan using local SQLite storage."""
    from .storage import Storage

    storage = Storage()
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
    console.print(f"[green]✓ Scan #{scan_id} stored locally[/green]")


def _store_server(ctx, prod, target, source_type, syft_version, original_sbom, modified_sbom, packages):
    """Store scan using API server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            result = client.upload_scan(
                product_name=prod.name,
                product_version=prod.version,
                source_path=target,
                source_type=source_type,
                syft_version=syft_version,
                original_sbom=original_sbom,
                modified_sbom=modified_sbom,
                packages=packages,
            )
            console.print(f"[green]✓ Scan #{result['id']} uploaded to server[/green]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Upload failed: {e}[/red]")
        sys.exit(1)


@main.command("query")
@click.option("-n", "--name", help="Package name pattern (use %% as wildcard)")
@click.option("-f", "--file", "file_path", help="File path pattern")
@click.option("-d", "--digest", help="File digest (exact match)")
@click.option("-p", "--product", help="Filter by product name")
@click.option("-v", "--version", "product_version", help="Filter by product version")
@click.option("--limit", type=int, default=50, help="Maximum results")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.pass_context
def query(ctx, name, file_path, digest, product, product_version, limit, output_json):
    """Query packages and files across all products."""
    if ctx.obj["local_mode"]:
        _query_local(name, file_path, digest, product, product_version, limit, output_json)
    else:
        _query_server(ctx, name, file_path, digest, product, product_version, limit, output_json)


def _query_local(name, file_path, digest, product, product_version, limit, output_json):
    """Query using local SQLite storage."""
    from .storage import Storage

    storage = Storage()

    if file_path or digest:
        results = storage.search_files(
            path_pattern=file_path, digest=digest,
            product_name=product, product_version=product_version, limit=limit
        )
        if output_json:
            click.echo(json.dumps(results, indent=2))
            return
        if not results:
            console.print("[yellow]No files found[/yellow]")
            return
        table = Table(title="File Search Results", box=box.SIMPLE)
        table.add_column("Path", style="cyan")
        table.add_column("Package", style="green")
        table.add_column("Product", style="magenta")
        for row in results:
            table.add_row(row["path"], f"{row['package_name']}", f"{row['product_name']}-{row['product_version']}")
        console.print(table)

    elif name:
        results = storage.search_packages(
            name_pattern=name, product_name=product, product_version=product_version, limit=limit
        )
        if output_json:
            click.echo(json.dumps(results, indent=2))
            return
        if not results:
            console.print("[yellow]No packages found[/yellow]")
            return
        table = Table(title="Package Search Results", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Product", style="magenta")
        for row in results:
            table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}")
        console.print(table)
    else:
        console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")


def _query_server(ctx, name, file_path, digest, product, product_version, limit, output_json):
    """Query using API server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            if file_path or digest:
                results = client.search_files(
                    path=file_path, digest=digest,
                    product_name=product, product_version=product_version, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No files found[/yellow]")
                    return
                table = Table(title="File Search Results", box=box.SIMPLE)
                table.add_column("Path", style="cyan")
                table.add_column("Package", style="green")
                table.add_column("Product", style="magenta")
                for row in results:
                    table.add_row(row["path"], row["package_name"], f"{row['product_name']}-{row['product_version']}")
                console.print(table)

            elif name:
                results = client.search_packages(
                    name=name, product_name=product, product_version=product_version, limit=limit
                )
                if output_json:
                    click.echo(json.dumps(results, indent=2))
                    return
                if not results:
                    console.print("[yellow]No packages found[/yellow]")
                    return
                table = Table(title="Package Search Results", box=box.SIMPLE)
                table.add_column("Name", style="cyan")
                table.add_column("Version", style="green")
                table.add_column("Product", style="magenta")
                for row in results:
                    table.add_row(row["name"], row["version"] or "", f"{row['product_name']}-{row['product_version']}")
                console.print(table)
            else:
                console.print("[yellow]Please specify --name, --file, or --digest[/yellow]")
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command("export")
@click.option("-p", "--product", required=True, help="Product name")
@click.option("-v", "--version", "product_version", required=True, help="Product version")
@click.option("-f", "--format", "output_format", 
              type=click.Choice(["syft-json", "spdx-json", "spdx-tv", "cyclonedx-json", "cyclonedx-xml", "all"]),
              default="spdx-json", help="Output format")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file or directory")
@click.pass_context
def export_cmd(ctx, product, product_version, output_format, output):
    """Export a product's SBOM to various formats."""
    if ctx.obj["local_mode"]:
        _export_local(product, product_version, output_format, output)
    else:
        _export_server(ctx, product, product_version, output_format, output)


def _export_local(product, product_version, output_format, output):
    """Export using local storage."""
    from .storage import Storage

    storage = Storage()
    sbom = storage.get_product_sbom(product, product_version)
    if not sbom:
        console.print(f"[red]No SBOM found for {product}-{product_version}[/red]")
        sys.exit(1)

    _do_export(sbom, product, product_version, output_format, output)


def _export_server(ctx, product, product_version, output_format, output):
    """Export using API server."""
    from .client import SyfterClient, APIError
    import httpx

    server_url = ctx.obj["server_url"]
    try:
        with SyfterClient(server_url) as client:
            data = client.get_sbom(product, product_version)
            sbom = json.loads(gzip.decompress(data).decode("utf-8"))
            _do_export(sbom, product, product_version, output_format, output)
    except httpx.ConnectError:
        console.print(f"[red]Error: Cannot connect to server at {server_url}[/red]")
        console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(server_url))
        sys.exit(1)
    except APIError as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


def _do_export(sbom, product, product_version, output_format, output):
    """Perform the actual export."""
    if output_format == "syft-json":
        output_str = json.dumps(sbom, indent=2)
        if output:
            output.write_text(output_str)
            console.print(f"[green]Wrote syft-json to {output}[/green]")
        else:
            click.echo(output_str)
        return

    if output_format == "all":
        if not output:
            output = Path(".")
        output.mkdir(parents=True, exist_ok=True)
        base_name = f"{product}-{product_version}"
        results = batch_export(sbom, output, base_name)
        console.print(f"[green]Exported to {len(results)} formats[/green]")
        return

    format_map = {
        "spdx-json": export_to_spdx_json,
        "spdx-tv": export_to_spdx_tv,
        "cyclonedx-json": export_to_cyclonedx_json,
        "cyclonedx-xml": export_to_cyclonedx_xml,
    }

    try:
        result = format_map[output_format](sbom, output)
        if not output:
            click.echo(result)
    except ExportError as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


@main.command("products")
@click.pass_context
def list_products(ctx):
    """List all products in the database."""
    if ctx.obj["local_mode"]:
        from .storage import Storage
        storage = Storage()
        products = storage.list_products()
    else:
        import httpx
        from .client import SyfterClient
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                products = client.list_products()
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(ctx.obj['server_url']))
            sys.exit(1)

    if not products:
        console.print("[yellow]No products found[/yellow]")
        return

    table = Table(title="Products", box=box.SIMPLE)
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Scans", justify="right")
    table.add_column("Packages", justify="right")

    for p in products:
        table.add_row(
            p["name"] if isinstance(p, dict) else p.name,
            p["version"] if isinstance(p, dict) else p.version,
            str(p.get("scan_count", 0) if isinstance(p, dict) else getattr(p, "scan_count", 0)),
            str(p.get("total_packages", 0) if isinstance(p, dict) else getattr(p, "total_packages", 0)),
        )
    console.print(table)


@main.command("stats")
@click.pass_context
def stats(ctx):
    """Show database statistics."""
    if ctx.obj["local_mode"]:
        from .storage import Storage
        storage = Storage()
        s = storage.get_stats()
        storage_type = "local"
        db_type = "sqlite"
    else:
        import httpx
        from .client import SyfterClient
        try:
            with SyfterClient(ctx.obj["server_url"]) as client:
                s = client.get_stats()
                storage_type = s.get("storage_type", "unknown")
                db_type = s.get("database_type", "unknown")
        except httpx.ConnectError:
            console.print(f"[red]Error: Cannot connect to server at {ctx.obj['server_url']}[/red]")
            console.print("[dim]Is the server running? Check with: curl {}/health[/dim]".format(ctx.obj['server_url']))
            sys.exit(1)

    console.print(Panel(
        f"[bold]Mode:[/bold] {'Server' if not ctx.obj['local_mode'] else 'Local'}\n"
        f"[bold]Database:[/bold] {db_type}\n"
        f"[bold]Storage:[/bold] {storage_type}\n"
        f"[bold]Products:[/bold] {s.get('products', 0)}\n"
        f"[bold]Scans:[/bold] {s.get('scans', 0)}\n"
        f"[bold]Packages:[/bold] {s.get('packages', 0)}\n"
        f"[bold]Files:[/bold] {s.get('files', 0)}",
        title="Statistics",
        box=box.ROUNDED,
    ))


@main.command("check")
def check():
    """Check if syft is installed."""
    try:
        version = check_syft_installed()
        console.print(f"[green]✓ Syft is installed (version {version})[/green]")
    except SyftNotFoundError as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
