# RH-Syfter

SBOM generation and management tool for Red Hat products and infrastructure using [Syft](https://github.com/anchore/syft).

## Overview

RH-Syfter wraps the Anchore Syft tool to:

- **Scan** directories of RPMs, container images, and other artifacts
- **Enrich** SBOMs with product-specific metadata (CPEs, PURLs with distro qualifiers)
- **Store** SBOMs in a queryable database (SQLite or PostgreSQL)
- **Query** packages and files across all your products or systems
- **Export** to customer-facing formats (SPDX, CycloneDX)

### Two Modes of Operation

RH-Syfter supports two distinct modes:

1. **Product Mode** - Scan and manage SBOMs for software products (distros, containers, middleware)
2. **System Mode** - Scan and track packages across your infrastructure (servers, VMs, hosts)

## Prerequisites

- **Python 3.9+**
- **Syft** - Install from [GitHub releases](https://github.com/anchore/syft/releases), Homebrew, or:
  ```bash
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  ```
- **Skopeo** - Can be installed via dnf or Homebrew, see [GitHub installation instructions](https://github.com/containers/skopeo/blob/main/install.md)

## Installation

```bash
# Clone the repository
git clone https://github.com/redhat/rh-syfter.git
cd rh-syfter

# Install in development mode
pip install -e .

# Or install dependencies directly
pip install click pyyaml rich packageurl-python
```

## Quick Start

### 1. Scan a Directory of RPMs

```bash
# Scan RHEL 10.0 packages
rh-syfter scan /path/to/rhel10/rpms -p rhel -v 10.0

# Scan with description
rh-syfter scan /path/to/rpms -p rhel -v 10.0 --description "Red Hat Enterprise Linux 10.0"
```

### 2. Scan a Container Image

```bash
rh-syfter scan registry.redhat.io/rhel9:latest -p rhel -v 9.0
rh-syfter scan docker:ubi9/ubi:latest -p ubi -v 9.0
```

### 3. Query Packages

```bash
# Find all kernel packages across products
rh-syfter query -n "kernel%"

# Find packages in a specific product
rh-syfter query -n "openssl%" -p rhel -v 10.0

# Find files
rh-syfter query -f "%/bin/bash"
```

### 4. Export SBOMs

```bash
# Export to SPDX JSON
rh-syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.spdx.json

# Export to CycloneDX
rh-syfter export -p rhel -v 10.0 -f cyclonedx-json -o rhel-10.cdx.json

# Export to all formats
rh-syfter export -p rhel -v 10.0 -f all -o ./sboms/
```

## System Mode (Infrastructure Scanning)

In addition to scanning products, RH-Syfter can scan hosts in your infrastructure to track installed packages across systems.

### Scan the Local Host

```bash
# Scan localhost and upload to server
rh-syfter system-scan

# Add a tag for grouping
rh-syfter system-scan --tag production

# Scan with a descriptive tag
rh-syfter system-scan --tag "web-servers"
```

### Scan Remote Hosts via SSH

```bash
# Scan a remote host
rh-syfter system-scan webserver01.example.com

# With SSH options
rh-syfter system-scan 192.168.1.100 -u admin -i ~/.ssh/server_key

# Scan with a tag
rh-syfter system-scan dbserver.local --tag databases
```

**Note:** Remote scanning requires `syft` to be installed on the remote host.

### List Systems

```bash
# List all scanned systems
rh-syfter systems

# Filter by tag
rh-syfter systems --tag production
```

### Query Packages Across Systems

```bash
# Find which systems have openssh installed
rh-syfter system-query -n "openssh%"

# Search in specific systems
rh-syfter system-query -n "kernel%" --tag production

# Find files across systems
rh-syfter system-query -f "%/bin/bash"
```

### List Packages/Files for a System

```bash
# List all packages on a system
rh-syfter system-list -H webserver01 -t packages

# List all files
rh-syfter system-list -H webserver01 -t files
```

## CLI Reference

### `rh-syfter scan`

Scan a target and store the SBOM with product metadata.

```
Usage: rh-syfter scan [OPTIONS] TARGET

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  --vendor TEXT             Vendor name (default: "Red Hat")
  --cpe-vendor TEXT         CPE vendor string (default: "redhat")
  --purl-namespace TEXT     PURL namespace (default: "redhat")
  --description TEXT        Product description
  -o, --output PATH         Write modified SBOM to file
  --original-output PATH    Write original SBOM to file
  --no-store                Don't store in database
```

### `rh-syfter query`

Query packages and files across all products.

```
Usage: rh-syfter query [OPTIONS]

Options:
  -n, --name TEXT           Package name pattern (% = wildcard)
  -f, --file TEXT           File path pattern
  -d, --digest TEXT         File digest (exact match)
  -p, --product TEXT        Filter by product name
  -v, --version TEXT        Filter by product version
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
```

### `rh-syfter export`

Export a product's SBOM to various formats.

```
Usage: rh-syfter export [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  -f, --format TEXT         Output format: syft-json, spdx-json, spdx-tv,
                            cyclonedx-json, cyclonedx-xml, all
  -o, --output PATH         Output file or directory
```

### `rh-syfter products`

List all products in the database.

### `rh-syfter scans`

List all scans, optionally filtered by product.

### `rh-syfter stats`

Show database statistics.

### `rh-syfter check`

Verify syft is installed and show its version.

### `rh-syfter list`

List files or packages for a product version.

```
Usage: rh-syfter list [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  -t, --type [files|packages]  What to list (default: files)
  --full                    Include architecture in package output
```

### `rh-syfter system-scan`

Scan a host and store the SBOM for infrastructure tracking.

```
Usage: rh-syfter system-scan [OPTIONS] [TARGET]

Arguments:
  TARGET                    Hostname or IP (default: localhost)

Options:
  -t, --tag TEXT            Tag for grouping/CMDB linking
  -u, --user TEXT           SSH user for remote hosts
  -p, --port INTEGER        SSH port (default: 22)
  -i, --identity PATH       SSH identity file
  -o, --output PATH         Write SBOM to file
  --no-store                Don't store (just output)
  -q, --quiet               Suppress progress output
  --skip-files              Skip file indexing
  --include-debug           Include debuginfo packages
```

### `rh-syfter systems`

List all systems in the database.

```
Usage: rh-syfter systems [OPTIONS]

Options:
  --tag TEXT                Filter by system tag
```

### `rh-syfter system-query`

Query packages and files across systems.

```
Usage: rh-syfter system-query [OPTIONS]

Options:
  -n, --name TEXT           Package name pattern (% = wildcard)
  -f, --file TEXT           File path pattern
  -d, --digest TEXT         File digest (exact match)
  -H, --hostname TEXT       Filter by hostname
  -t, --tag TEXT            Filter by system tag
  --limit INTEGER           Maximum results (default: 50)
  --json                    Output as JSON
```

### `rh-syfter system-list`

List files or packages for a specific system.

```
Usage: rh-syfter system-list [OPTIONS]

Options:
  -H, --hostname TEXT       System hostname (required)
  -t, --type [files|packages]  What to list (default: files)
  --full                    Include architecture in package output
```

## Shell Script Wrappers

For convenience, shell scripts are provided in `scripts/`:

```bash
# Simple scan wrapper
./scripts/scan-product.sh /path/to/rpms rhel 10.0

# Query wrapper
./scripts/query.sh package "kernel%"
./scripts/query.sh file "%/bin/bash"

# Export wrapper
./scripts/export-sbom.sh rhel 10.0 spdx-json rhel-10.spdx.json

# Batch scan from config file
./scripts/batch-scan.sh products.conf
```

### Batch Scan Configuration

Create a config file for batch scanning:

```
# products.conf
/path/to/rhel10 rhel 10.0 "RHEL 10.0"
/path/to/rhel9 rhel 9.4 "RHEL 9.4"
/path/to/ocp openshift 4.14 "OpenShift Container Platform 4.14"
registry.redhat.io/ubi9:latest ubi 9.0 "Universal Base Image 9"
```

Then run:
```bash
./scripts/batch-scan.sh products.conf
```

## How It Works

### SBOM Enrichment

When you scan a target, RH-Syfter:

1. Runs Syft to generate a `syft-json` format SBOM
2. Modifies each package's metadata to include:
   - **CPE**: Updated with vendor (e.g., `cpe:2.3:a:redhat:kernel:...`)
   - **PURL**: Added distro qualifier (e.g., `pkg:rpm/redhat/kernel@5.14?distro=rhel-10.0`)
   - **Metadata**: Product information for traceability

### Storage

SBOMs are stored in SQLite (`~/.rh-syfter/syfter.db`) with:

- **Full SBOM preservation**: Both original and modified syft-json stored as-is
- **Indexed packages**: Package metadata for fast querying
- **Indexed files**: File paths and digests for lookup

This dual approach allows:
- Fast queries across all products
- Pristine SBOM retrieval for export

### Export Formats

RH-Syfter uses Syft's native conversion to generate:

| Format | Extension | Description |
|--------|-----------|-------------|
| `syft-json` | `.syft.json` | Native Syft format (stored internally) |
| `spdx-json` | `.spdx.json` | SPDX 2.3 JSON |
| `spdx-tv` | `.spdx` | SPDX Tag-Value |
| `cyclonedx-json` | `.cdx.json` | CycloneDX 1.4 JSON |
| `cyclonedx-xml` | `.cdx.xml` | CycloneDX 1.4 XML |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SYFTER_DB` | Database file path (local mode) | `~/.rh-syfter/syfter.db` |
| `SYFTER_SERVER` | API server URL (server mode) | None (uses local mode) |

## Examples

### Workflow: Generating Customer SBOMs

```bash
# 1. Scan all your products
rh-syfter scan /mnt/rhel10-rpms -p rhel -v 10.0
rh-syfter scan /mnt/rhel9-rpms -p rhel -v 9.4
rh-syfter scan registry.redhat.io/ubi9:latest -p ubi -v 9.0

# 2. Check what's stored
rh-syfter products
rh-syfter stats

# 3. Query across all products
rh-syfter query -n "openssl%"

# 4. Export customer-facing SBOMs
mkdir -p customer-sboms
rh-syfter export -p rhel -v 10.0 -f all -o customer-sboms/
rh-syfter export -p rhel -v 9.4 -f spdx-json -o customer-sboms/rhel-9.4.spdx.json
```

### Workflow: Finding Package Locations

```bash
# Find which products contain a specific package
rh-syfter query -n "curl" --json | jq '.[] | {product: "\(.product_name)-\(.product_version)", version: .version}'

# Find files by path pattern
rh-syfter query -f "%libssl%"

# Find files by digest
rh-syfter query -d "sha256:abc123..."
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rh-syfter CLI                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────┐    ┌─────────────┐    ┌─────────────────────────┐   │
│  │      Scanner      │───>│ Manipulator │───>│        Storage          │   │
│  │  (syft, ssh+syft) │    │ (CPE/PURL)  │    │ (SQLite/PostgreSQL+S3)  │   │
│  └───────────────────┘    └─────────────┘    └───────────┬─────────────┘   │
│          │                                               │                  │
│          │                                               v                  │
│  ┌───────┴───────┐                              ┌──────────┐               │
│  │ Scan Targets  │                              │ Exporter │               │
│  ├───────────────┤                              │  (SPDX/  │               │
│  │ • Products    │                              │   CDX)   │               │
│  │   - RPM dirs  │                              └──────────┘               │
│  │   - Containers│                                                         │
│  │   - Archives  │                                                         │
│  │ • Systems     │                                                         │
│  │   - Localhost │                                                         │
│  │   - SSH hosts │                                                         │
│  └───────────────┘                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black syfter/
ruff check syfter/
```

## License

Apache License 2.0
