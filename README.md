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

### Two Deployment Options

RH-Syfter can run in two deployment configurations:

| Mode | Storage | Best For |
|------|---------|----------|
| **Local Mode** | SQLite (`~/.rh-syfter/syfter.db`) | Development, single-user, small scale |
| **Server Mode** | PostgreSQL + MinIO (S3) | Production, multi-user, large scale |

- **Local Mode** is the default - no setup required, just install and run
- **Server Mode** requires running the API server with `podman-compose`

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
pip install click pyyaml rich packageurl-python httpx
```

## Deployment Options

### Option 1: Local Mode (Default)

Local mode uses SQLite and requires no additional setup. Just install and start using:

```bash
# Scans store to ~/.rh-syfter/syfter.db
rh-syfter scan /path/to/rpms -p myproduct -v 1.0
rh-syfter products
rh-syfter query -n "openssl%"
```

Local mode is great for:
- Development and testing
- Single-user workstations
- Small to medium scan volumes (up to ~50 products)

### Option 2: Server Mode (Distributed)

Server mode uses PostgreSQL for the database and MinIO (S3-compatible) for SBOM storage. This scales to thousands of products and supports multiple concurrent users.

#### Prerequisites for Server Mode

- **Podman** and **podman-compose** (or Docker/docker-compose)
  ```bash
  # Fedora/RHEL
  sudo dnf install podman podman-compose
  
  # macOS
  brew install podman podman-compose
  ```

#### Start the Server

```bash
cd docker

# Create environment file with your passwords
cp env.example .env
# Edit .env to set secure passwords:
#   POSTGRES_PASSWORD=your_secure_password
#   MINIO_ROOT_PASSWORD=your_secure_password

# Start all services (PostgreSQL, MinIO, API)
podman-compose up -d

# Check status
podman-compose ps

# View logs
podman-compose logs -f api
```

The services will be available at:
- **API Server**: http://localhost:8000
- **MinIO Console**: http://localhost:9001 (login with MINIO_ROOT_USER/PASSWORD)
- **PostgreSQL**: localhost:5432

#### Configure the CLI for Server Mode

Set the `SYFTER_SERVER` environment variable to point to your API server:

```bash
# Add to your ~/.bashrc or ~/.zshrc
export SYFTER_SERVER=http://localhost:8000

# Or specify per-command
rh-syfter --server http://localhost:8000 products
```

#### Server Mode Commands

Once `SYFTER_SERVER` is set, all commands automatically use the server:

```bash
# These now talk to the API server
rh-syfter scan registry.redhat.io/ubi9:latest -p ubi -v 9.0
rh-syfter products
rh-syfter query -n "kernel%"
rh-syfter export -p ubi -v 9.0 -f spdx-json -o ubi9.spdx.json
```

#### Force Local Mode

If `SYFTER_SERVER` is set but you want to use local SQLite:

```bash
rh-syfter --local products
```

#### Server Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     rh-syfter CLI (client)                      │
│               SYFTER_SERVER=http://localhost:8000               │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTP API
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     RH-Syfter API Server                        │
│                    (FastAPI, syfter-api)                        │
└───────────────────────────────┬─────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────┐              ┌─────────────────────┐
│     PostgreSQL      │              │   MinIO (S3)        │
│  (syfter-postgres)  │              │  (syfter-minio)     │
│                     │              │                     │
│  • Products         │              │  • Original SBOMs   │
│  • Packages         │              │  • Modified SBOMs   │
│  • Files            │              │  (gzip compressed)  │
│  • Systems          │              │                     │
└─────────────────────┘              └─────────────────────┘
```

#### Managing the Server

```bash
cd docker

# Stop all services
podman-compose down

# Stop and remove volumes (DELETES ALL DATA)
podman-compose down -v

# Rebuild after code changes
podman-compose build --no-cache api
podman-compose up -d api

# View API logs
podman-compose logs -f api

# Access PostgreSQL directly
podman-compose exec syfter-postgres psql -U syfter -d syfter
```

#### ARM Mac Users

On Apple Silicon Macs, you may need to specify the platform:

```bash
# Option 1: Set in .env
echo "DOCKER_DEFAULT_PLATFORM=linux/arm64" >> .env

# Option 2: Set environment variable
export DOCKER_DEFAULT_PLATFORM=linux/arm64
podman-compose up -d
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

#### Container Layer Tracking

When scanning container images, rh-syfter **automatically** determines which base image contributed each package. This helps identify where to fix vulnerabilities in multi-stage container builds.

```bash
# Scan a container image - base image scanning is automatic
rh-syfter scan registry.redhat.io/rhel9/go-toolset:latest -p go-toolset -v 9.0

# Query packages - shows source image for each package
rh-syfter query -n "go%" -p go-toolset -v 9.0
```

Output shows which image each package came from:
```
  Name                    Version          Product          Source Image      
 ──────────────────────────────────────────────────────────────────────────── 
  bash                    5.1.8-9.el9      go-toolset-9.0   ubi9/ubi          
  git                     2.47.3-1.el9_6   go-toolset-9.0   ubi9/s2i-base     
  golang                  1.25.3-1.el9_7   go-toolset-9.0   rhel9/go-toolset  
```

**How it works:**
1. Uses **layer digest comparison** to accurately identify the base image chain (e.g., `ubi9/ubi` → `ubi9/s2i-core` → `ubi9/s2i-base` → `rhel9/go-toolset`)
2. Extracts exact image references from labels (e.g., `registry.redhat.io/ubi9/ubi:9.7-1767674301`)
3. Scans each base image to build package lists
4. Compares package lists to determine which image introduced each package
5. Records `source_image` with each package in the database

The `rh-syfter layers` command shows the complete layer chain with:
- `layer_id`: The container layer digest (truncated)
- `layer_index`: The position in the layer stack (0 = base layer)
- `source_image`: The image that introduced this layer
- `image_reference`: The full image reference (registry/name:version-release)

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

> **Note:** System mode requires server mode (`SYFTER_SERVER` must be set). See [Server Mode](#option-2-server-mode-distributed) setup instructions.

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
  --layers                  Include source layer (container scans only)
```

With `--layers`, packages are output as `source_image::package-version`:

```bash
rh-syfter list -p go-toolset -v 1.25 -t packages --layers | grep zlib
ubi9/ubi::zlib-1.2.11-40.el9
ubi9/s2i-base::zlib-devel-1.2.11-40.el9

# Find all packages from a specific base image
rh-syfter list -p go-toolset -v 1.25 -t packages --layers | grep "^ubi9/ubi::"

# Count packages per layer
rh-syfter list -p go-toolset -v 1.25 -t packages --layers | cut -d: -f1 | sort | uniq -c
```

### `rh-syfter layers`

Display container layer chain for a product (container scans only).

```
Usage: rh-syfter layers [OPTIONS]

Options:
  -p, --product TEXT        Product name (required)
  -v, --version TEXT        Product version (required)
  --json                    Output as JSON
```

Shows the layer-by-layer breakdown of a container image, including:
- Layer index and truncated digest
- Source image name (e.g., `ubi9/ubi`, `rhel9/go-toolset`)
- Version and full image reference for each layer

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

RH-Syfter stores data in two locations:

**Local Mode** (SQLite):
- Database: `~/.rh-syfter/syfter.db`
- SBOMs stored as compressed blobs in the database

**Server Mode** (PostgreSQL + MinIO):
- Database: PostgreSQL for indexed metadata (packages, files, products)
- Object Storage: MinIO/S3 for compressed SBOM files

Both modes store:
- **Full SBOM preservation**: Both original and modified syft-json stored as-is
- **Indexed packages**: Package metadata for fast querying
- **Indexed files**: File paths and digests for lookup
- **Container layers**: Layer-to-image mapping for container scans

This dual approach allows:
- Fast queries across all products (database)
- Pristine SBOM retrieval for export (object storage)

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

### Client Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SYFTER_DB` | SQLite database path (local mode) | `~/.rh-syfter/syfter.db` |
| `SYFTER_SERVER` | API server URL (server mode) | None (uses local mode) |

### Server Variables (for API container)

| Variable | Description | Default |
|----------|-------------|---------|
| `SYFTER_DB_TYPE` | Database type (`sqlite` or `postgresql`) | `sqlite` |
| `SYFTER_PG_HOST` | PostgreSQL host | `localhost` |
| `SYFTER_PG_PORT` | PostgreSQL port | `5432` |
| `SYFTER_PG_DATABASE` | PostgreSQL database name | `syfter` |
| `SYFTER_PG_USER` | PostgreSQL username | `syfter` |
| `SYFTER_PG_PASSWORD` | PostgreSQL password | (required) |
| `SYFTER_STORAGE_TYPE` | Storage type (`local` or `s3`) | `local` |
| `SYFTER_S3_ENDPOINT` | S3/MinIO endpoint URL | (required for s3) |
| `SYFTER_S3_BUCKET` | S3 bucket name | `syfter-sboms` |
| `SYFTER_S3_ACCESS_KEY` | S3 access key | (required for s3) |
| `SYFTER_S3_SECRET_KEY` | S3 secret key | (required for s3) |

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
