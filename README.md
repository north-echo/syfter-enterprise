# Syfter Enterprise

A fork of [syfter](https://github.com/vdanen/syfter) hardened for multi-team, large-scale SBOM management.

## Why This Fork?

Syfter is a solid single-user SBOM tool. We deployed it as a centralized service scanning 3,600+ RPM repositories and 4,300+ container images (11M+ packages) for multiple teams and hit scaling limits:

| Problem | Upstream | Enterprise |
|---------|----------|------------|
| **Authentication** | None -- API is open | Built-in API key auth with per-team keys, admin management endpoints |
| **Rate limiting** | None | Token-bucket rate limiter per API key (60/min queries, 10/min uploads) |
| **Products list** | Sequential COUNT queries (N+1) | LATERAL join with index scans -- **16s -> 0.4s** |
| **Package search** | Full table scan + JOIN + sort | Subquery-first pattern with COLLATE "C" index -- **30s timeout -> 0.2s** |
| **Response caching** | None | In-process cache with auto-invalidation on mutations |
| **Job queue** | Async upload with FK violations | Removed -- direct upload only |
| **Object storage** | MinIO (self-hosted S3) | Native AWS S3 via IRSA |
| **Dependencies** | Not tracked | RPM requires/provides with indexed lookups |
| **Container SBOMs** | Local syft scan only | Downloads official Red Hat SPDX 2.3 SBOMs from OCI artifact tags |
| **Layer analysis** | Flat layer list | Base image identification via layer chain prefix matching |
| **Attestations** | Not supported | Cosign SLSA provenance and build attestation metadata |
| **Upload memory** | Decompresses all payloads at once | Deferred dependency parsing, early SBOM memory freeing |

Everything that works well in upstream syfter (scanning, SBOM enrichment, export) is preserved unchanged.

## What Changed

### Added
- **`server/auth.py`** -- API key authentication middleware + admin key management endpoints
- **`server/middleware.py`** -- Rate limiting (token bucket) and response caching middleware
- **`server/api/relationships.py`** -- Product-to-product component relationship CRUD
- **`alembic/`** -- Database migrations (001-004: base schema, auth, dependencies/relationships, attestations)

### Modified
- **`server/api/products.py`** -- Raw SQL with LATERAL joins for product counts
- **`server/api/queries.py`** -- Subquery-first-then-JOIN pattern for all search endpoints; COLLATE "C" ordering for index-compatible sorts; dependency and provenance search endpoints; trace endpoint with base image classification
- **`server/api/layers.py`** -- Layer chain retrieval (`GET /chains`), batch layer enrichment (`POST /enrich`), subquery optimization for layer search
- **`server/api/scans.py`** -- Dependency ingestion, image layer tracking with `is_base` field, attestation storage, deferred dependency decompression, early SBOM memory freeing with explicit GC
- **`server/config.py`** -- Auth, rate limit, cache, and dependency configuration via environment variables
- **`server/main.py`** -- Middleware registration, admin key seeding on startup
- **`server/api/models.py`** -- Added `Dependency`, `ComponentRelationship`, `Attestation` models; `is_base` field on `ImageLayer`

### Removed
- **`server/api/jobs.py`** -- Async job queue (caused FK violations, unnecessary for direct uploads)
- All job-related schemas, models, CLI commands, and client methods

## Features

### RPM Dependency Tracking

The upload endpoint accepts an optional `dependencies_json` field containing RPM requires/provides data. Dependencies are stored in a normalized, indexed table for fast lookups.

```bash
# Search dependencies
curl "$SYFTER_SERVER/api/v1/query/dependencies?dependency_name=libssl" \
  -H "X-API-Key: $SYFTER_API_KEY"

# Filter by type
curl "$SYFTER_SERVER/api/v1/query/dependencies?dependency_type=requires&package_name=curl" \
  -H "X-API-Key: $SYFTER_API_KEY"
```

### Component Relationships

Track product-to-product composition (e.g., an OpenStack operator image is a component of OpenStack Platform).

```bash
# List relationships
curl "$SYFTER_SERVER/api/v1/relationships/" -H "X-API-Key: $SYFTER_API_KEY"

# Create relationship
curl -X POST "$SYFTER_SERVER/api/v1/relationships/" \
  -H "X-API-Key: $SYFTER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"parent_product": "openstack", "parent_version": "18",
       "component_product": "osp-director-operator", "component_version": "1.4",
       "relationship_type": "component_of"}'
```

### Container Layer Enrichment

Identifies base images by prefix-matching OCI layer digest chains across products. If container C is `FROM ubi9:9.4`, then C's first K layers are byte-identical to UBI9's K layers.

```bash
# Get all layer chains
curl "$SYFTER_SERVER/api/v1/layers/chains" -H "X-API-Key: $SYFTER_API_KEY"

# Batch-enrich all container layer data (idempotent)
curl -X POST "$SYFTER_SERVER/api/v1/layers/enrich" -H "X-API-Key: $SYFTER_API_KEY"

# Query packages by layer type
curl "$SYFTER_SERVER/api/v1/layers/ubi9/9.4/packages?layer_type=base" \
  -H "X-API-Key: $SYFTER_API_KEY"
```

### Attestation Metadata

Container scans can include cosign attestation data (SLSA provenance, SPDX document attestations). Metadata is indexed in PostgreSQL; full attestation JSON is stored in S3.

```bash
# View attestations for a product
curl "$SYFTER_SERVER/api/v1/products/ubi9/9.4/attestations" \
  -H "X-API-Key: $SYFTER_API_KEY"
```

### Cross-Product Provenance

Trace a package across all products to find where it ships and where it originated.

```bash
# Find all products containing a specific package
curl "$SYFTER_SERVER/api/v1/query/provenance/ubi9/9.4?package_name=openssl" \
  -H "X-API-Key: $SYFTER_API_KEY"
```

## Quick Start

```bash
# Start the server
SYFTER_AUTH_ENABLED=true \
SYFTER_ADMIN_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))") \
SYFTER_DB_TYPE=postgresql \
SYFTER_PG_HOST=localhost \
SYFTER_PG_PASSWORD=changeme \
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000

# Health check (no auth required)
curl http://localhost:8000/health

# Create a team key
curl -X POST http://localhost:8000/api/v1/admin/keys \
  -H "X-API-Key: $SYFTER_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"team_name": "security"}'

# Use the team key
export SYFTER_API_KEY=<returned-key>
export SYFTER_SERVER=http://localhost:8000
syfter products
syfter query -n "openssl%"
```

## Configuration

All settings via environment variables (same as upstream, plus these):

| Variable | Default | Description |
|----------|---------|-------------|
| `SYFTER_AUTH_ENABLED` | `true` | Enable API key authentication |
| `SYFTER_ADMIN_API_KEY` | -- | Seed key for initial admin access |
| `SYFTER_RATE_LIMIT_ENABLED` | `true` | Enable per-key rate limiting |
| `SYFTER_RATE_LIMIT_QUERY` | `60` | Query requests per minute per key |
| `SYFTER_RATE_LIMIT_QUERY_BURST` | `20` | Query burst allowance |
| `SYFTER_RATE_LIMIT_UPLOAD` | `10` | Upload requests per minute per key |
| `SYFTER_RATE_LIMIT_UPLOAD_BURST` | `5` | Upload burst allowance |
| `SYFTER_CACHE_ENABLED` | `true` | Enable response caching |
| `SYFTER_CACHE_STATS_TTL` | `300` | Stats cache TTL (seconds) |
| `SYFTER_CACHE_PRODUCTS_TTL` | `300` | Products cache TTL (seconds) |

Set `SYFTER_AUTH_ENABLED=false` for local development without keys.

## API Endpoints

### Public
- `GET /health` -- Health check (no auth)

### Query (auth required)
- `GET /api/v1/query/stats` -- Database statistics (cached)
- `GET /api/v1/query/packages?name=<pattern>` -- Search packages by name, version, arch, purl, cpe
- `GET /api/v1/query/files?path=<pattern>` -- Search files by path or digest
- `GET /api/v1/query/dependencies?dependency_name=&dependency_type=` -- Search RPM requires/provides
- `GET /api/v1/query/components?product_name=&component_name=` -- Search component relationships
- `GET /api/v1/query/provenance/{product}/{version}` -- Cross-product package provenance
- `GET /api/v1/products` -- List products (paginated, cached)

### Layers (auth required)
- `GET /api/v1/layers/{product}/{version}` -- Container layer chain
- `GET /api/v1/layers/{product}/{version}/packages?layer_type=base` -- Packages by layer type
- `GET /api/v1/layers/chains` -- All layer chains (for enrichment)
- `POST /api/v1/layers/enrich` -- Batch base image enrichment

### Scans (auth required)
- `POST /api/v1/scans/upload` -- Upload scan (multipart: `original_sbom`, `modified_sbom`, `packages_json`, optional `dependencies_json`, `image_layers_json`, `attestation_json`)

### Relationships (auth required)
- `GET /api/v1/relationships/` -- List component relationships
- `POST /api/v1/relationships/` -- Create component relationship
- `DELETE /api/v1/relationships/{id}` -- Delete component relationship

### Attestations (auth required)
- `GET /api/v1/products/{product}/{version}/attestations` -- Attestation metadata

### Admin (admin key required)
- `POST /api/v1/admin/keys/` -- Create API key
- `GET /api/v1/admin/keys/` -- List API keys
- `DELETE /api/v1/admin/keys/{id}` -- Revoke API key

## Database Schema

### Core Tables (from upstream)
- **`products`** -- Product name, version, vendor
- **`scans`** -- Scan metadata, S3 keys, source type/path
- **`packages`** -- Package name, version, arch, epoch, release, source_rpm, license, purl, cpes, layer_id, source_image
- **`files`** -- File path, digest, algorithm per package
- **`image_layers`** -- Container layer chain with `layer_id`, `layer_index`, `source_image`, `is_base`
- **`api_keys`** -- API key management (SHA-256 hashed)

### Added Tables
- **`dependencies`** -- RPM requires/provides per package (indexed on `dependency_name`, `dependency_type`, `package_id`, `scan_id`, `product_id`)
- **`component_relationships`** -- Product-to-product composition mappings (unique constraint on parent + component)
- **`attestations`** -- Cosign attestation metadata: predicate_type, builder_id, build timestamps, S3 key (indexed on `scan_id`, `predicate_type`)

### Performance Indexes

For large-scale deployments (1M+ packages), these indexes are critical:

```sql
-- LIKE prefix queries + ORDER BY (the COLLATE "C" is essential)
CREATE INDEX idx_package_name_c ON packages (name COLLATE "C");

-- LIKE via text_pattern_ops (used by the index scan filter)
CREATE INDEX idx_package_name_pattern ON packages (name text_pattern_ops);

-- Foreign key lookups for product-scoped counts
CREATE INDEX idx_packages_product_id ON packages (product_id);
CREATE INDEX idx_scan_product ON scans (product_id);
```

## Upload Memory Optimization

Large SBOM uploads (10K+ packages, 1M+ dependencies) can spike server memory. The upload endpoint uses several strategies to stay within limits:

- **Modified SBOM stub**: Scanners can send `{"stub": true}` as `modified_sbom` instead of duplicating the full SBOM, halving decompression memory
- **Deferred dependency parsing**: Dependency data is read as compressed bytes during upload but decompressed only after SBOMs are stored and freed from memory
- **Explicit GC**: `gc.collect()` runs between parsing phases to release intermediate allocations
- **Batched inserts**: Dependencies are inserted in 10K-row batches with progress logging

## Deployment

This fork is designed for OpenShift/Kubernetes. See the [deployment repo](https://github.com/north-echo/syfter-deployment) for:
- Deployment manifests (Deployment, Service, Route, NetworkPolicy)
- OpenShift BuildConfig for container builds
- PostgreSQL StatefulSet configuration
- Keycloak OIDC integration for browser access
- AWS S3 + IRSA setup
- Repodata scanner (`scan-repodata.py`) and container scanner (`scan-containers.py`)

The container image is built from `podman/Containerfile`.

## Upstream Compatibility

The CLI client (`syfter` command) is fully compatible. Set `SYFTER_API_KEY` for authenticated access:

```bash
export SYFTER_SERVER=https://your-server.example.com
export SYFTER_API_KEY=your-team-key
syfter scan /path/to/rpms -p rhel -v 10.1
syfter query -n "kernel%"
syfter products
```

All upstream features (scanning, SBOM enrichment, export, container layer tracking, system mode) work identically.

## License

Apache License 2.0 -- same as upstream syfter.

## Credits

Based on [syfter](https://github.com/vdanen/syfter) by Vincent Danen. The upstream project does the heavy lifting of SBOM generation, enrichment, and container layer analysis. This fork adds the operational scaffolding for running it as a shared enterprise service.
