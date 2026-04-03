# Syfter Enterprise

A fork of [syfter](https://github.com/vdanen/syfter) hardened for multi-team, large-scale SBOM management.

## Why This Fork?

Syfter is a solid single-user SBOM tool. We deployed it as a centralized service scanning 3,200+ RPM repositories (11M+ packages) for multiple teams and hit scaling limits:

| Problem | Upstream | Enterprise |
|---------|----------|------------|
| **Authentication** | None — API is open | Built-in API key auth with per-team keys, admin management endpoints |
| **Rate limiting** | None | Token-bucket rate limiter per API key (60/min queries, 10/min uploads) |
| **Products list** | Sequential COUNT queries (N+1) | LATERAL join with index scans — **16s → 0.4s** |
| **Package search** | Full table scan + JOIN + sort | Subquery-first pattern with COLLATE "C" index — **30s timeout → 0.2s** |
| **Response caching** | None | In-process cache with auto-invalidation on mutations |
| **Job queue** | Async upload with FK violations | Removed — direct upload only |
| **Object storage** | MinIO (self-hosted S3) | Native AWS S3 via IRSA |

Everything that works well in upstream syfter (scanning, SBOM enrichment, export, container layer tracking) is preserved unchanged.

## What Changed

### Added
- **`server/auth.py`** — API key authentication middleware + admin key management endpoints
- **`server/middleware.py`** — Rate limiting (token bucket) and response caching middleware
- **`alembic/`** — Database migrations for schema changes

### Modified
- **`server/api/products.py`** — Raw SQL with LATERAL joins for product counts
- **`server/api/queries.py`** — Subquery-first-then-JOIN pattern for all search endpoints; COLLATE "C" ordering for index-compatible sorts
- **`server/api/layers.py`** — Same subquery optimization for layer search
- **`server/config.py`** — Auth, rate limit, and cache configuration via environment variables
- **`server/main.py`** — Middleware registration, admin key seeding on startup, version bump

### Removed
- **`server/api/jobs.py`** — Async job queue (caused FK violations, unnecessary for direct uploads)
- All job-related schemas, models, CLI commands, and client methods

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
| `SYFTER_ADMIN_API_KEY` | — | Seed key for initial admin access |
| `SYFTER_RATE_LIMIT_ENABLED` | `true` | Enable per-key rate limiting |
| `SYFTER_RATE_LIMIT_QUERY` | `60` | Query requests per minute per key |
| `SYFTER_RATE_LIMIT_UPLOAD` | `10` | Upload requests per minute per key |
| `SYFTER_CACHE_ENABLED` | `true` | Enable response caching |
| `SYFTER_CACHE_STATS_TTL` | `300` | Stats cache TTL (seconds) |
| `SYFTER_CACHE_PRODUCTS_TTL` | `300` | Products cache TTL (seconds) |

Set `SYFTER_AUTH_ENABLED=false` for local development without keys.

## API Key Management

```bash
# Create a team key (admin only)
curl -X POST /api/v1/admin/keys \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"team_name": "platform", "expires_days": 365}'

# List keys
curl /api/v1/admin/keys -H "X-API-Key: $ADMIN_KEY"

# Revoke a key
curl -X DELETE /api/v1/admin/keys/<key-prefix> -H "X-API-Key: $ADMIN_KEY"
```

## Database Indexes

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

## Deployment

This fork is designed for OpenShift/Kubernetes. See the deployment repo for:
- Deployment manifests (Deployment, Service, Route, NetworkPolicy)
- OpenShift BuildConfig for container builds
- PostgreSQL StatefulSet configuration
- Keycloak OIDC integration for browser access
- AWS S3 + IRSA setup

The container image is built from `podman/Containerfile` (same as upstream).

## Upstream Compatibility

The CLI client (`syfter` command) is fully compatible. Set `SYFTER_API_KEY` for authenticated access:

```bash
export SYFTER_SERVER=https://your-server.example.com
export SYFTER_API_KEY=your-team-key
syfter scan /path/to/rpms -p rhel -v 10.1
syfter query -n "kernel%"
syfter products
```

All upstream features (scanning, export, container layer tracking, system mode) work identically.

## License

Apache License 2.0 — same as upstream syfter.

## Credits

Based on [syfter](https://github.com/vdanen/syfter) by Vincent Danen. The upstream project does the heavy lifting of SBOM generation, enrichment, and container layer analysis. This fork adds the operational scaffolding for running it as a shared enterprise service.
