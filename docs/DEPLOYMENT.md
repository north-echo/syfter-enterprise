# RH-Syfter Deployment Guide

This guide covers deploying the RH-Syfter server and clients for production use.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      RH-Syfter Clients                          │
│  (scan targets, upload SBOMs, query packages, export SBOMs)     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      RH-Syfter API Server                       │
│                    (FastAPI, 20-30 clients)                     │
└─────────────────────────────────────────────────────────────────┘
           │                                    │
           ▼                                    ▼
┌─────────────────────┐              ┌─────────────────────┐
│     PostgreSQL      │              │   MinIO / S3        │
│   (indexed data)    │              │  (SBOM storage)     │
│   ~50GB for 1000    │              │  ~500GB for 1000    │
│     scans           │              │     scans           │
└─────────────────────┘              └─────────────────────┘
```

## Quick Start with Docker Compose

The easiest way to deploy is using Docker Compose:

```bash
cd docker

# Create .env file with secrets
cat > .env << EOF
POSTGRES_PASSWORD=your_secure_password
MINIO_ROOT_USER=minio_admin
MINIO_ROOT_PASSWORD=your_minio_password
EOF

# Start all services
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f api
```

The API will be available at http://localhost:8000

## Manual Setup

### 1. PostgreSQL Setup

#### Install PostgreSQL

**RHEL/Fedora:**
```bash
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

#### Create Database and User

```bash
sudo -u postgres psql << EOF
CREATE USER syfter WITH PASSWORD 'your_secure_password';
CREATE DATABASE syfter OWNER syfter;
GRANT ALL PRIVILEGES ON DATABASE syfter TO syfter;
EOF
```

#### Configure Remote Access (if needed)

Edit `/var/lib/pgsql/data/postgresql.conf`:
```
listen_addresses = '*'
```

Edit `/var/lib/pgsql/data/pg_hba.conf`:
```
# Allow connections from your network
host    syfter    syfter    10.0.0.0/8    scram-sha-256
```

Restart PostgreSQL:
```bash
sudo systemctl restart postgresql
```

### 2. MinIO Setup

#### Install MinIO

**RHEL/Fedora:**
```bash
# Download binary
curl -O https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
sudo mv minio /usr/local/bin/

# Create data directory
sudo mkdir -p /data/minio
sudo chown $USER:$USER /data/minio
```

#### Run MinIO

```bash
# Set credentials
export MINIO_ROOT_USER=minio_admin
export MINIO_ROOT_PASSWORD=your_minio_password

# Run MinIO
minio server /data/minio --console-address ":9001"
```

Or as a systemd service:

```bash
sudo cat > /etc/systemd/system/minio.service << EOF
[Unit]
Description=MinIO
After=network-online.target
Wants=network-online.target

[Service]
User=minio
Group=minio
Environment="MINIO_ROOT_USER=minio_admin"
Environment="MINIO_ROOT_PASSWORD=your_minio_password"
ExecStart=/usr/local/bin/minio server /data/minio --console-address ":9001"
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo useradd -r minio
sudo chown -R minio:minio /data/minio
sudo systemctl daemon-reload
sudo systemctl enable --now minio
```

### 3. RH-Syfter API Server

#### Install

```bash
# Clone repository
git clone https://github.com/redhat/rh-syfter.git
cd rh-syfter

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with server dependencies
pip install -e ".[server]"
```

#### Configure

Set environment variables:

```bash
export SYFTER_DB_TYPE=postgresql
export SYFTER_PG_HOST=localhost
export SYFTER_PG_PORT=5432
export SYFTER_PG_DATABASE=syfter
export SYFTER_PG_USER=syfter
export SYFTER_PG_PASSWORD=your_secure_password

export SYFTER_STORAGE_TYPE=s3
export SYFTER_S3_ENDPOINT=http://localhost:9000
export SYFTER_S3_BUCKET=syfter-sboms
export SYFTER_S3_ACCESS_KEY=minio_admin
export SYFTER_S3_SECRET_KEY=your_minio_password
export SYFTER_S3_USE_SSL=false

export SYFTER_HOST=0.0.0.0
export SYFTER_PORT=8000
export SYFTER_WORKERS=4
```

Or create a `.env` file and use something like `python-dotenv`.

#### Run

```bash
# Development mode
python -m uvicorn server.main:app --reload

# Production mode
python -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Or as a systemd service:

```bash
sudo cat > /etc/systemd/system/syfter-api.service << EOF
[Unit]
Description=RH-Syfter API Server
After=network.target postgresql.service minio.service

[Service]
User=syfter
Group=syfter
WorkingDirectory=/opt/rh-syfter
Environment="PATH=/opt/rh-syfter/.venv/bin"
EnvironmentFile=/opt/rh-syfter/.env
ExecStart=/opt/rh-syfter/.venv/bin/python -m uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now syfter-api
```

## Client Configuration

Configure clients to use the server:

```bash
# Set server URL
export SYFTER_SERVER=http://your-server:8000

# Verify connection
rh-syfter stats

# Run a scan
rh-syfter scan /path/to/rpms -p rhel -v 10.0

# Query packages
rh-syfter query -n "kernel%"

# Export SBOM
rh-syfter export -p rhel -v 10.0 -f spdx-json -o rhel-10.spdx.json
```

## Production Considerations

### Security

1. **Use HTTPS**: Put a reverse proxy (nginx, HAProxy) in front of the API with TLS
2. **Firewall**: Restrict access to PostgreSQL and MinIO ports
3. **Authentication**: Consider adding API key authentication (not yet implemented)

### Scaling

1. **API Workers**: Increase `SYFTER_WORKERS` for more concurrent requests
2. **PostgreSQL**: Consider connection pooling (pgbouncer) for 30+ clients
3. **MinIO**: Can be clustered for high availability

### Backup

1. **PostgreSQL**: Regular pg_dump backups
2. **MinIO**: Enable versioning and replication

### Monitoring

1. **API**: Check `/health` endpoint
2. **PostgreSQL**: Monitor connections and query performance
3. **MinIO**: Monitor disk usage and request rates

## AWS S3 Configuration

To use AWS S3 instead of MinIO:

```bash
export SYFTER_STORAGE_TYPE=s3
export SYFTER_S3_BUCKET=your-bucket-name
export SYFTER_S3_ACCESS_KEY=your_aws_access_key
export SYFTER_S3_SECRET_KEY=your_aws_secret_key
export SYFTER_S3_REGION=us-east-1
# Don't set SYFTER_S3_ENDPOINT for AWS S3
```

## Troubleshooting

### API won't start

```bash
# Check logs
journalctl -u syfter-api -f

# Test database connection
psql -h localhost -U syfter -d syfter

# Test MinIO connection
mc alias set local http://localhost:9000 minio_admin your_password
mc ls local/
```

### Slow queries

```bash
# Check PostgreSQL indexes
psql -U syfter -d syfter -c "\di"

# Analyze tables
psql -U syfter -d syfter -c "ANALYZE;"
```

### Large SBOM upload fails

- Increase `SYFTER_TIMEOUT` on client
- Check MinIO disk space
- Check PostgreSQL connection limits
