#!/bin/sh
#
# script to nuke and rebuild

podman-compose down
podman rm -f syfter-api syfter-postgres syfter-minio 2>/dev/null

podman volume ls
podman volume rm docker_postgres_data docker_minio_data 2>/dev/null

podman rmi docker-api 2>/dev/null

podman-compose up -d --build

