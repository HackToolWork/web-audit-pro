#!/usr/bin/env bash
# Stop the lab. With --reset, also delete its data volume, network and credentials.
set -Eeuo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

docker rm -f sitozor-lab-wp sitozor-lab-db >/dev/null 2>&1 || true
if [[ "${1:-}" == "--reset" ]]; then
    docker volume rm sitozor-lab-wp >/dev/null 2>&1 || true
    docker network rm sitozor-lab >/dev/null 2>&1 || true
    rm -f "$LAB_DIR/.env"
    echo "[lab] Stopped and reset."
else
    echo "[lab] Stopped. Site files are kept in the sitozor-lab-wp volume; use --reset to delete them."
fi
