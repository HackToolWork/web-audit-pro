#!/usr/bin/env bash
# Local WordPress test lab with a deliberately outdated plugin, for end-to-end
# testing of plugin detection, vulnerability matching and the owner report.
#
# The site is bound to 127.0.0.1 only. Never expose it: it is intentionally vulnerable.
set -Eeuo pipefail

LAB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ENV_FILE="$LAB_DIR/.env"
NETWORK="sitozor-lab"
DB="sitozor-lab-db"
WP="sitozor-lab-wp"
VOLUME="sitozor-lab-wp"
PORT="${LAB_PORT:-8081}"
WP_IMAGE="${LAB_WP_IMAGE:-wordpress:6.4-apache}"
DB_IMAGE="${LAB_DB_IMAGE:-mariadb:11}"
CLI_IMAGE="${LAB_CLI_IMAGE:-wordpress:cli}"
# Contact Form 7 5.3.1: CVE-2020-35489 (unrestricted file upload), fixed in 5.3.2.
PLUGINS=("contact-form-7@5.3.1")

log() { printf '[lab] %s\n' "$*"; }

if [[ ! -f "$ENV_FILE" ]]; then
    umask 077
    {
        echo "DB_PASSWORD=$(openssl rand -hex 16)"
        echo "WP_ADMIN_PASSWORD=$(openssl rand -hex 12)"
    } > "$ENV_FILE"
    log "Generated test credentials in $ENV_FILE"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null

if ! docker container inspect "$DB" >/dev/null 2>&1; then
    log "Starting database ($DB_IMAGE)"
    docker run -d --name "$DB" --network "$NETWORK" \
        -e MARIADB_DATABASE=wordpress -e MARIADB_USER=wordpress \
        -e MARIADB_PASSWORD="$DB_PASSWORD" -e MARIADB_RANDOM_ROOT_PASSWORD=1 \
        "$DB_IMAGE" >/dev/null
fi

if ! docker container inspect "$WP" >/dev/null 2>&1; then
    log "Starting WordPress ($WP_IMAGE) on http://localhost:$PORT"
    docker run -d --name "$WP" --network "$NETWORK" -p "127.0.0.1:$PORT:80" \
        -e WORDPRESS_DB_HOST="$DB" -e WORDPRESS_DB_USER=wordpress \
        -e WORDPRESS_DB_PASSWORD="$DB_PASSWORD" -e WORDPRESS_DB_NAME=wordpress \
        -v "$VOLUME:/var/www/html" "$WP_IMAGE" >/dev/null
fi
docker start "$DB" "$WP" >/dev/null

wp() {
    docker run --rm --network "$NETWORK" --user 33:33 -v "$VOLUME:/var/www/html" \
        -e WORDPRESS_DB_HOST="$DB" -e WORDPRESS_DB_USER=wordpress \
        -e WORDPRESS_DB_PASSWORD="$DB_PASSWORD" -e WORDPRESS_DB_NAME=wordpress \
        -e HOME=/tmp "$CLI_IMAGE" wp --url="http://localhost:$PORT" "$@"
}

log "Waiting for WordPress files and database"
for _ in $(seq 1 60); do
    if docker exec "$WP" test -f /var/www/html/wp-config.php && wp db check >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

if ! wp core is-installed >/dev/null 2>&1; then
    log "Installing WordPress"
    wp core install --url="http://localhost:$PORT" --title="Sitozor Lab" \
        --admin_user=admin --admin_password="$WP_ADMIN_PASSWORD" \
        --admin_email=lab@example.com --skip-email >/dev/null
fi

for spec in "${PLUGINS[@]}"; do
    slug="${spec%@*}"
    version="${spec#*@}"
    if [[ "$(wp plugin get "$slug" --field=version 2>/dev/null || true)" != "$version" ]]; then
        log "Installing plugin $slug $version"
        wp plugin install "$slug" --version="$version" --force --activate >/dev/null
    fi
done

log "Ready: http://localhost:$PORT (admin password in $ENV_FILE)"
log "Scan: .venv/bin/web-audit http://localhost:$PORT --yes-i-am-authorized --allow-private --lang ru"
