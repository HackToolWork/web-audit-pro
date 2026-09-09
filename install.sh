#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="web-audit-pro"
INSTALL_ROOT="${WEB_AUDIT_INSTALL_ROOT:-/opt/web-audit-pro}"
BIN_PATH="${WEB_AUDIT_BIN:-/usr/local/bin/web-audit}"
VENV_PATH="${INSTALL_ROOT}/.venv"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

log() { printf '[%s] %s\n' "$APP_NAME" "$*"; }
fail() { printf '[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<USAGE
Usage: sudo ./install.sh

Installs web-audit-pro into an isolated virtual environment and exposes the
web-audit command system-wide at /usr/local/bin/web-audit.

Development and tests are intentionally kept in the source checkout. After
installation, use `make test` / `make check` from that checkout; the Makefile
will create .venv automatically when needed.

Environment overrides:
  WEB_AUDIT_INSTALL_ROOT   Installation directory (default: /opt/web-audit-pro)
  WEB_AUDIT_BIN            Command path (default: /usr/local/bin/web-audit)
USAGE
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || fail "sudo is required for system-wide installation"
    exec sudo -E "$0" "$@"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
python3 - <<'PY' || exit 1
import sys
if sys.version_info < (3, 11):
    print("ERROR: Python 3.11 or newer is required.", file=sys.stderr)
    print(f"Found Python {sys.version.split()[0]}", file=sys.stderr)
    raise SystemExit(1)
PY

mkdir -p "$INSTALL_ROOT"
if [[ ! -d "$SCRIPT_DIR/web_audit" || ! -f "$SCRIPT_DIR/pyproject.toml" ]]; then
    fail "run install.sh from the Web Audit Pro project directory"
fi

log "Creating isolated environment: $VENV_PATH"
python3 -m venv "$VENV_PATH"

log "Installing project and runtime dependencies"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_INPUT=1
if ! "$VENV_PATH/bin/python" -m pip install --disable-pip-version-check \
    --retries 1 --timeout 20 "$SCRIPT_DIR"; then
    printf '[%s] ERROR: installation failed.\n' "$APP_NAME" >&2
    printf '[%s] If the error mentions pyproject.toml/Hatchling, the package build is invalid.\n' "$APP_NAME" >&2
    printf '[%s] If it mentions resolution/download errors, check network access and the package index.\n' "$APP_NAME" >&2
    exit 1
fi

if [[ -e "$BIN_PATH" && ! -L "$BIN_PATH" ]]; then
    fail "$BIN_PATH already exists and is not a symlink; refusing to overwrite it"
fi
if [[ -L "$BIN_PATH" ]]; then
    current_target="$(readlink -f "$BIN_PATH")"
    expected_target="$(readlink -f "$VENV_PATH/bin/web-audit")"
    [[ "$current_target" == "$expected_target" ]] || \
        fail "$BIN_PATH points to another program; refusing to replace it"
fi
ln -sfn "$VENV_PATH/bin/web-audit" "$BIN_PATH"

"$VENV_PATH/bin/web-audit" --help >/dev/null

log "Installation complete"
log "Command: web-audit --help"
log "Installed at: $BIN_PATH"
log "Runtime environment: $VENV_PATH"
log "Development checks: from the source checkout run: make test"
log "Full quality gate: from the source checkout run: make check"
