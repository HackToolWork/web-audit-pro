SHELL := /bin/bash

.PHONY: help install-dev ensure-dev test lint format compile check build docker-build clean

# Prefer an already-active virtual environment. Otherwise use the repository-local
# .venv so clean checkouts never fall through to the system Python.
VENV_DIR := $(if $(VIRTUAL_ENV),$(VIRTUAL_ENV),$(CURDIR)/.venv)
PYTHON := $(VENV_DIR)/bin/python
VENV_BIN := $(VENV_DIR)/bin
PYTEST := $(PYTHON) -m pytest
RUFF := $(VENV_BIN)/ruff
BUILD := $(PYTHON) -m build

help:
	@printf '%s\n' \
		'make install-dev  Create/update the active or repository .venv' \
		'test             Run the test suite in the selected environment' \
		'lint             Run Ruff in the selected environment' \
		'compile          Compile Python modules' \
		'check            Run lint + compile + tests' \
		'build            Build the Python package' \
		'docker-build     Build the Docker image' \
		'clean             Remove generated build/test artifacts'

install-dev:
	@command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required.' >&2; exit 127; }
	@python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
	@if [ -n "$(VIRTUAL_ENV)" ]; then \
		test -x "$(PYTHON)" || { echo '[!] Active virtual environment has no usable Python: $(PYTHON)' >&2; exit 2; }; \
		echo '[web-audit-pro] Using active virtual environment: $(VIRTUAL_ENV)'; \
	else \
		python3 -m venv .venv; \
	fi
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install -e .

ensure-dev:
	@command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required. Install Python 3.11+.' >&2; exit 127; }
	@python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo '[!] Python 3.11+ is required.' >&2; exit 2; }
	@if [ -n "$(VIRTUAL_ENV)" ]; then \
		echo '[web-audit-pro] Using active virtual environment: $(VIRTUAL_ENV)'; \
	elif [ ! -x "$(PYTHON)" ]; then \
		echo '[web-audit-pro] Development environment is missing; creating it...'; \
		$(MAKE) install-dev; \
	fi

require-pytest: ensure-dev
	@$(PYTHON) -c 'import pytest' >/dev/null 2>&1 || { \
		echo '[!] Pytest is missing in the selected virtual environment.' >&2; \
		echo '[i] Run: $(PYTHON) -m pip install -r requirements-dev.txt' >&2; \
		exit 2; \
	}

require-ruff: ensure-dev
	@test -x "$(RUFF)" || { \
		echo '[!] Ruff is missing in the selected virtual environment.' >&2; \
		echo '[i] Run: $(PYTHON) -m pip install -r requirements-dev.txt' >&2; \
		exit 2; \
	}

require-build: ensure-dev
	@$(PYTHON) -c 'import build' >/dev/null 2>&1 || { \
		echo '[!] Build is missing in the selected virtual environment.' >&2; \
		echo '[i] Run: $(PYTHON) -m pip install -r requirements-dev.txt' >&2; \
		exit 2; \
	}

test: require-pytest
	$(PYTEST) -q

lint: require-ruff
	$(RUFF) check .

compile: ensure-dev
	$(PYTHON) -m compileall -q web_audit tests

format: require-ruff
	$(RUFF) format --check .

check: lint format compile test

build: require-build
	$(BUILD)

# Keep the canonical lower-case target for compatibility.
docker-build:
	docker build -t web-audit-pro:local .

clean:
	rm -rf build dist .pytest_cache .ruff_cache *.egg-info .venv
