# Web Audit Pro 5.0.1

## Release highlights

### Makefile virtual-environment validation

Development targets now verify that required tools exist as executables in the
selected virtual environment. This prevents an active-environment edge case
from accidentally falling through to the wrong Python installation.

### CI reliability

Regression coverage was updated to validate the improved Makefile behavior.
The CI matrix covers Python 3.11, 3.12, 3.13, and 3.14, with package and
Docker validation.

## Installation

```bash
sudo ./install.sh
web-audit --version
```

For contributors:

```bash
make install-dev
make check
```

## Verification

Local validation for the 5.0.1 release candidate includes Ruff linting and
format checking, Python compilation, dependency checks, and 110 automated tests.
