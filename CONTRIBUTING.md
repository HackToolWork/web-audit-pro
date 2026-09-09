# Contributing

Thank you for helping improve web-audit-pro.

## Development setup

The repository provides a Make-based workflow that respects an already active
`VIRTUAL_ENV`. Otherwise it creates a repository-local `.venv`.

```bash
make install-dev
make check
```

You can also use the underlying commands directly:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
ruff check .
```

## Pull requests

Keep changes focused, add regression tests, preserve the project's safety model,
and update user-facing documentation when behavior changes.

Do not add credential attacks, destructive requests, unrestricted crawling,
automatic takeover attempts, or mechanisms intended to bypass authorization.

## Security-sensitive changes

Explain changes to network behavior, scope handling, rate limiting, data storage,
credential redaction, or report generation in the pull request.

Never include live secrets or private target data in issues or pull requests.
