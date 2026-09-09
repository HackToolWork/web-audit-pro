# syntax=docker/dockerfile:1

FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md requirements.txt ./
COPY web_audit ./web_audit

RUN python -m pip install --upgrade pip \
    && python -m pip wheel --no-cache-dir --wheel-dir /dist .

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    WEB_AUDIT_VULN_DB=/app/reports/vulndb.sqlite3

RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin webaudit \
    && mkdir -p /app/reports \
    && chown -R webaudit:webaudit /app

WORKDIR /app
COPY --from=builder /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

USER webaudit
ENTRYPOINT ["web-audit"]
CMD ["--help"]
