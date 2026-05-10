FROM python:3.12-slim AS builder

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md /app/
COPY src /app/src

RUN python -m pip install --upgrade pip build && \
    python -m build --wheel --outdir /tmp/dist

FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 appuser

COPY --from=builder /tmp/dist /tmp/dist
RUN python -m pip install --upgrade pip && \
    python -m pip install /tmp/dist/*.whl && \
    rm -rf /tmp/dist

COPY mcpguard.yaml mcpguard.servers.yaml /app/

USER appuser

ENTRYPOINT ["mcpguard"]
CMD ["--help"]
