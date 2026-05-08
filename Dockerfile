FROM python:3.12-slim

WORKDIR /workspace

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md mcpguard.yaml mcpguard.servers.yaml /workspace/
COPY src /workspace/src
COPY tests /workspace/tests
COPY examples /workspace/examples

RUN pip install --upgrade pip && \
    pip install -e .[dev]

CMD ["python", "-m", "pytest"]
