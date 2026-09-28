# Undogate gateway: REST + remote MCP (/mcp) + optional Slack approvals.
FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.18 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd --system --uid 10001 --home /nonexistent undogate
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 \
    UNDOGATE_AUDIT_LOG=/var/log/undogate/audit.jsonl
RUN mkdir -p /var/log/undogate /etc/undogate && chown undogate /var/log/undogate
WORKDIR /etc/undogate
USER undogate
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz').status != 200)"
CMD ["uvicorn", "undogate.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
