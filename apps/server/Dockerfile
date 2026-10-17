# Build context: repository root (see docker-compose.yml)
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
COPY apps/server apps/server
COPY packages/core packages/core
COPY packages/world packages/world
COPY packages/mcp-proxy packages/mcp-proxy
COPY packages/cli packages/cli
COPY packages/eval packages/eval
RUN uv sync --frozen --no-dev --package notary-server

FROM python:3.12-slim-bookworm
WORKDIR /app
COPY --from=build /app /app
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
# One worker, one WebSocket implementation: the broker state and the read-token key live in this
# process, and the log filter covers the `websockets` loggers (#235).
CMD ["uvicorn", "notary_server.app:app", "--ws", "websockets", "--host", "0.0.0.0", "--port", "8000"]
