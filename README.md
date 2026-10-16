# NOTARY

Deterministic defence against indirect prompt injection in AI agents. See [CLAUDE.md](CLAUDE.md) for the architecture rules.

```sh
pnpm install && uv sync
pnpm dev                # http://localhost:3000/x-ray  (server on :8000)
docker compose up       # same demo in containers
pnpm turbo run lint typecheck test build && pnpm schema:check
```
