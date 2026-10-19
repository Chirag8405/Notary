"""Write schema/proxy-config.schema.json from `ProxyConfig` (deterministic).

The file is generated: change the Pydantic models in `notary_mcp_proxy.config`, then run
`pnpm schema:generate`. This script lives outside the package so the package stays free of I/O.
"""

import json
from pathlib import Path

from notary_mcp_proxy.config import ProxyConfig

OUT_FILE = Path(__file__).resolve().parents[1] / "schema" / "proxy-config.schema.json"
DIALECT = "https://json-schema.org/draft/2020-12/schema"


def build_schema() -> dict[str, object]:
    """The config's schema by alias (`server`, `servers`, `$schema`), led by the dialect."""
    generated = ProxyConfig.model_json_schema(by_alias=True)
    return {"$schema": DIALECT, **generated}


def main() -> None:
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(build_schema(), indent=2, ensure_ascii=False) + "\n"
    OUT_FILE.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT_FILE.name}")


if __name__ == "__main__":
    main()
