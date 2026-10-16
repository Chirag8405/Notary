"""Write the FastAPI OpenAPI document to packages/client/openapi.json (deterministic)."""

import json
import sys
from pathlib import Path

from notary_server.app import app

OUT = Path(__file__).resolve().parents[3] / "packages" / "client" / "openapi.json"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    sys.stdout.write(f"wrote {OUT}\n")


if __name__ == "__main__":
    main()
