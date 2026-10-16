"""Serialise sample events to JSON fixtures that the TS side parses with Zod."""

import sys
from pathlib import Path

from notary_world.sample_run import EVENT_ADAPTER, poisoned_bill_events

OUT = Path(__file__).resolve().parents[1] / "fixtures" / "events"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.json"):
        stale.unlink()
    seen: dict[str, int] = {}
    for event in poisoned_bill_events():
        count = seen.get(event.type, 0)
        seen[event.type] = count + 1
        payload = EVENT_ADAPTER.dump_json(event, indent=2).decode("utf-8")
        (OUT / f"{event.seq:02d}_{event.type}.json").write_text(payload + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {sum(seen.values())} event fixtures to {OUT}\n")


if __name__ == "__main__":
    main()
