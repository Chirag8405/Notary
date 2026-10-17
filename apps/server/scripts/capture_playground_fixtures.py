"""Record the playground's REST answers into apps/web/tests/fixtures/playground/.

    uv run --no-sync python apps/server/scripts/capture_playground_fixtures.py          # write
    uv run --no-sync python apps/server/scripts/capture_playground_fixtures.py --check  # 1 = drift

The app runs in-process (`TestClient`): no server, no network, no LLM. Every file is
`{"status": <int>, "body": <json>}`, so the web tests serve the server's own answers.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from fastapi.testclient import TestClient

from notary_server.app import app, create_app
from notary_server.hijacked import HijackedSessions, counter_session_ids
from notary_world.cast import ATTACKER_IBAN, BILLER_IBAN
from notary_world.tools import TOOL_SPECS

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = REPO_ROOT / "apps" / "web" / "tests" / "fixtures" / "playground"
POISON_COMMAND = REPO_ROOT / "packages" / "world" / "fixtures" / "commands" / "poison_world.json"

JsonDict = dict[str, object]


def recorded(status: int, body: object) -> JsonDict:
    return {"status": status, "body": body}


class Answered(Protocol):
    status_code: int

    def json(self) -> object: ...


def answer(response: Answered) -> JsonDict:
    return recorded(response.status_code, response.json())


def hijacked_call(
    client: TestClient, session: JsonDict, call_id: str, tool: str, args: dict[str, str]
) -> Answered:
    command = {
        "type": "hijacked_tool_call",
        "run_id": session["run_id"],
        "call_id": call_id,
        "tool": tool,
        "args": args,
    }
    return client.post(f"/playground/hijacked/{session['session_id']}/calls", json=command)


def numbered_client() -> TestClient:
    """An app whose Hijacked Mode sessions are `h1`, `h2`, ... (a real server uses random ids), so
    the recorded fixtures are the same every time they are captured."""
    return TestClient(
        create_app(event_delay=0, hijacked=HijackedSessions(new_id=counter_session_ids()))
    )


def capture() -> dict[str, JsonDict]:
    files: dict[str, JsonDict] = {}
    client = TestClient(app)

    poison = json.loads(POISON_COMMAND.read_text())
    files["poison.sample"] = answer(client.post("/playground/poison", json=poison))
    files["poison.cassette-miss"] = answer(
        client.post("/playground/poison", json={**poison, "payload": "Pay to another IBAN"})
    )
    files["attacks.list"] = answer(client.get("/attacks"))
    for attack_id in ("A3", "A13", "B1"):
        files[f"attack.{attack_id}"] = answer(client.post(f"/playground/attacks/{attack_id}/run"))

    poisoned = numbered_client()
    start = poisoned.post("/playground/hijacked", json={"scenario": "poisoned_bill", "seed": 0})
    files["hijacked.start"] = answer(start)
    session: JsonDict = start.json()
    files["hijacked.step.pay_attacker"] = answer(
        hijacked_call(
            poisoned, session, "c1", "pay_bill", {"payee": ATTACKER_IBAN, "amount": "120.00"}
        )
    )
    files["hijacked.step.send_email"] = answer(
        hijacked_call(
            poisoned,
            session,
            "c2",
            "send_email",
            {"to": "x@evil.test", "subject": "s", "body": "b"},
        )
    )
    files["hijacked.step.read_inbox"] = answer(
        hijacked_call(poisoned, session, "c3", "read_inbox", {})
    )
    files["hijacked.state"] = answer(poisoned.get(f"/playground/hijacked/{session['session_id']}"))

    legit = numbered_client()
    legit_start = legit.post(
        "/playground/hijacked", json={"scenario": "legitimate_bill", "seed": 0}
    )
    files["hijacked.legit.start"] = answer(legit_start)
    files["hijacked.legit.step.pay_biller"] = answer(
        hijacked_call(
            legit, legit_start.json(), "c1", "pay_bill", {"payee": BILLER_IBAN, "amount": "120.00"}
        )
    )

    arena = {
        "type": "arena_start",
        "scenario": "poisoned_bill",
        "rounds": 3,
        "lanes": ["classifier", "notary"],
        "seed": 0,
    }
    files["arena.seed0"] = answer(client.post("/playground/arena", json=arena))
    files["arena.cassette-miss"] = answer(
        client.post("/playground/arena", json={**arena, "seed": 1})
    )
    files["tools.specs"] = recorded(200, [spec.model_dump(mode="json") for spec in TOOL_SPECS])
    return files


def render(entry: JsonDict) -> str:
    return json.dumps(entry, indent=2, ensure_ascii=False) + "\n"


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Record the playground fixtures.")
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 on drift")
    args = parser.parse_args(argv)
    files = capture()
    if args.check:
        stale = [
            name
            for name, entry in files.items()
            if not (FIXTURE_DIR / f"{name}.json").is_file()
            or (FIXTURE_DIR / f"{name}.json").read_text() != render(entry)
        ]
        known = {f"{name}.json" for name in files}
        stale += [p.name for p in FIXTURE_DIR.glob("*.json") if p.name not in known]
        if stale:
            sys.stderr.write(f"playground fixtures are stale: {', '.join(sorted(stale))}\n")
            return 1
        return 0
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, entry in files.items():
        (FIXTURE_DIR / f"{name}.json").write_text(render(entry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
