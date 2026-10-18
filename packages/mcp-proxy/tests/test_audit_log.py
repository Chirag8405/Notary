"""The durable audit chain: one file per run, written before the effect, with a head anchor."""

import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from builders import ACME_IBAN, RecordingBackend, make_gateway
from stdio_session import StdioSession, proxy_command, request, tool_call

from notary_core.audit import GENESIS_HASH, append, verify_chain, verify_chain_detailed
from notary_core.models import (
    AuditEntry,
    DecisionMade,
    EffectBudget,
    EffectExecuted,
    Event,
    IntentContract,
    Lane,
    RunFinished,
    RunStarted,
)
from notary_mcp_proxy.audit_log import (
    ANCHOR_SUFFIX,
    CHAIN_SUFFIX,
    AuditWriteError,
    ChainAnchor,
    RunLog,
    durable_append,
)
from notary_mcp_proxy.client import StdioClient
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.gateway import RawCall
from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.main import build_server

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
ATTACKER_IBAN = "DE00ATTACKER0000000001"


def read_chain(path: Path) -> list[AuditEntry]:
    return [AuditEntry.model_validate_json(line) for line in path.read_text().splitlines()]


def read_anchor(path: Path) -> ChainAnchor:
    return ChainAnchor.model_validate_json(path.read_text())


def bank_config(tmp_path: Path) -> Path:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    path = tmp_path / "notary.json"
    path.write_text(json.dumps(data))
    return path


def call(proxy_call_id: int, name: str, arguments: JsonObject) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": proxy_call_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def pay(call_id: str, payee: str) -> RawCall:
    return RawCall(call_id=call_id, tool="pay_bill", args={"payee": payee, "amount": "120.00"})


def test_the_chain_file_verifies_and_matches_its_anchor(tmp_path: Path) -> None:
    config = ProxyConfig.model_validate_json(bank_config(tmp_path).read_bytes())
    log = RunLog(tmp_path / "runs", "run-demo")
    client = StdioClient(config.server.command)
    try:
        proxy = build_server(config, client, run_id="run-demo", audit_append=durable_append(log))
        answers = [
            proxy.handle(call(1, "read_inbox", {})),
            proxy.handle(call(2, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120})),
            proxy.handle(call(3, "pay_bill", {"payee": ACME_IBAN, "amount": 120})),
        ]
        proxy.finish_run()
    finally:
        client.close()
        log.close()
    flags = [(a or {}).get("result") for a in answers]
    assert [r["isError"] for r in flags if isinstance(r, dict)] == [False, True, False]
    chain = read_chain(log.chain_path)
    assert verify_chain(chain)
    assert chain[0].index == 0
    assert isinstance(chain[0].event, RunStarted)
    assert chain[-1].event.type == "run_finished"
    anchor = read_anchor(log.anchor_path)
    assert anchor == log.anchor
    assert (anchor.run_id, anchor.length, anchor.head) == ("run-demo", len(chain), chain[-1].hash)
    assert verify_chain_detailed(chain, expected_length=anchor.length, expected_head=anchor.head).ok
    blocked = [
        e.event.decision.verdict for e in chain if isinstance(e.event, DecisionMade)
    ]
    assert blocked == ["ALLOW", "BLOCK", "ALLOW"]


@pytest.mark.invariant("I1")
def test_decision_is_on_disk_before_the_tool_runs(tmp_path: Path) -> None:
    log = RunLog(tmp_path, "run-1")
    backend = RecordingBackend()
    seen: list[list[str]] = []

    def probe() -> tuple[AuditEntry, ...]:
        seen.append([e.event.type for e in read_chain(log.chain_path)])
        return ()

    backend.probe = probe
    gateway = make_gateway(backend, audit_append=durable_append(log))
    outcome = gateway.propose(pay("c1", ACME_IBAN))
    assert outcome.status == "executed"
    assert len(seen) == 1
    assert seen[0][-1] == "decision_made"  # the ALLOW is already a line of the file
    assert "effect_executed" not in seen[0]
    assert verify_chain(read_chain(log.chain_path))
    log.close()


@pytest.mark.invariant("I1")
def test_a_failing_write_halts_the_gateway_and_the_tool_does_not_run(tmp_path: Path) -> None:
    broken = {"fsync": False}

    def sync(_fd: int) -> None:
        if broken["fsync"]:
            raise OSError("disk full")

    log = RunLog(tmp_path, "run-1", sync=sync)

    def inner(chain: Sequence[AuditEntry], event: Event) -> tuple[AuditEntry, ...]:
        broken["fsync"] = isinstance(event, DecisionMade)
        return append(chain, event)

    backend = RecordingBackend()
    gateway = make_gateway(backend, audit_append=durable_append(log, inner))
    first = gateway.propose(pay("c1", ACME_IBAN))
    assert (first.status, first.error) == ("halted", "audit append failed")
    assert backend.calls == []
    assert gateway.halted == "audit append failed"
    broken["fsync"] = False  # the disk recovers; the gateway and the log stay halted
    later = gateway.propose(RawCall(call_id="c2", tool="read_inbox", args={}))
    assert (later.status, later.error) == ("halted", "audit append failed")
    assert backend.calls == []
    assert gateway.emit(_finished) is False
    log.close()


def _finished(run: str, lane: Lane, seq: int) -> Event:
    return RunFinished(
        type="run_finished", run_id=run, lane=lane, seq=seq, outcome="error", summary="x"
    )


def test_a_removed_directory_fails_closed(tmp_path: Path) -> None:
    directory = tmp_path / "runs"
    log = RunLog(directory, "run-1")
    backend = RecordingBackend()
    gateway = make_gateway(backend, audit_append=durable_append(log))
    chain_file = log.chain_path
    chain_file.unlink()
    for child in directory.iterdir():
        child.unlink()
    directory.rmdir()
    outcome = gateway.propose(pay("c1", ACME_IBAN))
    assert outcome.status == "halted"
    assert backend.calls == []
    log.close()


def test_one_file_per_run(tmp_path: Path) -> None:
    first = RunLog(tmp_path, "run-a")
    second = RunLog(tmp_path, "run-b")
    assert first.chain_path != second.chain_path
    with pytest.raises(FileExistsError):
        RunLog(tmp_path, "run-a")
    first.close()
    second.close()
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        f"run-a{ANCHOR_SUFFIX}",
        f"run-a{CHAIN_SUFFIX}",
        f"run-b{ANCHOR_SUFFIX}",
        f"run-b{CHAIN_SUFFIX}",
    ]


@pytest.mark.parametrize("run_id", ["../x", "a/b", "", ".hidden", "a b"])
def test_run_id_must_be_a_safe_file_name(tmp_path: Path, run_id: str) -> None:
    with pytest.raises(ValueError, match="safe file name"):
        RunLog(tmp_path, run_id)


def test_the_anchor_is_valid_json_after_every_append(tmp_path: Path) -> None:
    log = RunLog(tmp_path, "run-1")
    assert read_anchor(log.anchor_path) == ChainAnchor(run_id="run-1", length=0, head=None)
    gateway = make_gateway(RecordingBackend(), audit_append=durable_append(log))
    assert gateway.chain == ()
    for call_id in ("c1", "c2"):
        gateway.propose(RawCall(call_id=call_id, tool="read_inbox", args={}))
        anchor = read_anchor(log.anchor_path)  # a half-written file would not parse
        assert anchor.length == len(gateway.chain)
        assert anchor.head == gateway.chain[-1].hash
    assert not list(tmp_path.glob("*.tmp"))
    log.close()


def test_an_entry_out_of_order_is_refused(tmp_path: Path) -> None:
    log = RunLog(tmp_path, "run-1")
    chain = append((), _started())
    two = append(chain, _started())
    with pytest.raises(AuditWriteError):
        log.write(two[-1])
    with pytest.raises(AuditWriteError):  # and the log stays failed
        log.write(chain[-1])
    log.close()


def _started() -> Event:
    contract = IntentContract(
        contract_id="c",
        user_intent="t",
        allowed_tools=(),
        budget=EffectBudget(
            max_effects=1,
            max_spend_cents=1,
            max_egress_bytes=1,
            max_call_amount_cents=1,
            max_approvals=1,
        ),
        egress_hosts=(),
        authorized_irreversible=(),
    )
    return RunStarted(
        type="run_started",
        run_id="r",
        lane="notary",
        seq=0,
        scenario="t",
        contract=contract,
        classifier=None,
    )


def test_the_empty_anchor_head_is_none_and_genesis_for_verification(tmp_path: Path) -> None:
    log = RunLog(tmp_path, "run-1")
    assert log.anchor.head is None
    assert verify_chain_detailed([], expected_length=0, expected_head=GENESIS_HASH).ok
    log.close()


def test_stdio_shutdown_writes_run_finished_and_prints_the_head(tmp_path: Path) -> None:
    audit = tmp_path / "audit"
    session = StdioSession(proxy_command(bank_config(tmp_path), "--audit-dir", str(audit)))
    session.send(request(1, "initialize", {"protocolVersion": "x"}))
    session.send(tool_call(2, "read_inbox", {}))
    session.send(tool_call(3, "pay_bill", {"payee": ATTACKER_IBAN, "amount": 120}))
    session.send(tool_call(4, "pay_bill", {"payee": ACME_IBAN, "amount": 120}))
    answers = [session.result(i)["isError"] for i in (2, 3, 4)]
    stderr = session.finish()
    assert answers == [False, True, False]
    (chain_file,) = audit.glob(f"*{CHAIN_SUFFIX}")
    (anchor_file,) = audit.glob(f"*{ANCHOR_SUFFIX}")
    chain = read_chain(chain_file)
    assert verify_chain(chain)
    assert chain[0].event.type == "run_started"
    assert chain[-1].event.type == "run_finished"
    anchor = read_anchor(anchor_file)
    assert (anchor.length, anchor.head) == (len(chain), chain[-1].hash)
    assert isinstance(chain[0].event, RunStarted)
    run_id = chain[0].event.run_id
    assert f"notary-mcp-proxy: run {run_id} closed: length {len(chain)} head {chain[-1].hash}" in (
        stderr
    )
    effects = [e.event.tool for e in chain if isinstance(e.event, EffectExecuted)]
    assert effects == ["read_inbox", "pay_bill"]


def test_the_proxy_refuses_to_start_when_the_log_cannot_be_created(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")
    done = subprocess.run(
        proxy_command(bank_config(tmp_path), "--audit-dir", str(blocker)),
        input=b"",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 2
    assert b"startup failed" in done.stderr
