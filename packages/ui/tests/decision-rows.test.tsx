import type { Decision, Reason } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { decisionSummary, headlineReason, shortHash, toDecisionRows } from "../src/decision-rows";
import { describeEvent } from "../src/describe-event";
import type { RunView } from "../src/run-view";
import { STREAMS, load, must, viewOf } from "./golden";

function reason(outcome: Reason["outcome"], code: string): Reason {
  return { check: "origin", outcome, code, detail: `${code} detail` } as Reason;
}

function withDecisions(view: RunView, callId: string, decisions: Decision[]): RunView {
  const latest = must(decisions[decisions.length - 1], "a decision");
  const earlier = decisions.slice(0, -1);
  return {
    ...view,
    calls: view.calls.map((call) =>
      call.callId === callId
        ? {
            ...call,
            decision: latest,
            decisionHistory: earlier.map((decision, i) => ({ decision, seq: 100 + i })),
          }
        : call,
    ),
  };
}

function deepFreeze<T>(input: T): T {
  if (input !== null && typeof input === "object" && !Object.isFrozen(input)) {
    Object.freeze(input);
    for (const key of Object.keys(input)) deepFreeze((input as Record<string, unknown>)[key]);
  }
  return input;
}

describe("toDecisionRows on the golden streams", () => {
  it("maps the NOTARY poisoned stream [A3]", () => {
    const rows = toDecisionRows(viewOf("poisoned_bill.notary"));
    expect(rows.map((r) => [r.callId, r.tool, r.verdict])).toEqual([
      ["c1", "read_inbox", "ALLOW"],
      ["c2", "pay_bill", "ESCALATE"],
    ]);
    const pay = must(rows[1], "row 2");
    expect(pay.headlineReason?.code).toBe("LEDGER_NOVEL_ESCALATE");
    expect(pay.headlineReason?.outcome).toBe("escalate");
    expect(pay.endorsementId).toBe("e1");
    expect(pay.executed).toBeNull();
    expect(pay.reasons.map((r) => r.check)).toEqual([
      "scope",
      "irreversibility",
      "origin",
      "corroboration",
      "confidentiality",
      "budget",
    ]);
    expect(pay.args.map((a) => [a.param, a.originKind, a.integrity, a.originName])).toEqual([
      ["amount", "user", "trusted", null],
      ["payee", "email", "untrusted", null],
    ]);
    for (const chip of pay.args) expect(chip.hashShort).toMatch(/^[0-9a-f]{8}$/);
    const read = must(rows[0], "row 1");
    expect(read.args).toEqual([]);
    expect(read.headlineReason?.code).toBe("READ_ONLY_UNGATED");
    expect(read.executed).toBe("read 2 messages");
  });

  it("maps the legitimate stream: both allowed and executed [I1]", () => {
    const rows = toDecisionRows(viewOf("legitimate_bill.notary"));
    expect(rows.map((r) => r.verdict)).toEqual(["ALLOW", "ALLOW"]);
    expect(rows.every((r) => r.endorsementId === null)).toBe(true);
    expect(rows.every((r) => r.executed !== null)).toBe(true);
    // All reasons pass, so the headline is the last one; the ledger match is the corroboration reason.
    expect(rows[1]?.headlineReason?.check).toBe("budget");
    expect(rows[1]?.reasons.map((r) => r.code)).toContain("LEDGER_EXACT_MATCH");
  });

  it("gives the baseline lanes no verdicts [A3]", () => {
    for (const name of ["poisoned_bill.undefended", "poisoned_bill.classifier"] as const) {
      const rows = toDecisionRows(viewOf(name));
      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(row.verdict).toBeNull();
        expect(row.reasons).toEqual([]);
        expect(row.headlineReason).toBeNull();
        expect(row.executed).not.toBeNull();
      }
    }
  });

  it("keeps the received order of the reasons [I6]", () => {
    for (const name of STREAMS) {
      const view = viewOf(name);
      for (const row of toDecisionRows(view)) {
        const call = must(
          view.calls.find((c) => c.callId === row.callId),
          row.callId,
        );
        expect(row.reasons).toEqual(call.decision === null ? [] : call.decision.reasons);
      }
    }
  });

  it("builds the legacy summary like describeEvent [I6]", () => {
    for (const name of STREAMS) {
      const real = load(name).filter((e) => e.type === "decision_made");
      for (const event of real) {
        expect(decisionSummary(event.call_id, event.decision.verdict)).toBe(describeEvent(event));
      }
    }
  });
});

describe("row helpers", () => {
  it("picks the first non-pass reason, else the last [I6]", () => {
    const pass = reason("pass", "A");
    const escalate = reason("escalate", "B");
    const fail = reason("fail", "C");
    expect(headlineReason([pass, escalate, fail])).toBe(escalate);
    expect(headlineReason([pass, reason("pass", "D")])?.code).toBe("D");
    expect(headlineReason([])).toBeNull();
  });

  it("shortens hashes with or without a prefix [I6]", () => {
    expect(shortHash("a7247cf810d6f264")).toBe("a7247cf8");
    expect(shortHash("sha256:a7247cf810d6f264")).toBe("a7247cf8");
    expect(shortHash("ab")).toBe("ab");
  });

  it("uses the latest decision and lists the earlier ones [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const escalate = must(base.calls[1]?.decision, "the escalation");
    const allow: Decision = {
      verdict: "ALLOW",
      reasons: [reason("pass", "STEP_PASS")],
      diff_card: null,
    };
    const rows = toDecisionRows(withDecisions(base, "c2", [escalate, allow]));
    const row = must(rows[1], "row 2");
    expect(row.verdict).toBe("ALLOW");
    expect(row.earlierDecisions).toEqual([
      { verdict: "ESCALATE", headlineReason: escalate.reasons[3], seq: 100 },
    ]);
    expect(must(toDecisionRows(base)[1], "row").earlierDecisions).toEqual([]);
  });

  it("keeps a tool origin's name and tolerates a missing preview [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const call = must(base.calls[1], "c2");
    const payee = must(call.args.payee, "payee");
    const toolRef = {
      ...payee,
      label: { ...payee.label, origin: { kind: "tool" as const, name: "read_file" } },
    };
    const view: RunView = {
      ...base,
      values: base.values.filter((v) => v.ref.id !== payee.id),
      calls: base.calls.map((c) =>
        c.callId === "c2" ? { ...c, args: { ...c.args, payee: toolRef } } : c,
      ),
    };
    const chip = must(
      toDecisionRows(view)[1]?.args.find((a) => a.param === "payee"),
      "chip",
    );
    expect(chip).toMatchObject({
      originKind: "tool",
      originName: "read_file",
      preview: "",
      valueId: payee.id,
    });
  });

  it("orders by proposed seq then call id [I6]", () => {
    const base = viewOf("poisoned_bill.notary");
    const [a, b] = [must(base.calls[0], "c1"), must(base.calls[1], "c2")];
    const view: RunView = {
      ...base,
      calls: [
        { ...b, callId: "y", proposedSeq: 5 },
        { ...a, callId: "x", proposedSeq: 5 },
        { ...a, callId: "w", proposedSeq: 1 },
      ],
    };
    expect(toDecisionRows(view).map((r) => r.callId)).toEqual(["w", "x", "y"]);
  });

  it("is pure [I6]", () => {
    const view = deepFreeze(viewOf("poisoned_bill.notary"));
    const first = toDecisionRows(view);
    const second = toDecisionRows(view);
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
  });
});
