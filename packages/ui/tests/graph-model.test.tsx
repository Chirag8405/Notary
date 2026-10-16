import { EventSchema } from "@notary/schema";
import type { Decision, Event, Reason } from "@notary/schema";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import * as ui from "../src";
import type {
  GateNode,
  GateState,
  GraphEdge,
  GraphModel,
  NodeIntegrity,
  NodeTone,
  ValueNode,
} from "../src";
import { buildGraph, edgeId, gateNodeId, toneOf, valueNodeId } from "../src/graph-model";
import { foldEvents } from "../src/run-view";
import type { CallView, RunView } from "../src/run-view";

const streamsDir = resolve(import.meta.dirname, "../../world/fixtures/streams");

/** A fresh parse each call, so a test may freeze or change what it gets. */
function load(name: string): Event[] {
  const text = readFileSync(resolve(streamsDir, `${name}.json`), "utf8");
  return EventSchema.array().parse(JSON.parse(text));
}

const STREAMS = [
  "poisoned_bill.undefended",
  "poisoned_bill.classifier",
  "poisoned_bill.notary",
  "legitimate_bill.notary",
] as const;

function graphOf(name: (typeof STREAMS)[number]): GraphModel {
  return buildGraph(foldEvents(load(name)));
}

function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`missing: ${what}`);
  return value;
}

function gates(model: GraphModel): GateNode[] {
  return model.nodes.filter((node): node is GateNode => node.kind === "gate");
}

function valueNodes(model: GraphModel): ValueNode[] {
  return model.nodes.filter((node): node is ValueNode => node.kind === "value");
}

function gate(model: GraphModel, callId: string): GateNode {
  return must(
    gates(model).find((node) => node.callId === callId),
    `gate ${callId}`,
  );
}

function value(model: GraphModel, valueId: string): ValueNode {
  return must(
    valueNodes(model).find((node) => node.valueId === valueId),
    `value ${valueId}`,
  );
}

function edgeOf(model: GraphModel, from: string, to: string, param: string | null): GraphEdge {
  return must(
    model.edges.find((edge) => edge.id === edgeId(from, to, param)),
    `edge ${from} -> ${to}`,
  );
}

function deepFreeze<T>(input: T): T {
  if (input !== null && typeof input === "object" && !Object.isFrozen(input)) {
    Object.freeze(input);
    for (const key of Object.keys(input)) deepFreeze((input as Record<string, unknown>)[key]);
  }
  return input;
}

/** A copy of `view` with one call changed (the real view is never touched). */
function withCall(view: RunView, callId: string, change: Partial<CallView>): RunView {
  return {
    ...view,
    calls: view.calls.map((call) => (call.callId === callId ? { ...call, ...change } : call)),
  };
}

function reason(overrides: Partial<Reason>): Reason {
  return {
    check: "origin",
    outcome: "fail",
    code: "ORIGIN_UNTRUSTED",
    detail: "",
    ...overrides,
  };
}

function block(reasons: Reason[]): Decision {
  return { verdict: "BLOCK", reasons, diff_card: null };
}

const NOTARY = foldEvents(load("poisoned_bill.notary"));

describe("toneOf", () => {
  it("covers every origin kind [I2]", () => {
    const expected: Record<string, NodeTone> = {
      user: "user",
      ledger: "ledger",
      tool: "tool",
      email: "tool",
      file: "tool",
      web: "tool",
      llm: "other",
    };
    for (const [kind, tone] of Object.entries(expected)) expect(toneOf(kind)).toBe(tone);
    expect(toneOf("something_new")).toBe("other");
  });
});

describe("golden streams as graphs", () => {
  it("draws the NOTARY poisoned stream with an escalated, unsevered gate [A3]", () => {
    const model = graphOf("poisoned_bill.notary");
    expect(valueNodes(model).map((node) => node.id)).toEqual([
      "v:v-email-body",
      "v:v-payee",
      "v:v-amount",
    ]);
    expect(gates(model).map((node) => [node.id, node.tool, node.state])).toEqual([
      ["g:c1", "read_inbox", "allow"],
      ["g:c2", "pay_bill", "escalate"],
    ]);
    expect(gate(model, "c1")).toMatchObject({ reasonCode: "READ_ONLY_UNGATED", executed: true });
    expect(gate(model, "c2")).toMatchObject({
      reasonCode: "LEDGER_NOVEL_ESCALATE",
      executed: false,
    });

    const payee = value(model, "v-payee");
    expect(payee).toMatchObject({ tone: "tool", originKind: "email", integrity: "untrusted" });
    expect(payee.preview).not.toBe("");
    expect(value(model, "v-amount")).toMatchObject({ tone: "user", integrity: "trusted" });

    const payeeEdge = edgeOf(model, "v:v-payee", "g:c2", "payee");
    expect(payeeEdge).toMatchObject({ kind: "argument", severed: false, reasonCode: null });
    expect(model.edges.some((edge) => edge.severed)).toBe(false);
  });

  it("draws a derived edge from the pointed-at value and none for a pointer to itself [A3]", () => {
    const model = graphOf("poisoned_bill.notary");
    const derived = model.edges.filter((edge) => edge.kind === "derived");
    // v-payee points into v-email-body; v-email-body points at itself, which draws nothing.
    expect(derived.map((edge) => [edge.from, edge.to, edge.param])).toEqual([
      ["v:v-email-body", "v:v-payee", null],
    ]);
  });

  it("draws the legitimate stream with two allowed gates [I1]", () => {
    const model = graphOf("legitimate_bill.notary");
    expect(gates(model).map((node) => [node.callId, node.state, node.executed])).toEqual([
      ["c1", "allow", true],
      ["c2", "allow", true],
    ]);
    // The payee's label in this stream is email / untrusted, so its tone is the amber tool tone.
    // What lets the payment through is the ledger match the monitor reports (corroboration), which
    // a label does not carry; so the model shows an untrusted node on an allowed gate.
    expect(value(model, "v-payee")).toMatchObject({
      tone: "tool",
      originKind: "email",
      integrity: "untrusted",
    });
    expect(model.edges.some((edge) => edge.severed)).toBe(false);
    expect(gate(model, "c2").reasonCode).toBe("STEP_PASS");
  });

  it("leaves the baseline lanes ungated and executed [A3]", () => {
    for (const name of ["poisoned_bill.undefended", "poisoned_bill.classifier"] as const) {
      const model = graphOf(name);
      expect(gates(model).map((node) => [node.callId, node.state, node.executed])).toEqual([
        ["c1", "ungated", true],
        ["c2", "ungated", true],
      ]);
      expect(gates(model).every((node) => node.reasonCode === null)).toBe(true);
      expect(model.edges.some((edge) => edge.severed)).toBe(false);
      // v-payee points into a value these lanes never show, so no derived edge is drawn.
      expect(model.edges.filter((edge) => edge.kind === "derived")).toEqual([]);
      expect(valueNodes(model).map((node) => node.valueId)).toEqual(["v-amount", "v-payee"]);
    }
  });
});

describe("gate states and severed edges", () => {
  it("a BLOCK severs the edge whose parameter the failing reason names [A4]", () => {
    const failing = reason({
      check: "corroboration",
      code: "LEDGER_NOT_FOUND",
      detail: "payee is not in the ledger",
    });
    const view = withCall(NOTARY, "c2", { decision: block([failing]) });
    const model = buildGraph(view);
    expect(gate(model, "c2")).toMatchObject({ state: "block", reasonCode: "LEDGER_NOT_FOUND" });
    expect(edgeOf(model, "v:v-payee", "g:c2", "payee")).toMatchObject({
      severed: true,
      reasonCode: "LEDGER_NOT_FOUND",
    });
    expect(edgeOf(model, "v:v-amount", "g:c2", "amount")).toMatchObject({
      severed: false,
      reasonCode: null,
    });
  });

  it("falls back to the untrusted argument edges when no reason names a parameter [A4]", () => {
    const failing = reason({ code: "ORIGIN_UNTRUSTED", detail: "argument is not trusted" });
    const model = buildGraph(withCall(NOTARY, "c2", { decision: block([failing]) }));
    expect(edgeOf(model, "v:v-payee", "g:c2", "payee").severed).toBe(true);
    expect(edgeOf(model, "v:v-amount", "g:c2", "amount").severed).toBe(false);
    expect(edgeOf(model, "v:v-payee", "g:c2", "payee").reasonCode).toBe("ORIGIN_UNTRUSTED");
  });

  it("matches parameter names as whole words only [A4]", () => {
    const sever = (detail: string): boolean => {
      const failing = reason({ detail });
      const model = buildGraph(withCall(NOTARY, "c2", { decision: block([failing]) }));
      // A naming reason severs only that edge; the fallback severs the untrusted payee edge, so
      // use the trusted amount parameter as the probe for a real match.
      return edgeOf(model, "v:v-amount", "g:c2", "amount").severed;
    };
    expect(sever("amount exceeds the budget")).toBe(true);
    expect(sever("amount: 120.00")).toBe(true);
    expect(sever("(amount)")).toBe(true);
    expect(sever("amount_cents exceeds the budget")).toBe(false);
    expect(sever("preamount exceeds the budget")).toBe(false);
    expect(sever("total_amount")).toBe(false);
  });

  it("counts only failing reasons when it looks for a named parameter [A4]", () => {
    const passing = reason({ outcome: "pass", code: "STEP_PASS", detail: "amount is fine" });
    const failing = reason({ detail: "payee is not trusted" });
    const model = buildGraph(withCall(NOTARY, "c2", { decision: block([passing, failing]) }));
    expect(edgeOf(model, "v:v-payee", "g:c2", "payee").severed).toBe(true);
    expect(edgeOf(model, "v:v-amount", "g:c2", "amount").severed).toBe(false);
  });

  it("severs nothing for escalate, allow, pending and ungated gates [A3]", () => {
    const allow: Decision = { verdict: "ALLOW", reasons: [], diff_card: null };
    const states: [string, RunView][] = [
      ["escalate", NOTARY],
      ["allow", withCall(NOTARY, "c2", { decision: allow })],
      ["pending", { ...withCall(NOTARY, "c2", { decision: null }), finished: null }],
      ["ungated", withCall(NOTARY, "c2", { decision: null })],
    ];
    for (const [state, view] of states) {
      const model = buildGraph(view);
      expect(
        model.edges.some((edge) => edge.severed),
        state,
      ).toBe(false);
    }
  });

  it("shows allow when an escalation was approved and decided again [A3]", () => {
    const earlier = must(NOTARY.calls[1]?.decision, "the escalation");
    const allow: Decision = { verdict: "ALLOW", reasons: [], diff_card: null };
    const view = withCall(NOTARY, "c2", {
      decision: allow,
      decidedSeq: 12,
      decisionHistory: [{ decision: earlier, seq: 7 }],
    });
    const node = gate(buildGraph(view), "c2");
    expect(node.state).toBe("allow");
    expect(node.reasonCode).toBeNull();
  });

  it("follows the pending and ungated rules [I6]", () => {
    const undecided = withCall(NOTARY, "c2", { decision: null, decidedSeq: null });
    // notary lane, no decision, run unfinished: pending
    expect(gate(buildGraph({ ...undecided, finished: null }), "c2").state).toBe("pending");
    // notary lane, no decision, run finished: ungated
    expect(gate(buildGraph(undecided), "c2").state).toBe("ungated");
    // another lane, no decision, run unfinished: ungated
    const baseline = foldEvents(load("poisoned_bill.classifier").slice(0, 4));
    expect(baseline.finished).toBeNull();
    expect(gate(buildGraph(baseline), "c2").state).toBe("ungated");
    // a call with a decision is never ungated, whatever the lane
    const decided = { ...NOTARY, lane: "undefended" as const };
    expect(gate(buildGraph(decided), "c2").state).toBe("escalate");
  });

  it("keeps a blocked gate blocked even when it executed [A4]", () => {
    const failing = reason({ detail: "payee is not trusted" });
    const view = withCall(NOTARY, "c2", {
      decision: block([failing]),
      executed: { summary: "paid", seq: 9 },
    });
    expect(gate(buildGraph(view), "c2")).toMatchObject({ state: "block", executed: true });
  });
});

describe("derived edges and flags", () => {
  it("draws no derived edge, and does not throw, for a missing source [A3]", () => {
    const view: RunView = {
      ...NOTARY,
      values: NOTARY.values.filter((item) => item.ref.id !== "v-email-body"),
    };
    const model = buildGraph(view);
    expect(model.edges.filter((edge) => edge.kind === "derived")).toEqual([]);
    expect(valueNodes(model).map((node) => node.valueId)).toEqual(["v-payee", "v-amount"]);
  });

  it("flags only the ids passed in the options [A1]", () => {
    expect(valueNodes(buildGraph(NOTARY)).some((node) => node.flagged)).toBe(false);
    const flagged = buildGraph(NOTARY, { flaggedValueIds: new Set(["v-payee"]) });
    expect(
      valueNodes(flagged)
        .filter((node) => node.flagged)
        .map((n) => n.valueId),
    ).toEqual(["v-payee"]);
    const none = buildGraph(NOTARY, { flaggedValueIds: new Set(["nope"]) });
    expect(valueNodes(none).some((node) => node.flagged)).toBe(false);
  });
});

describe("stability and purity", () => {
  it("keeps node and edge ids stable as events arrive [I6]", () => {
    for (const name of STREAMS) {
      const events = load(name);
      let previous = new Set<string>();
      for (let k = 0; k <= events.length; k += 1) {
        const model = buildGraph(foldEvents(events.slice(0, k)));
        const ids = new Set([...model.nodes, ...model.edges].map((item) => item.id));
        for (const id of previous) expect(ids.has(id), `${name} k=${k} lost ${id}`).toBe(true);
        previous = ids;
      }
    }
  });

  it("is deterministic [I6]", () => {
    for (const name of STREAMS) {
      expect(graphOf(name)).toEqual(graphOf(name));
    }
    const first = buildGraph(NOTARY);
    const second = buildGraph(NOTARY);
    expect(first).toEqual(second);
    expect(first.nodes).not.toBe(second.nodes);
    expect(first.edges).not.toBe(second.edges);
  });

  it("orders values, gates and edges deterministically [I6]", () => {
    const shuffled: RunView = {
      ...NOTARY,
      values: [...NOTARY.values].reverse(),
      calls: [...NOTARY.calls].reverse(),
    };
    expect(buildGraph(shuffled)).toEqual(buildGraph(NOTARY));
    const model = buildGraph(shuffled);
    const kinds = model.nodes.map((node) => node.kind);
    expect(kinds).toEqual([...kinds].sort((a, b) => (a === b ? 0 : a === "value" ? -1 : 1)));
    // Argument edges follow gate order then parameter name; derived edges come last.
    expect(model.edges.map((edge) => edge.id)).toEqual([
      edgeId("v:v-amount", "g:c2", "amount"),
      edgeId("v:v-payee", "g:c2", "payee"),
      edgeId("v:v-email-body", "v:v-payee", null),
    ]);
  });

  it("orders values by seq then id and calls by proposed seq then id [I6]", () => {
    const sample = must(NOTARY.values[0], "a value");
    const tie = (id: string, seq: number): RunView["values"][number] => ({
      ...sample,
      seq,
      ref: { ...sample.ref, id },
    });
    const callSample = must(NOTARY.calls[0], "a call");
    const view: RunView = {
      ...NOTARY,
      values: [tie("b", 5), tie("a", 5), tie("z", 1)],
      calls: [
        { ...callSample, callId: "y", proposedSeq: 2, args: {} },
        { ...callSample, callId: "x", proposedSeq: 2, args: {} },
        { ...callSample, callId: "w", proposedSeq: 1, args: {} },
      ],
    };
    const model = buildGraph(view);
    expect(model.nodes.map((node) => node.id)).toEqual(["v:z", "v:a", "v:b", "g:w", "g:x", "g:y"]);
  });

  it("does not mutate the view [I6]", () => {
    const view = deepFreeze(foldEvents(load("poisoned_bill.notary")));
    const snapshot = JSON.stringify(view);
    expect(() => buildGraph(view, { flaggedValueIds: new Set(["v-payee"]) })).not.toThrow();
    expect(JSON.stringify(view)).toBe(snapshot);
  });

  it("skips an argument whose value has no node, without throwing [I6]", () => {
    const view: RunView = {
      ...NOTARY,
      values: NOTARY.values.filter((item) => item.ref.id !== "v-amount"),
    };
    const model = buildGraph(view);
    expect(model.edges.map((edge) => edge.param)).toEqual(["payee", null]);
  });
});

describe("exports", () => {
  it("exports the model from the package index [I6]", () => {
    expect(ui.buildGraph).toBe(buildGraph);
    expect(ui.toneOf).toBe(toneOf);
    expect(ui.valueNodeId("x")).toBe("v:x");
    expect(ui.gateNodeId("c1")).toBe("g:c1");
    expect(ui.edgeId("v:a", "g:c1", "payee")).toBe("e:v:a->g:c1:payee");
    expect(valueNodeId("x")).toBe("v:x");
    expect(gateNodeId("c1")).toBe("g:c1");
    const sample: {
      tone: NodeTone;
      integrity: NodeIntegrity;
      state: GateState;
      model: GraphModel | null;
    } = { tone: "user", integrity: "trusted", state: "allow", model: null };
    expect(sample.model).toBeNull();
  });
});
