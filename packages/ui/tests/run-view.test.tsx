import { EventSchema } from "@notary/schema";
import type { Event } from "@notary/schema";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import * as ui from "../src";
import type {
  CallView,
  DecisionRecord,
  EndorsementView,
  LaneName,
  RunView,
  ValueView,
} from "../src";
import { emptyRunView, foldEvents, reduceEvent } from "../src/run-view";

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

function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`missing: ${what}`);
  return value;
}

function pick<T extends Event["type"]>(
  events: readonly Event[],
  type: T,
  nth = 0,
): Extract<Event, { type: T }> {
  const matches = events.filter(
    (event): event is Extract<Event, { type: T }> => event.type === type,
  );
  return must(matches[nth], `${type} #${nth}`);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}

/** The same events, with every value_labeled moved to just after the last call_proposed. */
function labelsAfterCalls(events: readonly Event[]): Event[] {
  const labels = events.filter((event) => event.type === "value_labeled");
  const rest = events.filter((event) => event.type !== "value_labeled");
  const lastCall = rest.map((event) => event.type).lastIndexOf("call_proposed");
  const ordered = [...rest.slice(0, lastCall + 1), ...labels, ...rest.slice(lastCall + 1)];
  return ordered.map((event, seq) => ({ ...event, seq }));
}

describe("foldEvents on the golden streams", () => {
  it("folds the NOTARY poisoned stream [A3]", () => {
    const events = load("poisoned_bill.notary");
    const view = foldEvents(events);
    const started = pick(events, "run_started");
    const finished = pick(events, "run_finished");
    const endorsement = pick(events, "endorsement_requested").endorsement;

    expect(view.runId).toBe(started.run_id);
    expect(view.scenario).toBe(started.scenario);
    expect(view.lane).toBe("notary");
    expect(view.classifier).toBeNull();
    expect(view.contract).toEqual(started.contract);
    expect(view.calls).toHaveLength(2);
    expect(view.calls.map((call) => call.callId)).toEqual(["c1", "c2"]);
    expect(view.calls[0]?.decision?.verdict).toBe("ALLOW");
    expect(view.calls[0]?.executed?.summary).toBe(pick(events, "effect_executed").summary);
    const second = must(view.calls[1], "second call");
    expect(second.decision?.verdict).toBe("ESCALATE");
    expect(second.endorsementId).toBe(endorsement.endorsement_id);
    expect(second.executed).toBeNull();
    expect(view.endorsements).toHaveLength(1);
    expect(view.endorsements[0]?.endorsement).toEqual(endorsement);
    expect(view.oracle).not.toBeNull();
    expect(view.finished?.outcome).toBe(finished.outcome);
    expect(view.finished?.summary).toBe(finished.summary);
    expect(view.anomalies).toEqual([]);
    expect(view.lastSeq).toBe(10);
    // Two values were labeled before the call that uses them; the amount is only an argument.
    expect(view.values.map((value) => [value.ref.id, value.labeled])).toEqual([
      ["v-email-body", true],
      ["v-payee", true],
      ["v-amount", false],
    ]);
  });

  it("folds the legitimate stream [I1]", () => {
    const view = foldEvents(load("legitimate_bill.notary"));
    expect(view.calls).toHaveLength(2);
    expect(view.calls.map((call) => call.decision?.verdict)).toEqual(["ALLOW", "ALLOW"]);
    expect(view.calls.every((call) => call.executed !== null)).toBe(true);
    expect(view.endorsements).toEqual([]);
    expect(view.oracle).not.toBeNull();
    expect(view.finished?.outcome).toBe("completed");
    expect(view.anomalies).toEqual([]);
  });

  it("folds the baseline streams without decisions [A3]", () => {
    for (const name of ["poisoned_bill.undefended", "poisoned_bill.classifier"] as const) {
      const events = load(name);
      const view = foldEvents(events);
      expect(view.lane).toBe(name.endsWith("undefended") ? "undefended" : "classifier");
      expect(view.calls).toHaveLength(2);
      for (const call of view.calls) {
        expect(call.decision).toBeNull();
        expect(call.decidedSeq).toBeNull();
        expect(call.executed).not.toBeNull();
      }
      const argIds = events.flatMap((event) =>
        event.type === "call_proposed"
          ? Object.entries(event.proposal.args)
              .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
              .map(([, ref]) => ref.id)
          : [],
      );
      expect(view.values.map((value) => value.ref.id)).toEqual([...new Set(argIds)]);
      expect(view.values.every((value) => !value.labeled && value.preview === "")).toBe(true);
      expect(view.endorsements).toEqual([]);
      expect(view.anomalies).toEqual([]);
    }
  });

  it("enriches a value in place when its label arrives after its call [I6]", () => {
    const events = labelsAfterCalls(load("poisoned_bill.notary"));
    const firstLabel = events.findIndex((event) => event.type === "value_labeled");
    const before = foldEvents(events.slice(0, firstLabel));
    const labeled = pick(events, "value_labeled", 1);
    const position = before.values.findIndex((value) => value.ref.id === labeled.value.id);
    expect(position).toBeGreaterThanOrEqual(0);
    const earlier = must(before.values[position], "value before its label");
    expect(earlier.labeled).toBe(false);
    expect(earlier.preview).toBe("");

    const after = must(foldEvents(events).values[position], "value after its label");
    expect(after.ref.id).toBe(labeled.value.id);
    expect(after.labeled).toBe(true);
    expect(after.preview).toBe(labeled.preview);
    expect(after.unit).toBe(labeled.unit);
    expect(after.seq).toBe(earlier.seq);
  });

  it("incremental reduce equals batch fold for every prefix [I6]", () => {
    for (const name of STREAMS) {
      const events = load(name);
      const steps: RunView[] = [emptyRunView];
      for (const event of events) {
        steps.push(reduceEvent(must(steps[steps.length - 1], "previous step"), event));
      }
      for (let k = 0; k <= events.length; k += 1) {
        expect(foldEvents(events.slice(0, k))).toEqual(steps[k]);
      }
      for (let split = 0; split <= events.length; split += 1) {
        const head = events.slice(0, split);
        const tail = events.slice(split);
        expect(foldEvents(head.concat(tail))).toEqual(tail.reduce(reduceEvent, foldEvents(head)));
      }
    }
  });
});

describe("reduceEvent is pure", () => {
  it("does not mutate its input [I6]", () => {
    for (const name of STREAMS) {
      const events = deepFreeze(load(name));
      let view: RunView = deepFreeze(foldEvents([]));
      for (const event of events) {
        const snapshot = JSON.stringify(view);
        const eventSnapshot = JSON.stringify(event);
        const next = reduceEvent(view, event);
        expect(JSON.stringify(view)).toBe(snapshot);
        expect(JSON.stringify(event)).toBe(eventSnapshot);
        view = deepFreeze(next);
      }
    }
  });

  it("returns fresh containers and never holds the event's objects [I6]", () => {
    const events = load("poisoned_bill.notary");
    const before = foldEvents(events.slice(0, 8));
    const event = must(events[8], "next event");
    const after = reduceEvent(before, event);
    expect(after).not.toBe(before);
    expect(after.values).not.toBe(before.values);
    expect(after.calls).not.toBe(before.calls);
    expect(after.endorsements).not.toBe(before.endorsements);
    expect(after.anomalies).not.toBe(before.anomalies);
    expect(after.calls[0]).not.toBe(before.calls[0]);
    const started = pick(events, "run_started");
    expect(foldEvents(events).contract).not.toBe(started.contract);
    expect(emptyRunView.values).toEqual([]);
  });

  it("is pure: two folds are deep-equal and the input array is unchanged [I6]", () => {
    const events = load("poisoned_bill.notary");
    const snapshot = JSON.stringify(events);
    const first = foldEvents(events);
    const second = foldEvents(events);
    expect(first).toEqual(second);
    expect(first.values).not.toBe(second.values);
    expect(first.calls).not.toBe(second.calls);
    expect(JSON.stringify(events)).toBe(snapshot);
  });
});

describe("anomalies", () => {
  const events = load("poisoned_bill.notary");
  const base = foldEvents(events);
  const nextSeq = base.lastSeq + 1;

  it("records a decision for an unknown call [I6]", () => {
    const synthetic: Event = { ...pick(events, "decision_made"), call_id: "c404", seq: nextSeq };
    const next = reduceEvent(base, synthetic);
    expect(next.calls).toEqual(base.calls);
    expect(next.anomalies).toEqual([`decision_made for unknown call c404 (seq ${nextSeq})`]);
  });

  it("records an effect for an unknown call [I6]", () => {
    const synthetic: Event = { ...pick(events, "effect_executed"), call_id: "c404", seq: nextSeq };
    const next = reduceEvent(base, synthetic);
    expect(next.calls).toEqual(base.calls);
    expect(next.anomalies).toEqual([`effect_executed for unknown call c404 (seq ${nextSeq})`]);
  });

  it("stores an endorsement for an unknown call and records it [I6]", () => {
    const requested = pick(events, "endorsement_requested");
    const synthetic: Event = {
      ...requested,
      seq: nextSeq,
      endorsement: { ...requested.endorsement, endorsement_id: "e9", call_id: "c404" },
    };
    const next = reduceEvent(base, synthetic);
    expect(next.endorsements.map((item) => item.endorsement.endorsement_id)).toEqual(["e1", "e9"]);
    expect(next.anomalies).toEqual([
      `endorsement_requested for unknown call c404 (seq ${nextSeq})`,
    ]);
  });

  it("ignores a repeated call id [I6]", () => {
    const proposed = pick(events, "call_proposed");
    const next = reduceEvent(base, { ...proposed, seq: nextSeq });
    expect(next.calls).toEqual(base.calls);
    expect(next.anomalies).toEqual([
      `duplicate call ${proposed.proposal.call_id} (seq ${nextSeq})`,
    ]);
  });

  it("ignores a duplicate or stale frame with one anomaly [I6]", () => {
    const replayed = must(events[3], "an applied event");
    const once = reduceEvent(base, replayed);
    expect(once.anomalies).toEqual([`stale or duplicate event ignored (seq ${replayed.seq})`]);
    expect({ ...once, anomalies: [] }).toEqual(base);
    const twice = reduceEvent(foldEvents(events.slice(0, 4)), replayed);
    expect(twice.anomalies).toHaveLength(1);
    expect(twice.lastSeq).toBe(replayed.seq);
  });

  it("ignores events of another run with one anomaly [I6]", () => {
    const foreign: Event = { ...pick(events, "oracle_updated"), run_id: "run-other", seq: nextSeq };
    const next = reduceEvent(base, foreign);
    expect(next.anomalies).toEqual([`event for other run run-other ignored (seq ${nextSeq})`]);
    expect({ ...next, anomalies: [] }).toEqual(base);
  });

  it("flags a repeated run_started of the same run [I6]", () => {
    const started = pick(events, "run_started");
    const next = reduceEvent(base, { ...started, seq: nextSeq });
    expect(next.anomalies).toEqual([
      `duplicate run_started for run ${started.run_id} (seq ${nextSeq})`,
    ]);
    expect({ ...next, anomalies: [] }).toEqual(base);
  });

  it("starts a fresh view when another run starts [I6]", () => {
    const started: Event = {
      ...pick(events, "run_started"),
      run_id: "run-other",
      scenario: "other_scenario",
      seq: 0,
    };
    const reset = reduceEvent(base, started);
    expect(reset.runId).toBe("run-other");
    expect(reset.scenario).toBe("other_scenario");
    expect(reset.calls).toEqual([]);
    expect(reset.values).toEqual([]);
    expect(reset.endorsements).toEqual([]);
    expect(reset.oracle).toBeNull();
    expect(reset.finished).toBeNull();
    expect(reset.anomalies).toEqual([]);
    expect(reset.lastSeq).toBe(0);
    const call: Event = { ...pick(events, "call_proposed"), run_id: "run-other", seq: 1 };
    expect(reduceEvent(reset, call).calls).toHaveLength(1);
  });

  it("keeps the first ref when a label differs and ignores a second label [I6]", () => {
    const stream = labelsAfterCalls(events);
    const firstLabel = stream.findIndex((event) => event.type === "value_labeled");
    const view = foldEvents(stream.slice(0, firstLabel));
    // The payee label: it is a call argument, so an unlabeled copy exists before it arrives.
    const label = pick(stream, "value_labeled", 1);
    const tampered: Event = {
      ...label,
      seq: view.lastSeq + 1,
      value: { ...label.value, content_hash: "0".repeat(64) },
    };
    const next = reduceEvent(view, tampered);
    const stored = must(
      next.values.find((value) => value.ref.id === label.value.id),
      "value",
    );
    const original = must(
      view.values.find((value) => value.ref.id === label.value.id),
      "value",
    );
    expect(stored.ref).toEqual(original.ref);
    expect(stored.labeled).toBe(true);
    expect(stored.preview).toBe(label.preview);
    expect(next.anomalies).toEqual([
      `value ${label.value.id} label differs from its first sighting (seq ${tampered.seq})`,
    ]);
    const again = reduceEvent(next, { ...label, seq: next.lastSeq + 1 });
    expect(again.anomalies).toEqual([
      ...next.anomalies,
      `value ${label.value.id} labeled again (seq ${next.lastSeq + 1})`,
    ]);
    expect({ ...again, anomalies: [], lastSeq: 0 }).toEqual({ ...next, anomalies: [], lastSeq: 0 });
  });
});

describe("decisions and effects", () => {
  it("a later decision replaces the first and keeps history [A3]", () => {
    const events = load("poisoned_bill.notary");
    const base = foldEvents(events);
    const original = pick(events, "decision_made", 1);
    const approved: Event = {
      ...original,
      seq: base.lastSeq + 1,
      decision: { verdict: "ALLOW", reasons: [], diff_card: null },
    };
    const next = reduceEvent(base, approved);
    const call = must(
      next.calls.find((item) => item.callId === original.call_id),
      "call",
    );
    expect(call.decision?.verdict).toBe("ALLOW");
    expect(call.decidedSeq).toBe(approved.seq);
    expect(call.decisionHistory).toEqual([{ decision: original.decision, seq: original.seq }]);
    expect(next.anomalies).toEqual([]);

    const effect: Event = {
      ...pick(events, "effect_executed", 0),
      call_id: original.call_id,
      summary: "paid after approval",
      seq: next.lastSeq + 1,
    };
    const executed = reduceEvent(next, effect);
    const done = must(
      executed.calls.find((item) => item.callId === original.call_id),
      "call",
    );
    expect(done.executed).toEqual({ summary: "paid after approval", seq: effect.seq });
    expect(executed.anomalies).toEqual([]);
  });

  it("starts every call with an empty decision history [A3]", () => {
    const view = foldEvents(load("poisoned_bill.notary"));
    expect(view.calls.every((call) => call.decisionHistory.length === 0)).toBe(true);
  });
});

describe("ordering", () => {
  it("keeps sorted argument insertion and first-seen values [I6]", () => {
    const events = load("poisoned_bill.notary");
    const proposed = pick(events, "call_proposed", 1);
    const payee = must(proposed.proposal.args.payee, "payee ref");
    const amount = must(proposed.proposal.args.amount, "amount ref");
    const synthetic: Event = {
      ...proposed,
      seq: 1,
      proposal: {
        ...proposed.proposal,
        call_id: "c9",
        args: { zeta: { ...payee, id: "v-zeta" }, alpha: { ...amount, id: "v-alpha" } },
      },
    };
    const view = foldEvents([{ ...pick(events, "run_started"), seq: 0 }, synthetic]);
    expect(view.values.map((value) => value.ref.id)).toEqual(["v-alpha", "v-zeta"]);
    expect(Object.keys(must(view.calls[0], "call").args)).toEqual(["alpha", "zeta"]);

    const full = foldEvents(events);
    const seqs = full.calls.map((call) => call.proposedSeq);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    const valueSeqs = full.values.map((value) => value.seq);
    expect(valueSeqs).toEqual([...valueSeqs].sort((a, b) => a - b));
  });

  it("never throws on any order, and an event that does not advance seq only adds one anomaly [I6]", () => {
    // Tiny seeded LCG, so the shuffles are the same on every run.
    let state = 20260101;
    const random = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };
    for (const name of STREAMS) {
      const events = load(name);
      for (let round = 0; round < 200; round += 1) {
        const order = [...events];
        for (let i = order.length - 1; i > 0; i -= 1) {
          const j = random() % (i + 1);
          const a = must(order[i], "item");
          const b = must(order[j], "item");
          order[i] = b;
          order[j] = a;
        }
        // Exact invariant: an event either advances lastSeq (applied) or leaves the view equal
        // except for exactly one new anomaly (ignored), so applied + ignored === events.length.
        let view: RunView = emptyRunView;
        let applied = 0;
        let ignored = 0;
        for (const event of order) {
          const next = reduceEvent(view, event);
          if (next.lastSeq === view.lastSeq) {
            ignored += 1;
            expect(next.anomalies).toHaveLength(view.anomalies.length + 1);
            expect({ ...next, anomalies: [] }).toEqual({ ...view, anomalies: [] });
          } else {
            applied += 1;
            expect(next.lastSeq).toBeGreaterThan(view.lastSeq);
          }
          view = next;
        }
        expect(applied + ignored).toBe(events.length);
      }
    }
  });
});

describe("exhaustiveness and exports", () => {
  function label(event: Event): string {
    switch (event.type) {
      case "run_started":
      case "value_labeled":
      case "call_proposed":
      case "decision_made":
      case "effect_executed":
      case "endorsement_requested":
      case "oracle_updated":
      case "run_finished":
        return event.type;
      default:
        return assertNever(event);
    }
  }

  function assertNever(value: never): never {
    throw new Error(`Unhandled event: ${JSON.stringify(value)}`);
  }

  it("handles every event type [I6]", () => {
    const events = load("poisoned_bill.notary");
    expect(new Set(events.map(label)).size).toBe(8);
    const started = pick(events, "run_started");
    for (const event of events) {
      expect(() => reduceEvent(reduceEvent(emptyRunView, started), event)).not.toThrow();
    }
  });

  it("exports everything from the package index [I6]", () => {
    expect(ui.foldEvents).toBe(foldEvents);
    expect(ui.reduceEvent).toBe(reduceEvent);
    expect(ui.emptyRunView).toBe(emptyRunView);
    const view: RunView = ui.foldEvents(load("poisoned_bill.notary"));
    const call: CallView | undefined = view.calls[0];
    const value: ValueView | undefined = view.values[0];
    const endorsement: EndorsementView | undefined = view.endorsements[0];
    const lane: LaneName | null = view.lane;
    const history: readonly DecisionRecord[] = call?.decisionHistory ?? [];
    expect([call?.callId, value?.ref.id, endorsement?.seq, lane, history.length]).toEqual([
      "c1",
      "v-email-body",
      8,
      "notary",
      0,
    ]);
  });
});
