import type {
  Decision,
  Endorsement,
  Event,
  IntentContract,
  OracleResult,
  ValueRef,
} from "@notary/schema";

/**
 * RunView: one shared, tested view of a run, folded from the event stream.
 *
 * Pure and deterministic: no React, clock, randomness or formatting. Every type is derived from
 * the schema, so a contract change shows up here as a compile error.
 */

export type LaneName = Event["lane"];

type ValueLabeledEvent = Extract<Event, { type: "value_labeled" }>;
type RunFinishedEvent = Extract<Event, { type: "run_finished" }>;

export interface ValueView {
  ref: ValueRef;
  /** Empty while the value has only been seen as a call argument. */
  preview: string;
  unit: ValueLabeledEvent["unit"];
  /** The first event that introduced the value. */
  seq: number;
  /** True once a `value_labeled` event arrived. */
  labeled: boolean;
}

export interface DecisionRecord {
  decision: Decision;
  seq: number;
}

export interface CallView {
  callId: string;
  tool: string;
  manifestHash: string;
  args: Readonly<Record<string, ValueRef>>;
  proposedSeq: number;
  /** The latest decision; null on the baseline lanes, which have none. */
  decision: Decision | null;
  decidedSeq: number | null;
  /** Earlier decisions of the same call, oldest first (an approved escalation is decided again). */
  decisionHistory: readonly DecisionRecord[];
  executed: { summary: string; seq: number } | null;
  endorsementId: string | null;
}

export interface EndorsementView {
  endorsement: Endorsement;
  seq: number;
}

export interface RunView {
  runId: string | null;
  scenario: string | null;
  lane: LaneName | null;
  classifier: string | null;
  contract: IntentContract | null;
  /** First-seen order. */
  values: readonly ValueView[];
  /** Ascending `proposedSeq`. */
  calls: readonly CallView[];
  /** First-seen order. */
  endorsements: readonly EndorsementView[];
  oracle: OracleResult | null;
  finished: { outcome: RunFinishedEvent["outcome"]; summary: string; seq: number } | null;
  /** The largest seq applied; -1 when nothing has been. */
  lastSeq: number;
  /** One deterministic string per ignored or inconsistent event. */
  anomalies: readonly string[];
}

export const emptyRunView: RunView = Object.freeze({
  runId: null,
  scenario: null,
  lane: null,
  classifier: null,
  contract: null,
  values: Object.freeze([]),
  calls: Object.freeze([]),
  endorsements: Object.freeze([]),
  oracle: null,
  finished: null,
  lastSeq: -1,
  anomalies: Object.freeze([]),
});

// --- reducer

type CallProposedEvent = Extract<Event, { type: "call_proposed" }>;
type DecisionMadeEvent = Extract<Event, { type: "decision_made" }>;
type EffectExecutedEvent = Extract<Event, { type: "effect_executed" }>;
type EndorsementRequestedEvent = Extract<Event, { type: "endorsement_requested" }>;
type OracleUpdatedEvent = Extract<Event, { type: "oracle_updated" }>;
type RunStartedEvent = Extract<Event, { type: "run_started" }>;

/** A RunView whose containers can be edited while one event is applied. */
interface Draft {
  runId: string | null;
  scenario: string | null;
  lane: LaneName | null;
  classifier: string | null;
  contract: IntentContract | null;
  values: ValueView[];
  calls: CallView[];
  endorsements: EndorsementView[];
  oracle: OracleResult | null;
  finished: RunView["finished"];
  lastSeq: number;
  anomalies: string[];
}

/** Fresh containers for everything in `view`, so the result never aliases the previous view. */
function freshen(view: RunView): Draft {
  return {
    ...view,
    values: view.values.map((value) => ({ ...value })),
    calls: view.calls.map((call) => ({
      ...call,
      args: { ...call.args },
      decisionHistory: call.decisionHistory.map((record) => ({ ...record })),
      executed: call.executed === null ? null : { ...call.executed },
    })),
    endorsements: view.endorsements.map((endorsement) => ({ ...endorsement })),
    finished: view.finished === null ? null : { ...view.finished },
    anomalies: [...view.anomalies],
  };
}

function cloneUnknown(value: unknown): unknown {
  if (Array.isArray(value)) return (value as readonly unknown[]).map(cloneUnknown);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    // fromEntries defines own properties, so a key such as "__proto__" stays plain data.
    return Object.fromEntries(Object.keys(record).map((key) => [key, cloneUnknown(record[key])]));
  }
  return value;
}

/** Deep copy of plain JSON data, so the view never holds an object that belongs to an event. */
function clonePlain<T>(value: T): T {
  return cloneUnknown(value) as T;
}

/** Structural equality for plain JSON data (key order does not matter). */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    const left = a as readonly unknown[];
    const right = b as readonly unknown[];
    return left.length === right.length && left.every((item, i) => deepEqual(item, right[i]));
  }
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => Object.hasOwn(right, key) && deepEqual(left[key], right[key]))
  );
}

function byName(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function note(draft: Draft, message: string): void {
  draft.anomalies.push(message);
}

function findCall(draft: Draft, callId: string): { call: CallView; index: number } | null {
  const index = draft.calls.findIndex((call) => call.callId === callId);
  const call = index < 0 ? undefined : draft.calls[index];
  return call === undefined ? null : { call, index };
}

function applyRunStarted(draft: Draft, event: RunStartedEvent): void {
  draft.runId = event.run_id;
  draft.scenario = event.scenario;
  draft.lane = event.lane;
  draft.classifier = event.classifier;
  draft.contract = clonePlain(event.contract);
}

function applyValueLabeled(draft: Draft, event: ValueLabeledEvent): void {
  const id = event.value.id;
  const index = draft.values.findIndex((value) => value.ref.id === id);
  const existing = index < 0 ? undefined : draft.values[index];
  if (existing === undefined) {
    draft.values.push({
      ref: clonePlain(event.value),
      preview: event.preview,
      unit: event.unit,
      seq: event.seq,
      labeled: true,
    });
    return;
  }
  if (existing.labeled) {
    note(draft, `value ${id} labeled again (seq ${event.seq})`);
    return;
  }
  if (!deepEqual(existing.ref, event.value)) {
    note(draft, `value ${id} label differs from its first sighting (seq ${event.seq})`);
  }
  draft.values[index] = { ...existing, preview: event.preview, unit: event.unit, labeled: true };
}

function applyCallProposed(draft: Draft, event: CallProposedEvent): void {
  const proposal = event.proposal;
  if (findCall(draft, proposal.call_id) !== null) {
    note(draft, `duplicate call ${proposal.call_id} (seq ${event.seq})`);
    return;
  }
  const entries = Object.entries(proposal.args)
    .sort(([a], [b]) => byName(a, b))
    .map(([name, ref]) => [name, clonePlain(ref)] as const);
  for (const [, ref] of entries) {
    if (!draft.values.some((value) => value.ref.id === ref.id)) {
      draft.values.push({
        ref: clonePlain(ref),
        preview: "",
        unit: null,
        seq: event.seq,
        labeled: false,
      });
    }
  }
  draft.calls.push({
    callId: proposal.call_id,
    tool: proposal.tool,
    manifestHash: proposal.manifest_hash,
    args: Object.fromEntries(entries),
    proposedSeq: event.seq,
    decision: null,
    decidedSeq: null,
    decisionHistory: [],
    executed: null,
    endorsementId: null,
  });
}

function applyDecisionMade(draft: Draft, event: DecisionMadeEvent): void {
  const found = findCall(draft, event.call_id);
  if (found === null) {
    note(draft, `decision_made for unknown call ${event.call_id} (seq ${event.seq})`);
    return;
  }
  const { call, index } = found;
  const history =
    call.decision === null
      ? call.decisionHistory
      : [
          ...call.decisionHistory,
          { decision: call.decision, seq: call.decidedSeq ?? call.proposedSeq },
        ];
  draft.calls[index] = {
    ...call,
    decision: clonePlain(event.decision),
    decidedSeq: event.seq,
    decisionHistory: history,
  };
}

function applyEffectExecuted(draft: Draft, event: EffectExecutedEvent): void {
  const found = findCall(draft, event.call_id);
  if (found === null) {
    note(draft, `effect_executed for unknown call ${event.call_id} (seq ${event.seq})`);
    return;
  }
  draft.calls[found.index] = {
    ...found.call,
    executed: { summary: event.summary, seq: event.seq },
  };
}

function applyEndorsementRequested(draft: Draft, event: EndorsementRequestedEvent): void {
  const endorsement = clonePlain(event.endorsement);
  const view: EndorsementView = { endorsement, seq: event.seq };
  const index = draft.endorsements.findIndex(
    (item) => item.endorsement.endorsement_id === endorsement.endorsement_id,
  );
  if (index < 0) draft.endorsements.push(view);
  else draft.endorsements[index] = view;
  const found = findCall(draft, endorsement.call_id);
  if (found === null) {
    note(draft, `endorsement_requested for unknown call ${endorsement.call_id} (seq ${event.seq})`);
    return;
  }
  draft.calls[found.index] = { ...found.call, endorsementId: endorsement.endorsement_id };
}

function applyOracleUpdated(draft: Draft, event: OracleUpdatedEvent): void {
  draft.oracle = clonePlain(event.result);
}

function applyRunFinished(draft: Draft, event: RunFinishedEvent): void {
  draft.finished = { outcome: event.outcome, summary: event.summary, seq: event.seq };
}

function apply(draft: Draft, event: Event): Draft {
  draft.lastSeq = event.seq;
  switch (event.type) {
    case "run_started":
      applyRunStarted(draft, event);
      return draft;
    case "value_labeled":
      applyValueLabeled(draft, event);
      return draft;
    case "call_proposed":
      applyCallProposed(draft, event);
      return draft;
    case "decision_made":
      applyDecisionMade(draft, event);
      return draft;
    case "effect_executed":
      applyEffectExecuted(draft, event);
      return draft;
    case "endorsement_requested":
      applyEndorsementRequested(draft, event);
      return draft;
    case "oracle_updated":
      applyOracleUpdated(draft, event);
      return draft;
    case "run_finished":
      applyRunFinished(draft, event);
      return draft;
    default:
      return assertNever(event);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unhandled event: ${JSON.stringify(value)}`);
}

function ignored(view: RunView, message: string): RunView {
  const draft = freshen(view);
  note(draft, message);
  return draft;
}

/**
 * Apply one event. Never mutates its arguments and returns a new view with fresh containers.
 *
 * Rule order: a `run_started` of another run resets the view; otherwise an event of another run,
 * a stale or duplicate seq, or a repeated `run_started` is ignored with exactly one anomaly.
 */
export function reduceEvent(view: RunView, event: Event): RunView {
  if (event.type === "run_started" && view.runId !== null && event.run_id !== view.runId) {
    return apply(freshen(emptyRunView), event);
  }
  if (view.runId !== null && event.run_id !== view.runId) {
    return ignored(view, `event for other run ${event.run_id} ignored (seq ${event.seq})`);
  }
  if (event.seq <= view.lastSeq) {
    return ignored(view, `stale or duplicate event ignored (seq ${event.seq})`);
  }
  if (event.type === "run_started" && view.runId !== null) {
    return ignored(view, `duplicate run_started for run ${event.run_id} (seq ${event.seq})`);
  }
  return apply(freshen(view), event);
}

/** Fold a whole stream; `foldEvents(a.concat(b))` equals `b.reduce(reduceEvent, foldEvents(a))`. */
export function foldEvents(events: readonly Event[]): RunView {
  return events.reduce(reduceEvent, freshen(emptyRunView));
}
