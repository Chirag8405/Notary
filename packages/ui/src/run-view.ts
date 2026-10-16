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
