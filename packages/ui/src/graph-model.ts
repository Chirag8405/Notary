import type { Decision, Reason, ValueRef } from "@notary/schema";

import type { CallView, RunView, ValueView } from "./run-view";

/**
 * The provenance graph as data: what the center of the Trust X-ray draws. A later component only
 * renders this model, so the BLOCK and ESCALATE visuals can be tested on the golden streams
 * without a DOM. Pure and deterministic: no React, layout positions, clock or randomness.
 */

/** Green user, blue ledger, amber tool content, grey anything else. */
export type NodeTone = "user" | "ledger" | "tool" | "other";

export type NodeIntegrity = ValueRef["label"]["integrity"];

export interface ValueNode {
  kind: "value";
  /** `v:<valueId>`. */
  id: string;
  valueId: string;
  tone: NodeTone;
  /** The origin `kind` of the value's label (user, tool, email, file, web, ledger or llm). */
  originKind: string;
  /** Carried through, so an untrusted value stays distinguishable on a green origin. */
  integrity: NodeIntegrity;
  /** Empty while the value has only been seen as a call argument. */
  preview: string;
  /** True only for an id passed in `flaggedValueIds` (events carry no classifier flags). */
  flagged: boolean;
}

/** `ungated` is a lane without a monitor: the call has no decision to show. */
export type GateState = "pending" | "allow" | "escalate" | "block" | "ungated";

export interface GateNode {
  kind: "gate";
  /** `g:<callId>`. */
  id: string;
  callId: string;
  tool: string;
  state: GateState;
  /** The headline reason code of the latest decision; null when there is no decision. */
  reasonCode: string | null;
  executed: boolean;
}

export interface GraphEdge {
  /** `e:<from>-><to>:<param>`; the parameter is empty for a derived edge. */
  id: string;
  from: string;
  to: string;
  kind: "argument" | "derived";
  /** The argument name for an argument edge, null for a derived edge. */
  param: string | null;
  /** A BLOCK snaps the edge that caused it. */
  severed: boolean;
  /** The headline reason code, carried only by a severed edge. */
  reasonCode: string | null;
}

export interface GraphModel {
  /** All value nodes first, then all gate nodes. */
  nodes: readonly (ValueNode | GateNode)[];
  /** Argument edges first, then derived edges. */
  edges: readonly GraphEdge[];
}

export function toneOf(originKind: string): NodeTone {
  switch (originKind) {
    case "user":
      return "user";
    case "ledger":
      return "ledger";
    case "tool":
    case "email":
    case "file":
    case "web":
      return "tool";
    default:
      return "other";
  }
}

export function valueNodeId(valueId: string): string {
  return `v:${valueId}`;
}

export function gateNodeId(callId: string): string {
  return `g:${callId}`;
}

export function edgeId(from: string, to: string, param: string | null): string {
  return `e:${from}->${to}:${param ?? ""}`;
}

// --- buildGraph

const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function compareNumberThenText(an: number, bn: number, at: string, bt: string): number {
  return an !== bn ? an - bn : compareText(at, bt);
}

function isIdentifierChar(char: string): boolean {
  return /^[A-Za-z0-9_]$/.test(char);
}

/**
 * Whether `detail` mentions `param` as a whole word: the characters on both sides of a match must
 * not be identifier characters, so "payee" matches "payee is not in the ledger" but not
 * "payee_id" or "prepayee". A manual scan, so no parameter name is ever used as a pattern.
 */
function namesParameter(detail: string, param: string): boolean {
  if (param === "") return false;
  let from = 0;
  for (;;) {
    const at = detail.indexOf(param, from);
    if (at < 0) return false;
    const before = at === 0 ? "" : detail.charAt(at - 1);
    const after = detail.charAt(at + param.length);
    if (!isIdentifierChar(before) && !isIdentifierChar(after)) return true;
    from = at + 1;
  }
}

/** The first reason that is not a pass, else the last one, else null. */
function headline(reasons: readonly Reason[]): Reason | null {
  return reasons.find((reason) => reason.outcome !== "pass") ?? reasons.at(-1) ?? null;
}

function verdictState(verdict: Decision["verdict"]): GateState {
  switch (verdict) {
    case "ALLOW":
      return "allow";
    case "ESCALATE":
      return "escalate";
    case "BLOCK":
      return "block";
  }
}

/** A call with a decision is never ungated; one without is ungated off the notary lane or once done. */
function gateState(call: CallView, view: RunView): GateState {
  if (call.decision !== null) return verdictState(call.decision.verdict);
  return view.lane !== "notary" || view.finished !== null ? "ungated" : "pending";
}

/**
 * The argument names whose edge a BLOCK severs: those named by a failing reason, or, when no
 * failing reason names any, those whose value is untrusted. Nothing is severed for other states.
 */
function severedParams(
  call: CallView,
  state: GateState,
  params: readonly string[],
  values: ReadonlyMap<string, ValueView>,
): ReadonlySet<string> {
  if (state !== "block" || call.decision === null) return new Set();
  const failing = call.decision.reasons.filter((reason) => reason.outcome === "fail");
  const named = params.filter((param) => failing.some((r) => namesParameter(r.detail, param)));
  if (named.length > 0) return new Set(named);
  return new Set(
    params.filter((param) => {
      const ref = call.args[param];
      return ref !== undefined && values.get(ref.id)?.ref.label.integrity === "untrusted";
    }),
  );
}

/**
 * Build the provenance graph of a run: a node per value and per proposed call, an argument edge
 * from each value to its call, and a derived edge from the source of a span pointer.
 *
 * Ids are deterministic and never change as events arrive, and the order is fixed: values by
 * first-seen seq then id, calls by proposed seq then id. The gate state follows the LATEST
 * decision (`CallView.decision`), so an approved escalation shows `allow`.
 */
export function buildGraph(
  view: RunView,
  options: { flaggedValueIds?: ReadonlySet<string> } = {},
): GraphModel {
  const values = [...view.values].sort((a, b) =>
    compareNumberThenText(a.seq, b.seq, a.ref.id, b.ref.id),
  );
  const calls = [...view.calls].sort((a, b) =>
    compareNumberThenText(a.proposedSeq, b.proposedSeq, a.callId, b.callId),
  );
  const valuesById = new Map(values.map((value) => [value.ref.id, value] as const));

  const valueNodes: ValueNode[] = values.map((value) => ({
    kind: "value",
    id: valueNodeId(value.ref.id),
    valueId: value.ref.id,
    tone: toneOf(value.ref.label.origin.kind),
    originKind: value.ref.label.origin.kind,
    integrity: value.ref.label.integrity,
    preview: value.preview,
    flagged: options.flaggedValueIds?.has(value.ref.id) === true,
  }));

  const gateNodes: GateNode[] = [];
  const argumentEdges: GraphEdge[] = [];
  for (const call of calls) {
    const state = gateState(call, view);
    const reasonCode =
      call.decision === null ? null : (headline(call.decision.reasons)?.code ?? null);
    const gate = gateNodeId(call.callId);
    gateNodes.push({
      kind: "gate",
      id: gate,
      callId: call.callId,
      tool: call.tool,
      state,
      reasonCode,
      executed: call.executed !== null,
    });
    const params = Object.keys(call.args).sort(compareText);
    const severed = severedParams(call, state, params, valuesById);
    for (const param of params) {
      const ref = call.args[param];
      const value = ref === undefined ? undefined : valuesById.get(ref.id);
      if (value === undefined) continue;
      const from = valueNodeId(value.ref.id);
      const cut = severed.has(param);
      argumentEdges.push({
        id: edgeId(from, gate, param),
        from,
        to: gate,
        kind: "argument",
        param,
        severed: cut,
        reasonCode: cut ? reasonCode : null,
      });
    }
  }

  const derivedEdges: GraphEdge[] = [];
  for (const value of values) {
    const pointer = value.ref.label.span_pointer;
    if (pointer === null) continue;
    // A pointer to a value that was never seen, or to the value itself, draws nothing.
    if (pointer.source_value_id === value.ref.id || !valuesById.has(pointer.source_value_id)) {
      continue;
    }
    const from = valueNodeId(pointer.source_value_id);
    const to = valueNodeId(value.ref.id);
    derivedEdges.push({
      id: edgeId(from, to, null),
      from,
      to,
      kind: "derived",
      param: null,
      severed: false,
      reasonCode: null,
    });
  }

  return { nodes: [...valueNodes, ...gateNodes], edges: [...argumentEdges, ...derivedEdges] };
}
