import type { ValueRef } from "@notary/schema";

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
