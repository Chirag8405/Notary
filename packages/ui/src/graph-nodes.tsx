import {
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  Position,
  getStraightPath,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from "@xyflow/react";

import type { GateNode, GateState, GraphEdge, NodeTone, ValueNode } from "./graph-model";

/**
 * The custom React Flow nodes and edge of the provenance graph. They draw a `GraphModel`; they
 * never recompute a tone, a state or a reason code.
 */

export const PREVIEW_LIMIT = 24;

export type ValueFlowNode = Node<{ node: ValueNode; selected: boolean }, "value">;
export type GateFlowNode = Node<{ node: GateNode; selected: boolean }, "gate">;
export type ModelFlowEdge = Edge<{ edge: GraphEdge }, "model">;

/** The accessible name of a node: "<tone> value <originKind>, <integrity>" or "<tool> gate, <state>". */
export function nodeName(node: ValueNode | GateNode): string {
  return node.kind === "value"
    ? `${node.tone} value ${node.originKind}, ${node.integrity}`
    : `${node.tool} gate, ${node.state}`;
}

/** The first `PREVIEW_LIMIT` characters of a preview, with an ellipsis when it was cut. */
export function shortPreview(preview: string): string {
  return preview.length > PREVIEW_LIMIT ? `${preview.slice(0, PREVIEW_LIMIT)}…` : preview;
}

/** The short note a gate shows for its state, if any. */
export function gateNote(node: GateNode): string | null {
  if (node.state === "escalate") return "awaiting confirmation";
  if (node.state === "ungated") return "no check";
  return null;
}

/** A gate that ran is marked; one that ran despite a BLOCK is called out as an anomaly. */
export function executedNote(node: GateNode): string | null {
  if (!node.executed) return null;
  return node.state === "block" ? "executed despite block" : "executed";
}

const TONE_CLASS: Record<NodeTone, string> = {
  user: "border-green-500 bg-green-50 text-green-900",
  ledger: "border-blue-500 bg-blue-50 text-blue-900",
  tool: "border-amber-500 bg-amber-50 text-amber-900",
  other: "border-neutral-400 bg-neutral-50 text-neutral-800",
};

const GATE_CLASS: Record<GateState, string> = {
  allow: "border-green-600 bg-green-100 text-green-900",
  escalate: "border-yellow-500 bg-yellow-100 text-yellow-900",
  block: "border-red-600 bg-red-100 text-red-900",
  ungated: "border-neutral-400 bg-neutral-100 text-neutral-700",
  pending: "border-dashed border-neutral-400 bg-white text-neutral-700",
};

const RING = "ring-2 ring-indigo-500 ring-offset-1";
const FLAGGED = "outline outline-2 outline-red-500";

/** A value on the canvas: coloured by origin, outlined when a classifier flagged it. */
export function ValueNodeView({ data }: NodeProps<ValueFlowNode>) {
  const { node, selected } = data;
  const classes = [
    "w-48 rounded border-2 px-2 py-1 text-xs shadow-sm",
    TONE_CLASS[node.tone],
    node.flagged ? FLAGGED : "",
    selected ? RING : "",
  ];
  return (
    <div
      data-node="value"
      data-tone={node.tone}
      data-integrity={node.integrity}
      data-flagged={node.flagged ? "true" : "false"}
      data-selected={selected ? "true" : "false"}
      aria-label={nodeName(node)}
      title={node.preview}
      className={classes.filter(Boolean).join(" ")}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="font-semibold">
        {node.originKind} <span className="font-normal">({node.integrity})</span>
      </div>
      <div className="truncate font-mono">{shortPreview(node.preview)}</div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}

/** A tool gate on the canvas: its state is the colour, with a text badge. */
export function GateNodeView({ data }: NodeProps<GateFlowNode>) {
  const { node, selected } = data;
  const note = gateNote(node);
  const executed = executedNote(node);
  const classes = [
    "w-48 rounded border-2 px-2 py-1 text-xs shadow-sm",
    GATE_CLASS[node.state],
    selected ? RING : "",
  ];
  return (
    <div
      data-node="gate"
      data-state={node.state}
      data-executed={node.executed ? "true" : "false"}
      data-selected={selected ? "true" : "false"}
      aria-label={nodeName(node)}
      className={classes.filter(Boolean).join(" ")}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="font-semibold">{node.tool}</div>
      <div>
        <span className="rounded bg-white/60 px-1 uppercase">{node.state}</span>
        {node.reasonCode === null ? null : (
          <span className="ml-1 font-mono">{node.reasonCode}</span>
        )}
      </div>
      {note === null ? null : <div>{note}</div>}
      {executed === null ? null : <div>{executed}</div>}
    </div>
  );
}

/** CSS for the snap of a severed edge: motion only when the user has not asked for less. */
export const SNAP_CSS = `
@media (prefers-reduced-motion: no-preference) {
  .notary-severed-stub { animation: notary-snap 400ms ease-out 1; }
}
@keyframes notary-snap { from { stroke-width: 6px; } to { stroke-width: 2px; } }
`;

/**
 * Every model edge. An argument edge is solid and labelled with its parameter; a derived edge is
 * dashed; a severed edge is two stubs with a gap, labelled with its reason code.
 */
export function ModelEdgeView(props: EdgeProps<ModelFlowEdge>) {
  const { id, sourceX, sourceY, targetX, targetY, data } = props;
  if (data === undefined) return null;
  const { edge } = data;
  const label = edge.severed ? (edge.reasonCode ?? "blocked") : (edge.param ?? "");
  const centerX = (sourceX + targetX) / 2;
  const centerY = (sourceY + targetY) / 2;
  const labelStyle = { transform: `translate(-50%, -50%) translate(${centerX}px, ${centerY}px)` };
  const labelClass = edge.severed
    ? "pointer-events-none absolute rounded bg-red-100 px-1 font-mono text-[10px] text-red-800"
    : "pointer-events-none absolute rounded bg-white px-1 text-[10px] text-neutral-600";

  const labelNode =
    label === "" ? null : (
      <EdgeLabelRenderer>
        <div
          data-edge-label={edge.id}
          data-severed={edge.severed ? "true" : "false"}
          className={labelClass}
          style={labelStyle}
        >
          {label}
        </div>
      </EdgeLabelRenderer>
    );

  if (!edge.severed) {
    const [path] = getStraightPath({ sourceX, sourceY, targetX, targetY });
    return (
      <>
        <BaseEdge
          id={id}
          path={path}
          style={{
            stroke: "#737373",
            strokeWidth: 2,
            ...(edge.kind === "derived" ? { strokeDasharray: "6 4" } : {}),
          }}
        />
        {labelNode}
      </>
    );
  }

  // The stubs end 40% and start 60% of the way along the line; the gap is the break.
  const at = (t: number): [number, number] => [
    sourceX + (targetX - sourceX) * t,
    sourceY + (targetY - sourceY) * t,
  ];
  const [x1, y1] = at(0.4);
  const [x2, y2] = at(0.6);
  const [first] = getStraightPath({ sourceX, sourceY, targetX: x1, targetY: y1 });
  const [second] = getStraightPath({ sourceX: x2, sourceY: y2, targetX, targetY });
  const stub = { stroke: "#dc2626", strokeWidth: 2 };
  return (
    <>
      <BaseEdge id={`${id}:a`} path={first} className="notary-severed-stub" style={stub} />
      <BaseEdge id={`${id}:b`} path={second} className="notary-severed-stub" style={stub} />
      {labelNode}
    </>
  );
}
