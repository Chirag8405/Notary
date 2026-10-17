import {
  Background,
  ReactFlow,
  useNodesInitialized,
  useReactFlow,
  type EdgeTypes,
  type NodeTypes,
} from "@xyflow/react";
import { useEffect, useMemo } from "react";

import { layout } from "./graph-layout";
import { buildGraph } from "./graph-model";
import type { GateNode, GraphEdge, ValueNode } from "./graph-model";
import {
  GateNodeView,
  ModelEdgeView,
  SNAP_CSS,
  ValueNodeView,
  executedNote,
  gateNote,
  nodeName,
  shortPreview,
  type GateFlowNode,
  type ModelFlowEdge,
  type ValueFlowNode,
} from "./graph-nodes";
import type { RunView } from "./run-view";

export interface ProvenanceGraphProps {
  view: RunView;
  flaggedValueIds?: ReadonlySet<string>;
  /** A node id: "v:..." or "g:...". Selection is controlled; the component keeps none. */
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
}

const NODE_TYPES: NodeTypes = { value: ValueNodeView, gate: GateNodeView };
const EDGE_TYPES: EdgeTypes = { model: ModelEdgeView };

/** Room for the rows of the tallest column: a row is 110 units tall and is shown at about 60%. */
const MIN_HEIGHT = 380;
const MAX_HEIGHT = 720;

function panelHeight(positions: ReadonlyMap<string, { x: number; y: number }>): number {
  const lowest = Math.max(0, ...[...positions.values()].map((position) => position.y));
  return Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, Math.ceil((lowest + 90) * 0.6) + 40));
}

/**
 * Fits the whole graph in the panel, and again whenever a node appears or the panel changes size.
 * `fitView` as a prop only runs once, when the first node arrives (a single gate, shown huge).
 */
function FitOnChange({ signature }: { signature: string }) {
  const { fitView } = useReactFlow();
  const initialized = useNodesInitialized();
  useEffect(() => {
    if (initialized) void fitView({ padding: 0.2, maxZoom: 1 });
  }, [signature, initialized, fitView]);
  return null;
}

function edgeText(edge: GraphEdge): string {
  const label = edge.severed ? (edge.reasonCode ?? "blocked") : (edge.param ?? "derived");
  return `${edge.from} to ${edge.to}: ${label}`;
}

/** The graph of one run: what the model says, drawn on a canvas with a text list beside it. */
export function ProvenanceGraph({
  view,
  flaggedValueIds,
  selectedId = null,
  onSelect,
}: ProvenanceGraphProps) {
  const model = useMemo(
    () => buildGraph(view, flaggedValueIds === undefined ? {} : { flaggedValueIds }),
    [view, flaggedValueIds],
  );
  const positions = useMemo(() => layout(model), [model]);
  const height = useMemo(() => panelHeight(positions), [positions]);
  const signature = useMemo(
    () => `${model.nodes.map((node) => node.id).join(",")}|${height}`,
    [model, height],
  );

  const nodes = useMemo(
    () =>
      model.nodes.map((node): ValueFlowNode | GateFlowNode => {
        const position = positions.get(node.id) ?? { x: 0, y: 0 };
        const selected = node.id === selectedId;
        return node.kind === "value"
          ? { id: node.id, type: "value", position, data: { node, selected } }
          : { id: node.id, type: "gate", position, data: { node, selected } };
      }),
    [model, positions, selectedId],
  );
  const edges = useMemo(
    () =>
      model.edges.map((edge): ModelFlowEdge => ({
        id: edge.id,
        type: "model",
        source: edge.from,
        target: edge.to,
        data: { edge },
      })),
    [model],
  );

  if (model.nodes.length === 0) {
    return (
      <div className="w-full rounded border p-4" aria-label="Provenance graph">
        <p className="text-sm text-muted-foreground">No provenance yet</p>
      </div>
    );
  }

  return (
    <div className="w-full rounded border" aria-label="Provenance graph">
      <style>{SNAP_CSS}</style>
      <div className="min-h-[380px] w-full" style={{ height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          edgeTypes={EDGE_TYPES}
          fitView
          fitViewOptions={{ padding: 0.2, maxZoom: 1 }}
          minZoom={0.4}
          maxZoom={1.25}
          nodesDraggable={false}
          nodesConnectable={false}
          onNodeClick={(_event, node) => onSelect?.(node.id)}
          onPaneClick={() => onSelect?.(null)}
        >
          <Background />
          <FitOnChange signature={signature} />
        </ReactFlow>
      </div>
      <ul aria-label="Graph nodes" className="sr-only">
        {model.nodes.map((node) => (
          <li
            key={node.id}
            {...nodeAttributes(node, node.id === selectedId)}
            title={node.kind === "value" ? node.preview : undefined}
            onClick={() => onSelect?.(node.id)}
          >
            {nodeText(node)}
          </li>
        ))}
        {model.edges.map((edge) => (
          <li
            key={edge.id}
            data-edge={edge.id}
            data-kind={edge.kind}
            data-severed={edge.severed ? "true" : "false"}
          >
            {edgeText(edge)}
          </li>
        ))}
        {selectedId === null ? null : (
          <li>
            <button type="button" onClick={() => onSelect?.(null)}>
              Clear selection
            </button>
          </li>
        )}
      </ul>
    </div>
  );
}

function nodeAttributes(node: ValueNode | GateNode, selected: boolean) {
  const common = { "data-node-id": node.id, "data-selected": selected ? "true" : "false" };
  return node.kind === "value"
    ? {
        ...common,
        "data-node": "value",
        "data-tone": node.tone,
        "data-integrity": node.integrity,
        "data-flagged": node.flagged ? "true" : "false",
      }
    : { ...common, "data-node": "gate", "data-state": node.state };
}

function nodeText(node: ValueNode | GateNode): string {
  if (node.kind === "value") return `${nodeName(node)}: ${shortPreview(node.preview)}`;
  const parts = [nodeName(node), node.reasonCode, gateNote(node), executedNote(node)];
  return parts.filter((part): part is string => part !== null).join(" · ");
}
