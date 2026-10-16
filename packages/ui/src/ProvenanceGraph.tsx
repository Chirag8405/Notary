import { Background, Controls, ReactFlow, type Edge, type Node } from "@xyflow/react";

// Placeholder topology: untrusted email -> extracted payee -> proposed call.
const NODES: Node[] = [
  { id: "email", position: { x: 0, y: 0 }, data: { label: "email (untrusted)" } },
  { id: "payee", position: { x: 220, y: 0 }, data: { label: "payee value" } },
  { id: "call", position: { x: 440, y: 0 }, data: { label: "pay_bill call" } },
];
const EDGES: Edge[] = [
  { id: "email-payee", source: "email", target: "payee" },
  { id: "payee-call", source: "payee", target: "call" },
];

export function ProvenanceGraph() {
  return (
    <div className="h-64 w-full rounded border" aria-label="Provenance graph">
      <ReactFlow
        nodes={NODES}
        edges={EDGES}
        fitView
        nodesDraggable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
