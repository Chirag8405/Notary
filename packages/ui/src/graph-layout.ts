import type { GraphModel } from "./graph-model";

/**
 * Where each node of the provenance graph sits: three fixed columns, no physics, no randomness.
 *
 * - x = 0: source values (no derived edge points to them)
 * - x = 260: derived values (a derived edge points to them)
 * - x = 560: tool gates
 *
 * Within a column nodes keep the model's order, at y = 110 * index. A position depends only on
 * the node's id and its order, so adding events appends nodes without moving the ones before.
 * Never throws: an edge to an unknown id or to the node itself is harmless, and every node of the
 * model gets a position.
 */
const COLUMN_X = { source: 0, derived: 260, gate: 560 } as const;
const ROW_HEIGHT = 110;

export function layout(model: GraphModel): ReadonlyMap<string, { x: number; y: number }> {
  const derivedTargets = new Set(
    model.edges.filter((edge) => edge.kind === "derived").map((edge) => edge.to),
  );
  const used = { source: 0, derived: 0, gate: 0 };
  const positions = new Map<string, { x: number; y: number }>();
  for (const node of model.nodes) {
    const column =
      node.kind === "gate" ? "gate" : derivedTargets.has(node.id) ? "derived" : "source";
    positions.set(node.id, { x: COLUMN_X[column], y: ROW_HEIGHT * used[column] });
    used[column] += 1;
  }
  return positions;
}
