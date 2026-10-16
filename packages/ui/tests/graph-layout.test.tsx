import { describe, expect, it } from "vitest";

import { layout } from "../src/graph-layout";
import { buildGraph } from "../src/graph-model";
import type { GraphEdge, GraphModel } from "../src/graph-model";
import { foldEvents } from "../src/run-view";
import { STREAMS, load, must, viewOf } from "./golden";

function derivedEdge(from: string, to: string): GraphEdge {
  return {
    id: `e:${from}->${to}:`,
    from,
    to,
    kind: "derived",
    param: null,
    severed: false,
    reasonCode: null,
  };
}

describe("layout", () => {
  it("is deterministic and column-based [I6]", () => {
    const model = buildGraph(viewOf("poisoned_bill.notary"));
    const first = layout(model);
    const second = layout(model);
    expect([...first]).toEqual([...second]);
    expect(first).not.toBe(second);

    const gateXs = model.nodes.filter((n) => n.kind === "gate").map((n) => first.get(n.id)?.x);
    expect(new Set(gateXs)).toEqual(new Set([560]));

    // Derive the expected columns from the model's own derived edges, not from hard-coded ids.
    const derivedTargets = new Set(
      model.edges.filter((e) => e.kind === "derived").map((e) => e.to),
    );
    expect(derivedTargets.size).toBeGreaterThan(0);
    for (const node of model.nodes) {
      if (node.kind !== "value") continue;
      const expected = derivedTargets.has(node.id) ? 260 : 0;
      expect(first.get(node.id)?.x, node.id).toBe(expected);
    }

    // Within a column nodes keep the model's order, 110 apart.
    for (const x of [0, 260, 560]) {
      const column = model.nodes.filter((n) => first.get(n.id)?.x === x);
      expect(column.map((n) => first.get(n.id)?.y)).toEqual(column.map((_, i) => 110 * i));
    }
  });

  it("gives every node of every golden stream a position [I6]", () => {
    for (const name of STREAMS) {
      const model = buildGraph(viewOf(name));
      const positions = layout(model);
      expect(positions.size).toBe(model.nodes.length);
      for (const node of model.nodes) expect(positions.get(node.id), node.id).toBeDefined();
    }
  });

  it("never throws on an empty model, an unknown endpoint or a self edge [I6]", () => {
    const empty: GraphModel = { nodes: [], edges: [] };
    expect(layout(empty).size).toBe(0);

    const model = buildGraph(viewOf("poisoned_bill.notary"));
    const anyNode = must(model.nodes[0], "a node");
    const odd: GraphModel = {
      nodes: model.nodes,
      edges: [
        ...model.edges,
        derivedEdge("v:ghost", "v:also-ghost"),
        derivedEdge(anyNode.id, anyNode.id),
      ],
    };
    const positions = layout(odd);
    expect(positions.size).toBe(model.nodes.length);
    for (const node of model.nodes) expect(positions.get(node.id), node.id).toBeDefined();
    expect(positions.has("v:ghost")).toBe(false);
  });

  it("does not move earlier nodes as events arrive [I6]", () => {
    for (const name of STREAMS) {
      const events = load(name);
      let before = layout(buildGraph(foldEvents([])));
      for (let k = 1; k <= events.length; k += 1) {
        const after = layout(buildGraph(foldEvents(events.slice(0, k))));
        for (const [id, position] of before) {
          expect(after.get(id), `${name} k=${k} ${id}`).toEqual(position);
        }
        before = after;
      }
    }
  });
});
