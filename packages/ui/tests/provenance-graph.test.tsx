import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./dom-stubs";
import { ProvenanceGraph } from "../src/ProvenanceGraph";
import type { Decision, Reason } from "@notary/schema";
import type { RunView } from "../src/run-view";
import { emptyRunView } from "../src/run-view";
import { must, viewOf } from "./golden";
import type { StreamName } from "./golden";

afterEach(cleanup);

function list(): HTMLElement {
  return screen.getByLabelText("Graph nodes");
}

function nodes(kind: "value" | "gate"): HTMLElement[] {
  return [...list().querySelectorAll<HTMLElement>(`[data-node="${kind}"]`)];
}

function show(name: StreamName, props: { flagged?: string[]; selected?: string | null } = {}) {
  const flaggedValueIds = props.flagged === undefined ? undefined : new Set(props.flagged);
  return render(
    <ProvenanceGraph
      view={viewOf(name)}
      {...(flaggedValueIds === undefined ? {} : { flaggedValueIds })}
      {...(props.selected === undefined ? {} : { selectedId: props.selected })}
    />,
  );
}

function blockView(): RunView {
  const base = viewOf("poisoned_bill.notary");
  const failing: Reason = {
    check: "corroboration",
    outcome: "fail",
    code: "LEDGER_NOT_FOUND",
    detail: "value is not in the ledger",
  };
  const decision: Decision = { verdict: "BLOCK", reasons: [failing], diff_card: null };
  return {
    ...base,
    calls: base.calls.map((call) => (call.callId === "c2" ? { ...call, decision } : call)),
  };
}

describe("ProvenanceGraph", () => {
  it("renders the NOTARY poisoned graph [A3]", () => {
    show("poisoned_bill.notary");
    expect(nodes("gate").map((n) => n.getAttribute("data-state"))).toEqual(["allow", "escalate"]);
    const payee = nodes("value").find((n) => n.getAttribute("data-integrity") === "untrusted");
    expect(must(payee, "an untrusted value").getAttribute("data-tone")).toBe("tool");
    const escalate = must(
      nodes("gate").find((n) => n.getAttribute("data-state") === "escalate"),
      "the escalate gate",
    );
    expect(escalate.textContent).toContain("awaiting confirmation");
    expect(within(list()).getAllByText(/awaiting confirmation/)).toHaveLength(1);
  });

  it("renders the legitimate graph [I1]", () => {
    show("legitimate_bill.notary");
    expect(nodes("gate").map((n) => n.getAttribute("data-state"))).toEqual(["allow", "allow"]);
    // The stream gives an email-origin, untrusted payee, so its tone is "tool" (amber), the same
    // as in the poisoned stream. What lets this payment through is the ledger match in the
    // corroboration step, which a label does not carry: the gate colour, not the node colour,
    // distinguishes the poisoned run from the legitimate one.
    const untrusted = nodes("value").filter(
      (n) => n.getAttribute("data-integrity") === "untrusted",
    );
    expect(untrusted.length).toBeGreaterThan(0);
    for (const node of untrusted) expect(node.getAttribute("data-tone")).toBe("tool");
  });

  it('shows "no check" on the baseline graph [A3]', () => {
    show("poisoned_bill.undefended");
    const gates = nodes("gate");
    expect(gates).toHaveLength(2);
    for (const gate of gates) {
      expect(gate.getAttribute("data-state")).toBe("ungated");
      expect(gate.textContent).toContain("no check");
    }
  });

  it("shows the reason code on a severed edge [A4]", () => {
    render(<ProvenanceGraph view={blockView()} />);
    expect(nodes("gate").map((n) => n.getAttribute("data-state"))).toEqual(["allow", "block"]);
    const severed = [...list().querySelectorAll<HTMLElement>('[data-edge][data-severed="true"]')];
    expect(severed.length).toBeGreaterThan(0);
    for (const edge of severed) expect(edge.textContent).toContain("LEDGER_NOT_FOUND");
    expect(list().textContent).toContain("LEDGER_NOT_FOUND");
  });

  it("outlines only the flagged value [A1]", () => {
    const first = must(nodes_of("poisoned_bill.notary")[0], "a value node id");
    show("poisoned_bill.notary", { flagged: [first.replace(/^v:/, "")] });
    const flagged = nodes("value").filter((n) => n.getAttribute("data-flagged") === "true");
    expect(flagged.map((n) => n.getAttribute("data-node-id"))).toEqual([first]);
  });

  it("round-trips selection through the controlled prop [I6]", () => {
    const onSelect = vi.fn<(id: string | null) => void>();
    const view = viewOf("poisoned_bill.notary");
    const { rerender } = render(<ProvenanceGraph view={view} onSelect={onSelect} />);
    const gate = must(nodes("gate")[1], "a gate");
    fireEvent.click(gate);
    expect(onSelect).toHaveBeenLastCalledWith(gate.getAttribute("data-node-id"));

    const id = must(gate.getAttribute("data-node-id"), "the gate id");
    rerender(<ProvenanceGraph view={view} selectedId={id} onSelect={onSelect} />);
    const selected = [...list().querySelectorAll('[data-node][data-selected="true"]')];
    expect(selected.map((n) => n.getAttribute("data-node-id"))).toEqual([id]);

    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(onSelect).toHaveBeenLastCalledWith(null);
  });

  it('shows "No provenance yet" for an empty view [I6]', () => {
    render(<ProvenanceGraph view={emptyRunView} />);
    expect(screen.getByLabelText("Provenance graph").textContent).toContain("No provenance yet");
    expect(screen.queryByLabelText("Graph nodes")).toBeNull();
  });
});

/** Ids of the value nodes of a golden stream, as drawn. */
function nodes_of(name: StreamName): string[] {
  const { unmount } = show(name);
  const ids = nodes("value").map((n) => n.getAttribute("data-node-id") ?? "");
  unmount();
  return ids;
}
