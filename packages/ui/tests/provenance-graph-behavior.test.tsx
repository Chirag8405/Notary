import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import "./dom-stubs";
import * as ui from "../src";
import { ProvenanceGraph } from "../src/ProvenanceGraph";
import type { Decision, Reason } from "@notary/schema";
import type { RunView } from "../src/run-view";
import { must, viewOf } from "./golden";

afterEach(cleanup);

function list(): HTMLElement {
  return screen.getByLabelText("Graph nodes");
}

function items(selector: string): HTMLElement[] {
  return [...list().querySelectorAll<HTMLElement>(selector)];
}

function blockedAndExecuted(): RunView {
  const base = viewOf("poisoned_bill.notary");
  const failing: Reason = {
    check: "origin",
    outcome: "fail",
    code: "ORIGIN_UNTRUSTED",
    detail: "argument from the named source is not trusted",
  };
  const decision: Decision = { verdict: "BLOCK", reasons: [failing], diff_card: null };
  return {
    ...base,
    calls: base.calls.map((call) =>
      call.callId === "c2" ? { ...call, decision, executed: { summary: "paid", seq: 99 } } : call,
    ),
  };
}

describe("ProvenanceGraph behavior", () => {
  it("truncates the preview to 24 characters and keeps it whole in the title [I6]", () => {
    const base = viewOf("poisoned_bill.notary");
    const long = "x".repeat(60);
    const first = must(base.values[0], "a value");
    const view: RunView = {
      ...base,
      values: [{ ...first, preview: long }, ...base.values.slice(1)],
    };
    render(<ProvenanceGraph view={view} />);
    const node = must(items('[data-node="value"]')[0], "a value item");
    expect(node.getAttribute("title")).toBe(long);
    expect(node.textContent).toContain("x".repeat(24));
    expect(node.textContent).not.toContain("x".repeat(25));
  });

  it("keeps a blocked gate blocked and shows that it executed [A4]", () => {
    render(<ProvenanceGraph view={blockedAndExecuted()} />);
    const gate = must(
      items('[data-node="gate"]').find((n) => n.getAttribute("data-state") === "block"),
      "the block gate",
    );
    expect(gate.textContent).toContain("ORIGIN_UNTRUSTED");
    expect(gate.textContent).toContain("executed despite block");
  });

  it("names nodes by tone, origin and integrity, and by tool and state [I6]", () => {
    render(<ProvenanceGraph view={viewOf("poisoned_bill.notary")} />);
    const names = items("[data-node]").map((n) => n.textContent);
    expect(names.some((n) => n.startsWith("user value user, trusted"))).toBe(true);
    expect(names.some((n) => n.startsWith("tool value email, untrusted"))).toBe(true);
    expect(names.some((n) => n.startsWith("pay_bill gate, escalate"))).toBe(true);
    expect(names.some((n) => n.startsWith("read_inbox gate, allow"))).toBe(true);
  });

  it("draws the canvas nodes with the same names [I6]", () => {
    const { container } = render(<ProvenanceGraph view={viewOf("poisoned_bill.notary")} />);
    const labels = [...container.querySelectorAll(".react-flow [aria-label]")].map(
      (n) => n.getAttribute("aria-label") ?? "",
    );
    expect(labels).toContain("pay_bill gate, escalate");
  });

  it("keeps selection controlled: another selectedId moves the mark [I6]", () => {
    const view = viewOf("poisoned_bill.notary");
    const { rerender } = render(<ProvenanceGraph view={view} />);
    const [a, b] = items("[data-node]");
    const idA = must(a?.getAttribute("data-node-id"), "first id");
    const idB = must(b?.getAttribute("data-node-id"), "second id");
    const selected = () =>
      items('[data-node][data-selected="true"]').map((n) => n.getAttribute("data-node-id"));

    expect(selected()).toEqual([]);
    rerender(<ProvenanceGraph view={view} selectedId={idA} />);
    expect(selected()).toEqual([idA]);
    rerender(<ProvenanceGraph view={view} selectedId={idB} />);
    expect(selected()).toEqual([idB]);
    rerender(<ProvenanceGraph view={view} selectedId={null} />);
    expect(selected()).toEqual([]);
  });

  it("exports the component, its props type and layout [I6]", () => {
    expect(ui.ProvenanceGraph).toBe(ProvenanceGraph);
    expect(typeof ui.layout).toBe("function");
    const props: ui.ProvenanceGraphProps = { view: viewOf("poisoned_bill.notary") };
    expect(props.view.calls.length).toBeGreaterThan(0);
  });
});
