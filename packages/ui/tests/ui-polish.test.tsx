import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./dom-stubs";
import { DecisionStream } from "../src/DecisionStream";
import { EndorsementCard } from "../src/EndorsementCard";
import { ProvenanceGraph } from "../src/ProvenanceGraph";
import type { RunView } from "../src/run-view";
import { must, viewOf } from "./golden";

afterEach(cleanup);

describe("EndorsementCard buttons", () => {
  const endorsement = must(
    viewOf("poisoned_bill.notary").endorsements[0],
    "an endorsement",
  ).endorsement;

  it("are real buttons in DOM order Confirm, Reject, Use nearest, with a pointer cursor [I4]", () => {
    const onDecide = vi.fn();
    const { container } = render(
      <EndorsementCard
        endorsement={endorsement}
        remainingApprovals={3}
        state="pending"
        onDecide={onDecide}
      />,
    );
    const buttons = [...container.querySelectorAll("button")];
    expect(buttons.map((b) => b.textContent)).toEqual([
      "Confirm",
      "Reject",
      "Use nearest known value",
    ]);
    for (const button of buttons) {
      expect(button.type).toBe("button");
      expect(button.className).toContain("cursor-pointer");
      expect(button.className).toContain("focus-visible:ring-2");
      expect(button.className).toContain("disabled:cursor-not-allowed");
      expect(button.className).toContain("rounded-md");
    }
    expect(buttons[1]?.className).toContain("bg-primary");
    expect(buttons[0]?.className).toContain("border-warn");
    expect(buttons[2]?.className).toContain("border-input");
    expect(buttons[2]?.className).not.toContain("bg-primary");
    buttons[0]?.click();
    buttons[1]?.click();
    buttons[2]?.click();
    expect(onDecide.mock.calls).toEqual([["approve"], ["reject"], ["use_nearest"]]);
  });

  it("keep their look when disabled; only the nearest-value choice survives no approvals [I4]", () => {
    const { container } = render(
      <EndorsementCard
        endorsement={endorsement}
        remainingApprovals={0}
        state="pending"
        onDecide={() => undefined}
      />,
    );
    const [confirm, reject, nearest] = [...container.querySelectorAll("button")];
    for (const button of [confirm, reject]) {
      expect(button?.disabled).toBe(true);
      expect(button?.className).toContain("disabled:opacity-50");
    }
    // It approves nothing, so it does not use up an approval.
    expect(nearest?.textContent).toBe("Use nearest known value");
    expect(nearest?.disabled).toBe(false);
    expect(document.activeElement?.tagName).not.toBe("BUTTON");
  });
});

describe("DecisionStream buttons", () => {
  it("are only the things that select, styled as small badges, not links [I6]", () => {
    const onSelect = vi.fn();
    const { container } = render(
      <DecisionStream view={viewOf("poisoned_bill.notary")} onSelect={onSelect} />,
    );
    const buttons = [...container.querySelectorAll("button")];
    expect(buttons.length).toBeGreaterThan(0);
    for (const button of buttons) {
      const hooks = ["data-row-select", "data-chip", "data-hash-link"].filter((h) =>
        button.hasAttribute(h),
      );
      expect(hooks, button.outerHTML).toHaveLength(1);
      expect(button.className).toContain("cursor-pointer");
    }
    // Information that does not select is not a button.
    for (const info of container.querySelectorAll(
      "[data-preview], [data-verdict-badge], [data-manifest]",
    )) {
      expect(info.tagName).not.toBe("BUTTON");
    }
    const hash = must(container.querySelector<HTMLElement>("[data-hash-link]"), "hash link");
    expect(hash.className).toContain("rounded-md");
    expect(hash.className).toContain("font-mono");
    expect(hash.className).not.toContain("underline");
    expect(hash.className).not.toContain("text-indigo-700");
    hash.click();
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0]?.[0]).toMatchObject({ callId: "c2" });
    expect(onSelect.mock.calls[0]?.[0]).toHaveProperty("valueId");
  });
});

describe("ProvenanceGraph", () => {
  it("has no zoom controls and no minimap [I6]", () => {
    const { container } = render(<ProvenanceGraph view={viewOf("poisoned_bill.notary")} />);
    expect(container.querySelector(".react-flow__controls")).toBeNull();
    expect(container.querySelector(".react-flow__minimap")).toBeNull();
    expect(container.querySelector(".react-flow__background")).not.toBeNull();
  });

  it("draws every node as a card of one fixed width [I6]", () => {
    const { container } = render(<ProvenanceGraph view={viewOf("poisoned_bill.notary")} />);
    const cards = [...container.querySelectorAll(".react-flow__nodes [data-node]")];
    expect(cards.length).toBe(5);
    for (const card of cards) expect(card.className).toContain("w-[200px]");
  });

  it("has a panel of at least 380 px that grows with the tallest column [I6]", () => {
    const panel = (view: RunView): number => {
      const { container, unmount } = render(<ProvenanceGraph view={view} />);
      const element = must(
        container.querySelector<HTMLElement>('[class*="min-h-[380px]"]'),
        "panel",
      );
      const height = Number.parseInt(element.style.height, 10);
      unmount();
      return height;
    };
    const base = viewOf("poisoned_bill.notary");
    expect(panel(base)).toBe(380);

    const sample = must(base.values[0], "a value");
    const many: RunView = {
      ...base,
      values: Array.from({ length: 10 }, (_, i) => ({
        ...sample,
        seq: i,
        ref: {
          ...sample.ref,
          id: `extra-${i}`,
          label: { ...sample.ref.label, span_pointer: null },
        },
      })),
    };
    const tall = panel(many);
    expect(tall).toBeGreaterThan(380);
    expect(tall).toBeLessThanOrEqual(720);
  });
});
