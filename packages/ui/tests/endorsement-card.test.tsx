import type { DiffRow, Endorsement } from "@notary/schema";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as ui from "../src";
import { EndorsementCard } from "../src/EndorsementCard";
import type { CardState } from "../src/EndorsementCard";
import { must, viewOf } from "./golden";

afterEach(cleanup);

const REAL: Endorsement = must(
  viewOf("poisoned_bill.notary").endorsements[0],
  "an endorsement",
).endorsement;
const ROW: DiffRow = must(REAL.card.rows[0], "the payee row");

function withRow(change: Partial<DiffRow>): Endorsement {
  return { ...REAL, card: { rows: [{ ...ROW, ...change }] } };
}

function show(
  props: Partial<{
    endorsement: Endorsement;
    remainingApprovals: number | null;
    state: CardState;
    toolName: string;
    error: string | null;
  }> = {},
) {
  const onDecide = vi.fn<(decision: "approve" | "reject" | "use_nearest") => void>();
  const result = render(
    <EndorsementCard
      endorsement={props.endorsement ?? REAL}
      remainingApprovals={props.remainingApprovals ?? null}
      state={props.state ?? "pending"}
      onDecide={onDecide}
      {...(props.toolName === undefined ? {} : { toolName: props.toolName })}
      {...(props.error === undefined ? {} : { error: props.error })}
    />,
  );
  return { onDecide, ...result };
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole<HTMLButtonElement>("button", { name });
}

function markedCount(el: Element): number {
  return [...el.querySelectorAll("mark[data-differs]")].reduce(
    (n, mark) => n + Array.from(mark.textContent).length,
    0,
  );
}

describe("EndorsementCard on the real request", () => {
  it("renders the parameter, value, origin, integrity and ledger value [A3]", () => {
    show();
    const row = must(document.querySelector("[data-row]"), "row");
    expect(row.getAttribute("data-param")).toBe(ROW.param);
    expect(within(row as HTMLElement).getByText(ROW.param)).toBeTruthy();
    expect(row.querySelector("[data-proposed]")?.textContent).toBe(ROW.preview);
    expect(row.querySelector("[data-origin]")?.textContent).toBe(ROW.origin.kind);
    expect(row.querySelector("[data-integrity]")?.textContent).toBe("untrusted");
    expect(ROW.nearest_ledger_value).not.toBeNull();
    expect(row.querySelector("[data-ledger]")?.textContent).toBe(ROW.nearest_ledger_value);
    expect(screen.getByText("This value is not in your ledger.")).toBeTruthy();
  });

  it("marks exactly the differing characters in both values [A3]", () => {
    show();
    const length = Array.from(ROW.preview).length;
    const unique = new Set(
      ROW.differing_positions.filter((p) => Number.isInteger(p) && p >= 0 && p < length),
    );
    expect(unique.size).toBeGreaterThan(0);
    const proposed = must(document.querySelector("[data-proposed]"), "proposed");
    const ledger = must(document.querySelector("[data-ledger]"), "ledger");
    expect(markedCount(proposed)).toBe(unique.size);
    // The real ledger value is as long as the proposal, so the same positions apply to it.
    expect(markedCount(ledger)).toBe(unique.size);
    expect(screen.queryByText("different length: positions not comparable")).toBeNull();
  });

  it("titles the card with the tool name, else the call id [I6]", () => {
    const { unmount } = show({ toolName: "pay_bill" });
    expect(screen.getByRole("heading").textContent).toBe("Confirm pay_bill?");
    unmount();
    show();
    expect(screen.getByRole("heading").textContent).toBe(`Confirm ${REAL.call_id}?`);
  });
});

describe("EndorsementCard ledger and budget", () => {
  it("highlights the ledger value only when it is as long as the proposal [A3]", () => {
    const { unmount } = show({ endorsement: withRow({ nearest_ledger_value: "DE00SHORT" }) });
    const ledger = must(document.querySelector("[data-ledger]"), "ledger");
    expect(ledger.textContent).toBe("DE00SHORT");
    expect(ledger.querySelector("mark")).toBeNull();
    expect(screen.getByText("different length: positions not comparable")).toBeTruthy();
    unmount();

    show({ endorsement: withRow({ nearest_ledger_value: null, differing_positions: [] }) });
    expect(screen.getByText("no similar ledger entry")).toBeTruthy();
    expect(document.querySelector("[data-ledger]")).toBeNull();
  });

  it("shows the approvals left, and blocks at zero [A11]", () => {
    const three = show({ remainingApprovals: 3 });
    expect(screen.getByText("Approvals left: 3")).toBeTruthy();
    expect(screen.queryByText("No approvals left: the call is blocked")).toBeNull();
    expect(button("Confirm").disabled).toBe(false);
    three.unmount();

    const zero = show({ remainingApprovals: 0 });
    expect(screen.getByText("Approvals left: 0")).toBeTruthy();
    expect(screen.getByText("No approvals left: the call is blocked")).toBeTruthy();
    expect(button("Confirm").disabled).toBe(true);
    expect(button("Reject").disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(zero.onDecide).not.toHaveBeenCalled();
    zero.unmount();

    show({ remainingApprovals: null });
    expect(screen.queryByText(/Approvals left/)).toBeNull();
    expect(button("Confirm").disabled).toBe(false);
  });
});

describe("EndorsementCard states and buttons", () => {
  it("reports each decision once per click [I4]", () => {
    const { onDecide } = show();
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onDecide).toHaveBeenLastCalledWith("approve");
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(onDecide).toHaveBeenLastCalledWith("reject");
    expect(onDecide).toHaveBeenCalledTimes(2);
  });

  it("disables the buttons and shows the text of every state [I6]", () => {
    const expected: [CardState, string | null][] = [
      ["sending", "Sending..."],
      ["approved", "You confirmed this request"],
      ["rejected", "You rejected this request"],
    ];
    for (const [state, text] of expected) {
      const { onDecide, unmount } = show({ state });
      expect(screen.getByText(text ?? "")).toBeTruthy();
      for (const name of ["Confirm", "Reject"]) {
        const target = button(name);
        expect(target.disabled, `${state} ${name}`).toBe(true);
      }
      fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
      expect(onDecide).not.toHaveBeenCalled();
      unmount();
    }
  });

  it("renders no buttons once the request is no longer open [I4]", () => {
    show({ state: "conflict" });
    expect(screen.getByText("This request is no longer open")).toBeTruthy();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("shows an error as an alert [I6]", () => {
    show({ error: "run socket is not open" });
    expect(screen.getByRole("alert").textContent).toBe("run socket is not open");
    cleanup();
    show({ error: null });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("focuses the heading, never a button, and has no key shortcuts [I4]", () => {
    const { onDecide } = show();
    expect(document.activeElement).toBe(screen.getByRole("heading"));
    expect(document.activeElement?.tagName).not.toBe("BUTTON");
    const group = screen.getByRole("group", { name: "Endorsement request" });
    for (const key of ["Enter", " "]) {
      fireEvent.keyDown(group, { key });
      fireEvent.keyDown(screen.getByRole("heading"), { key });
      fireEvent.keyUp(group, { key });
    }
    expect(onDecide).not.toHaveBeenCalled();
  });
});

describe("EndorsementCard safety and exports", () => {
  it("shows hostile text as inert text and only strings from the event [I3]", () => {
    const hostile = "<img src=x onerror=alert(1)>[x](http://evil.example)";
    const { container } = show({
      endorsement: withRow({ preview: hostile, differing_positions: [0] }),
    });
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
    expect(container.querySelector("[data-proposed]")?.textContent).toBe(hostile);
    const mark = must(container.querySelector("[data-proposed] mark"), "mark");
    expect(mark.textContent).toBe("<");
  });

  it("exports the card, the highlighter and the types [I6]", () => {
    expect(ui.EndorsementCard).toBe(EndorsementCard);
    expect(typeof ui.highlightDiff).toBe("function");
    const segment: ui.Segment = ui.highlightDiff("ab", [0])[0] ?? { text: "", differs: false };
    const state: ui.CardState = "pending";
    const props: Pick<ui.EndorsementCardProps, "state"> = { state };
    expect(segment.differs).toBe(true);
    expect(props.state).toBe("pending");
  });
});
