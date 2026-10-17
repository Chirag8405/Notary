import { CommandSchema, EventSchema } from "@notary/schema";
import type { Command } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import type { EndorsementView } from "@notary/ui";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";
import type { PendingItem } from "@/components/endorsement-panel";

const file = resolve(
  import.meta.dirname,
  "../../../packages/world/fixtures/streams/poisoned_bill.notary.json",
);
const events = EventSchema.array().parse(JSON.parse(readFileSync(file, "utf8")));
const view = foldEvents(events);
const FIRST = view.endorsements[0];
if (FIRST === undefined) throw new Error("fixture has no endorsement");
const RUN_ID = view.runId ?? "";
const ID = FIRST.endorsement.endorsement_id;

/** A second request: a copy of the real one under another id. */
const SECOND: EndorsementView = {
  ...FIRST,
  endorsement: { ...FIRST.endorsement, endorsement_id: "e-second" },
};

afterEach(cleanup);

function item(id: string, remaining: number): PendingItem {
  return { endorsement: { endorsement_id: id }, remaining_approvals: remaining };
}

function setup(list: readonly PendingItem[] = [item(ID, 3)]) {
  const send = vi.fn<(command: Command) => void>();
  const fetchPending = vi.fn<() => Promise<readonly PendingItem[]>>();
  fetchPending.mockResolvedValue(list);
  return { send, fetchPending };
}

type Doubles = ReturnType<typeof setup>;

async function mount(
  doubles: Doubles,
  extra: Partial<Parameters<typeof EndorsementPanel>[0]> = {},
) {
  const props = {
    runId: RUN_ID,
    endorsements: [FIRST] as readonly EndorsementView[],
    send: doubles.send,
    fetchPending: doubles.fetchPending,
    ...extra,
  };
  const result = render(<EndorsementPanel {...props} />);
  await settle();
  return {
    ...result,
    update: async (more: Partial<typeof props>) => {
      result.rerender(<EndorsementPanel {...props} {...more} />);
      await settle();
    },
  };
}

/** Runs `run`, then lets pending promises settle inside act. */
async function settle(run: () => void = () => undefined): Promise<void> {
  await act(async () => {
    run();
    await Promise.resolve();
  });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole<HTMLButtonElement>("button", { name });
}

function cardButton(id: string, name: string): HTMLButtonElement {
  return within(card(id)).getByRole<HTMLButtonElement>("button", { name });
}

function card(id: string): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-endorsement-id="${id}"]`);
  if (el === null) throw new Error(`no card ${id}`);
  return el;
}

function deferred<T>() {
  let resolveIt: (value: T) => void = () => undefined;
  let rejectIt: (reason: Error) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolveIt = res;
    rejectIt = rej;
  });
  return { promise, resolve: resolveIt, reject: rejectIt };
}

describe("EndorsementPanel commands", () => {
  it("sends exactly the approve command and nothing else [I4]", async () => {
    const d = setup();
    await mount(d);
    fireEvent.click(button("Confirm"));
    expect(d.send).toHaveBeenCalledTimes(1);
    const command = d.send.mock.calls[0]?.[0];
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: ID,
      decision: "approve",
    });
    expect(CommandSchema.safeParse(command).success).toBe(true);
  });

  it("sends the reject command [I4]", async () => {
    const d = setup();
    await mount(d);
    fireEvent.click(button("Reject"));
    expect(d.send.mock.calls[0]?.[0]).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: ID,
      decision: "reject",
    });
  });

  it("sends once for two clicks in the same tick [I4]", async () => {
    const d = setup();
    await mount(d);
    const confirm = button("Confirm");
    act(() => {
      confirm.click();
      confirm.click();
    });
    expect(d.send).toHaveBeenCalledTimes(1);
    expect(card(ID).getAttribute("data-state")).toBe("sending");
  });

  it("blocks a click that arrives while send is still running [I4]", async () => {
    const d = setup();
    await mount(d);
    const confirm = button("Confirm");
    // The card's state is only written after send returns, so only the in-flight guard can stop this.
    d.send.mockImplementationOnce(() => {
      confirm.click();
    });
    fireEvent.click(confirm);
    expect(d.send).toHaveBeenCalledTimes(1);
  });

  it("restores the card when send throws, and lets the user try again [I4]", async () => {
    const d = setup();
    d.send.mockImplementationOnce(() => {
      throw new Error("run socket is not open");
    });
    await mount(d);
    fireEvent.click(button("Confirm"));
    expect(card(ID).getAttribute("data-state")).toBe("pending");
    expect(screen.getByRole("alert").textContent).toBe("run socket is not open");
    expect(button("Confirm").disabled).toBe(false);

    fireEvent.click(button("Confirm"));
    expect(d.send).toHaveBeenCalledTimes(2);
    expect(card(ID).getAttribute("data-state")).toBe("sending");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("sends nothing from the keyboard or the heading [I4]", async () => {
    const d = setup();
    await mount(d);
    for (const key of ["Enter", " "]) {
      fireEvent.keyDown(document.body, { key });
      fireEvent.keyDown(screen.getByRole("heading"), { key });
      fireEvent.keyUp(document.body, { key });
    }
    expect(d.send).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(screen.getByRole("heading"));
  });
});

describe("EndorsementPanel resolution", () => {
  it("moves to approved or rejected once the id leaves the pending list [I4]", async () => {
    for (const [name, text] of [
      ["Confirm", "You confirmed this request"],
      ["Reject", "You rejected this request"],
    ] as const) {
      const d = setup();
      d.fetchPending.mockResolvedValueOnce([item(ID, 3)]).mockResolvedValue([]);
      const { unmount } = await mount(d);
      expect(card(ID).getAttribute("data-state")).toBe("pending");
      fireEvent.click(button(name));
      await settle();
      expect(screen.getByText(text)).toBeTruthy();
      expect(card(ID).getAttribute("data-state")).toBe(
        name === "Confirm" ? "approved" : "rejected",
      );
      unmount();
    }
  });

  it("never resolves a card because a read failed [I4]", async () => {
    const d = setup();
    d.fetchPending.mockResolvedValueOnce([item(ID, 3)]);
    const { update } = await mount(d, { eventCount: 0 });
    d.fetchPending.mockRejectedValueOnce(new Error("network down"));
    fireEvent.click(button("Confirm"));
    await settle();
    expect(card(ID).getAttribute("data-state")).toBe("sending");

    // A successful list that still contains the id keeps the card sending...
    d.fetchPending.mockResolvedValueOnce([item(ID, 2)]);
    await update({ eventCount: 1 });
    expect(card(ID).getAttribute("data-state")).toBe("sending");

    // ...and a successful list without it resolves the card to the decision that was clicked.
    d.fetchPending.mockResolvedValueOnce([]);
    await update({ eventCount: 2 });
    expect(card(ID).getAttribute("data-state")).toBe("approved");
  });

  it("shows the approvals left from the pending list and refreshes it after a click [A11]", async () => {
    const d = setup([item(ID, 3), item("e-second", 3)]);
    d.fetchPending.mockResolvedValueOnce([item(ID, 3), item("e-second", 3)]);
    await mount(d, { endorsements: [FIRST, SECOND] });
    expect(d.fetchPending).toHaveBeenCalledTimes(1);
    expect(card(ID).textContent).toContain("Approvals left: 3");
    expect(card("e-second").textContent).toContain("Approvals left: 3");

    d.fetchPending.mockResolvedValue([item("e-second", 2)]);
    fireEvent.click(cardButton(ID, "Confirm"));
    await settle();
    expect(d.fetchPending).toHaveBeenCalledTimes(2);
    expect(card(ID).getAttribute("data-state")).toBe("approved");
    expect(card("e-second").textContent).toContain("Approvals left: 2");
  });

  it("keeps the buttons enabled while the approvals are unknown, and blocks at zero [A11]", async () => {
    const d = setup([]);
    await mount(d);
    expect(card(ID).textContent).not.toContain("Approvals left");
    expect(button("Confirm").disabled).toBe(false);
    cleanup();

    const zero = setup([item(ID, 0)]);
    await mount(zero);
    expect(card(ID).textContent).toContain("No approvals left: the call is blocked");
    expect(button("Confirm").disabled).toBe(true);
  });

  it("applies only the latest of two overlapping reads [I6]", async () => {
    const d = setup();
    const first = deferred<readonly PendingItem[]>();
    const second = deferred<readonly PendingItem[]>();
    d.fetchPending.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { update } = await mount(d);
    await update({ eventCount: 1 });
    expect(d.fetchPending).toHaveBeenCalledTimes(2);
    await settle(() => {
      second.resolve([item(ID, 2)]);
    });
    await settle(() => {
      first.resolve([item(ID, 3)]);
    });
    expect(card(ID).textContent).toContain("Approvals left: 2");
    expect(card(ID).textContent).not.toContain("Approvals left: 3");
  });

  it("reads the list again when the event count changes [I6]", async () => {
    const d = setup();
    const { update } = await mount(d, { eventCount: 1 });
    expect(d.fetchPending).toHaveBeenCalledTimes(1);
    await update({ eventCount: 2 });
    expect(d.fetchPending).toHaveBeenCalledTimes(2);
    await update({ eventCount: 2 });
    expect(d.fetchPending).toHaveBeenCalledTimes(2);
  });

  it("does not touch state after unmount [I6]", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const d = setup();
    const late = deferred<readonly PendingItem[]>();
    d.fetchPending.mockReturnValueOnce(late.promise);
    const { unmount } = await mount(d);
    unmount();
    await settle(() => {
      late.resolve([item(ID, 1)]);
    });
    expect(error).not.toHaveBeenCalled();
    error.mockRestore();
  });

  it("keeps final cards final and starts new ones pending [I6]", async () => {
    const d = setup();
    d.fetchPending.mockResolvedValueOnce([item(ID, 3)]).mockResolvedValue([item("e-second", 2)]);
    const { update } = await mount(d);
    fireEvent.click(button("Confirm"));
    await settle();
    expect(card(ID).getAttribute("data-state")).toBe("approved");

    await update({ endorsements: [FIRST, SECOND] });
    expect(card(ID).getAttribute("data-state")).toBe("approved");
    expect(card("e-second").getAttribute("data-state")).toBe("pending");
    expect(card("e-second").querySelectorAll("button:disabled")).toHaveLength(0);
  });
});

describe("EndorsementPanel closed socket", () => {
  it("turns pending and sending cards into conflicts on 4409 [I4]", async () => {
    const d = setup();
    const { update } = await mount(d);
    await update({ closeCode: 4409 });
    expect(card(ID).getAttribute("data-state")).toBe("conflict");
    expect(screen.getByText("This request is no longer open")).toBeTruthy();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("also closes a card that was already sending [I4]", async () => {
    const d = setup();
    const { update } = await mount(d);
    fireEvent.click(button("Confirm"));
    expect(card(ID).getAttribute("data-state")).toBe("sending");
    await update({ closeCode: 4409 });
    expect(card(ID).getAttribute("data-state")).toBe("conflict");
  });

  it("ignores any other close code [I6]", async () => {
    const d = setup();
    const { update } = await mount(d);
    await update({ closeCode: 1006 });
    await update({ closeCode: 4422 });
    expect(card(ID).getAttribute("data-state")).toBe("pending");
  });
});

describe("EndorsementPanel rendering", () => {
  it("renders an empty labelled region without endorsements [I6]", async () => {
    await mount(setup(), { endorsements: [] });
    const region = screen.getByLabelText("Endorsements");
    expect(region.children).toHaveLength(0);
  });

  it("titles each card with its tool name [I6]", async () => {
    await mount(setup(), { toolByCallId: { [FIRST.endorsement.call_id]: "pay_bill" } });
    expect(screen.getByRole("heading").textContent).toBe("Confirm pay_bill?");
  });
});

describe("EndorsementPanel onResolvedChange", () => {
  const ids = (set: ReadonlySet<string> | undefined) => [...(set ?? [])].sort();

  it("reports the answered cards once, by content, and never on mount [I4]", async () => {
    const d = setup();
    d.fetchPending.mockResolvedValueOnce([item(ID, 3)]).mockResolvedValue([]);
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    const { update } = await mount(d, { onResolvedChange: onResolved });
    expect(onResolved).not.toHaveBeenCalled();

    fireEvent.click(button("Confirm"));
    expect(onResolved).not.toHaveBeenCalled();
    await settle();
    expect(onResolved).toHaveBeenCalledTimes(1);
    expect(ids(onResolved.mock.calls[0]?.[0])).toEqual([ID]);

    // Re-renders, new events and a new callback do not report the same set again.
    await update({ eventCount: 9 });
    const other = vi.fn<(resolved: ReadonlySet<string>) => void>();
    await update({ onResolvedChange: other });
    await update({ eventCount: 10 });
    expect(onResolved).toHaveBeenCalledTimes(1);
    expect(other).not.toHaveBeenCalled();
  });

  it("counts rejected cards and grows the set as more cards are answered [I4]", async () => {
    const d = setup();
    d.fetchPending
      .mockResolvedValueOnce([item(ID, 3), item("e-second", 3)])
      .mockResolvedValueOnce([item("e-second", 3)])
      .mockResolvedValue([]);
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    await mount(d, { endorsements: [FIRST, SECOND], onResolvedChange: onResolved });

    fireEvent.click(within(card(ID)).getByRole("button", { name: "Reject" }));
    await settle();
    expect(ids(onResolved.mock.calls.at(-1)?.[0])).toEqual([ID]);

    fireEvent.click(cardButton("e-second", "Confirm"));
    await settle();
    expect(onResolved).toHaveBeenCalledTimes(2);
    expect(ids(onResolved.mock.calls.at(-1)?.[0])).toEqual(["e-second", ID]);
  });

  it("does not report a card that is only sending or in conflict [I4]", async () => {
    const d = setup();
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    const { update } = await mount(d, { onResolvedChange: onResolved });
    fireEvent.click(button("Confirm"));
    await settle();
    expect(card(ID).getAttribute("data-state")).toBe("sending");
    await update({ closeCode: 4409 });
    expect(card(ID).getAttribute("data-state")).toBe("conflict");
    expect(onResolved).not.toHaveBeenCalled();
  });
});
