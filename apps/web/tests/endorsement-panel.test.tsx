import { CommandSchema } from "@notary/schema";
import type { Command, Event } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import type { EndorsementView } from "@notary/ui";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";

import {
  APPROVED,
  BLOCKED,
  CALL,
  CARD,
  FINISHED,
  LABELED,
  MAX_APPROVALS,
  REJECTED,
  REPLACED,
  TO_REQUEST,
  append,
  decisionFor,
  proposalFor,
  requestFor,
  withBudget,
} from "./card-events";

const RUN_ID = foldEvents(TO_REQUEST).runId ?? "";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function cardsOf(events: readonly Event[]): readonly EndorsementView[] {
  return foldEvents(events).endorsements;
}

type Props = Parameters<typeof EndorsementPanel>[0];

function mount(events: readonly Event[] = TO_REQUEST, extra: Partial<Props> = {}) {
  const send = vi.fn<(command: Command) => void>();
  const props: Props = {
    runId: RUN_ID,
    endorsements: cardsOf(events),
    events,
    send,
    ...extra,
  };
  let current = props;
  const result = render(<EndorsementPanel {...current} />);
  return {
    ...result,
    send,
    /** The stream moved on (or the socket closed): the same panel, new props on top of the last. */
    update: (more: Partial<Props>) => {
      current = { ...current, ...more };
      if (more.events !== undefined && more.endorsements === undefined) {
        current.endorsements = cardsOf(more.events);
      }
      result.rerender(<EndorsementPanel {...current} />);
    },
  };
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

const stateOf = (id: string = CARD): string | null => card(id).getAttribute("data-state");

describe("EndorsementPanel commands", () => {
  it("sends exactly the approve command and nothing else [I4]", () => {
    const { send } = mount();
    fireEvent.click(button("Confirm"));
    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]?.[0];
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "approve",
    });
    expect(CommandSchema.safeParse(command).success).toBe(true);
  });

  it("sends the reject command [I4]", () => {
    const { send } = mount();
    fireEvent.click(button("Reject"));
    expect(send.mock.calls[0]?.[0]).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: CARD,
      decision: "reject",
    });
  });

  it("sends once for two clicks in the same tick [I4]", () => {
    const { send } = mount();
    const confirm = button("Confirm");
    act(() => {
      confirm.click();
      confirm.click();
    });
    expect(send).toHaveBeenCalledTimes(1);
    expect(stateOf()).toBe("sending");
  });

  it("blocks a click that arrives while send is still running [I4]", () => {
    const { send } = mount();
    const confirm = button("Confirm");
    // The card's state is only written after send returns, so only the in-flight guard can stop this.
    send.mockImplementationOnce(() => {
      confirm.click();
    });
    fireEvent.click(confirm);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("restores the card when send throws, and lets the user try again [I4]", () => {
    const { send } = mount();
    send.mockImplementationOnce(() => {
      throw new Error("run socket is not open");
    });
    fireEvent.click(button("Confirm"));
    expect(stateOf()).toBe("pending");
    expect(screen.getByRole("alert").textContent).toBe("run socket is not open");
    expect(button("Confirm").disabled).toBe(false);

    fireEvent.click(button("Confirm"));
    expect(send).toHaveBeenCalledTimes(2);
    expect(stateOf()).toBe("sending");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("sends nothing from the keyboard or the heading [I4]", () => {
    const { send } = mount();
    for (const key of ["Enter", " "]) {
      fireEvent.keyDown(document.body, { key });
      fireEvent.keyDown(screen.getByRole("heading"), { key });
      fireEvent.keyUp(document.body, { key });
    }
    expect(send).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(screen.getByRole("heading"));
  });
});

describe("EndorsementPanel: the stream resolves the cards", () => {
  it("makes no request at all, for a whole approve and a whole reject [I6]", () => {
    const fetchMock = vi.fn(() => Promise.reject(new Error("no network in this test")));
    vi.stubGlobal("fetch", fetchMock);
    for (const [name, events] of [
      ["Confirm", APPROVED],
      ["Reject", REJECTED],
    ] as const) {
      const { update, unmount } = mount();
      fireEvent.click(button(name));
      update({ events });
      unmount();
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("click, then the ALLOW event: sending, then approved [I4]", () => {
    const { update } = mount();
    expect(stateOf()).toBe("pending");
    fireEvent.click(button("Confirm"));
    expect(stateOf()).toBe("sending");
    update({ events: append(TO_REQUEST, decisionFor("ALLOW")) });
    expect(stateOf()).toBe("approved");
    expect(screen.getByText("You confirmed this request")).toBeTruthy();
  });

  it("a reject click, then the oracle: rejected [I4]", () => {
    const { update } = mount();
    fireEvent.click(button("Reject"));
    expect(stateOf()).toBe("sending");
    update({ events: REJECTED });
    expect(stateOf()).toBe("rejected");
    expect(screen.getByText("You rejected this request")).toBeTruthy();
  });

  it("no click and the run moved on (timeout or cancel): no longer open, not rejected [I4]", () => {
    const { update } = mount();
    update({ events: REJECTED });
    expect(stateOf()).toBe("conflict");
    expect(screen.getByText("This request is no longer open")).toBeTruthy();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("an approve click that the run did not take is no longer open, not approved [I4]", () => {
    const { update } = mount();
    fireEvent.click(button("Confirm"));
    update({ events: REJECTED });
    expect(stateOf()).toBe("conflict");
  });

  it("the server's word wins over the click: reject clicked, approval happened [I4]", () => {
    const { update } = mount();
    fireEvent.click(button("Reject"));
    update({ events: APPROVED });
    expect(stateOf()).toBe("approved");
  });

  it("the nearest known value is its own state, past the value that was labeled [I2]", () => {
    const { update, send } = mount();
    fireEvent.click(button("Use nearest known value"));
    expect(send.mock.calls[0]?.[0]).toMatchObject({ decision: "use_nearest" });
    update({ events: append(TO_REQUEST, LABELED) });
    expect(stateOf()).toBe("sending"); // only a value was labeled so far
    update({ events: REPLACED });
    expect(stateOf()).toBe("replaced");
    expect(screen.getByText("You asked for the nearest known value instead")).toBeTruthy();
  });

  it("an approval that the monitor then blocked says so [I4]", () => {
    const { update } = mount();
    fireEvent.click(button("Confirm"));
    update({ events: BLOCKED });
    expect(stateOf()).toBe("blocked");
    expect(
      screen.getByText("You confirmed this request, but the monitor blocked the call"),
    ).toBeTruthy();
  });

  it("the golden replay does not answer cards: its events after the card are canned [I6]", () => {
    const { update } = mount(REJECTED, { resolveFromEvents: false });
    expect(stateOf()).toBe("pending");
    fireEvent.click(button("Confirm"));
    update({ events: APPROVED });
    expect(stateOf()).toBe("sending"); // nothing in the replay can resolve it
  });

  it("keeps final cards final and starts new ones pending [I6]", () => {
    const { update } = mount();
    fireEvent.click(button("Confirm"));
    const second = append(APPROVED, requestFor("e2", "c9"));
    update({ events: second });
    expect(stateOf()).toBe("approved");
    expect(stateOf("e2")).toBe("pending");
    expect(card("e2").querySelectorAll("button:disabled")).toHaveLength(0);
  });
});

describe("EndorsementPanel: approvals left come from the contract", () => {
  it("shows the budget of the run on an open card [A11]", () => {
    mount();
    expect(card(CARD).textContent).toContain(`Approvals left: ${MAX_APPROVALS}`);
  });

  it("counts an earlier approval, and shows nothing on a card that is resolved [A11]", () => {
    const events = append(APPROVED, requestFor("e2", "c9"));
    mount(events);
    expect(card(CARD).textContent).not.toContain("Approvals left");
    expect(card("e2").textContent).toContain(`Approvals left: ${Math.max(MAX_APPROVALS - 1, 0)}`);
  });

  it("a replaced or rejected card uses no approval [A11]", () => {
    for (const earlier of [REJECTED, REPLACED]) {
      cleanup();
      mount(append(earlier, requestFor("e2", "c9")));
      expect(card("e2").textContent).toContain(`Approvals left: ${MAX_APPROVALS}`);
    }
  });

  it("blocks the buttons at zero [A11]", () => {
    mount(withBudget(TO_REQUEST, 0));
    expect(card(CARD).textContent).toContain("Approvals left: 0");
    expect(button("Confirm").disabled).toBe(true);
    expect(button("Reject").disabled).toBe(true);
  });

  it("keeps the buttons enabled while the budget is unknown [A11]", () => {
    mount(TO_REQUEST.slice(1)); // no run_started yet
    expect(card(CARD).textContent).not.toContain("Approvals left");
    expect(button("Confirm").disabled).toBe(false);
  });
});

describe("EndorsementPanel closed socket", () => {
  it("turns pending and sending cards into conflicts on 4409 [I4]", () => {
    const { update } = mount();
    update({ closeCode: 4409 });
    expect(stateOf()).toBe("conflict");
    expect(screen.getByText("This request is no longer open")).toBeTruthy();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("also closes a card that was already sending [I4]", () => {
    const { update } = mount();
    fireEvent.click(button("Confirm"));
    expect(stateOf()).toBe("sending");
    update({ closeCode: 4409 });
    expect(stateOf()).toBe("conflict");
  });

  it("does not touch a card the stream already resolved [I4]", () => {
    const { update } = mount(APPROVED);
    update({ closeCode: 4409 });
    expect(stateOf()).toBe("approved");
  });

  it("ignores any other close code: a closed socket resolves nothing [I6]", () => {
    const { update } = mount();
    fireEvent.click(button("Confirm"));
    update({ closeCode: 1006 });
    update({ closeCode: 4422 });
    expect(stateOf()).toBe("sending");
  });
});

describe("EndorsementPanel rendering", () => {
  it("renders an empty labelled region without endorsements [I6]", () => {
    mount(TO_REQUEST, { endorsements: [] });
    expect(screen.getByLabelText("Endorsements").children).toHaveLength(0);
  });

  it("titles each card with its tool name [I6]", () => {
    mount(TO_REQUEST, { toolByCallId: { [CALL]: "pay_bill" } });
    expect(screen.getByRole("heading").textContent).toBe("Confirm pay_bill?");
  });
});

describe("EndorsementPanel callbacks", () => {
  const ids = (set: ReadonlySet<string> | undefined) => [...(set ?? [])].sort();

  it("reports the answered cards once, by content, and never on mount [I4]", () => {
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    const { update } = mount(TO_REQUEST, { onResolvedChange: onResolved });
    expect(onResolved).not.toHaveBeenCalled();

    fireEvent.click(button("Confirm"));
    expect(onResolved).not.toHaveBeenCalled();
    update({ events: APPROVED, onResolvedChange: onResolved });
    expect(onResolved).toHaveBeenCalledTimes(1);
    expect(ids(onResolved.mock.calls[0]?.[0])).toEqual([CARD]);

    // More events and a new callback do not report the same set again.
    update({ events: [...APPROVED] });
    const other = vi.fn<(resolved: ReadonlySet<string>) => void>();
    update({ onResolvedChange: other });
    update({ events: [...APPROVED] });
    expect(onResolved).toHaveBeenCalledTimes(1);
    expect(other).not.toHaveBeenCalled();
  });

  it("counts rejected cards and grows the set as more cards are answered [I4]", () => {
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    const onRejected = vi.fn<(rejected: ReadonlySet<string>) => void>();
    const { update } = mount(TO_REQUEST, {
      onResolvedChange: onResolved,
      onRejectedChange: onRejected,
    });

    fireEvent.click(within(card(CARD)).getByRole("button", { name: "Reject" }));
    // After a rejection the run goes on: another call, and its own card.
    const first = append(TO_REQUEST, LABELED, proposalFor("c9"), requestFor("e2", "c9"));
    update({ events: first });
    expect(ids(onResolved.mock.calls.at(-1)?.[0])).toEqual([CARD]);
    expect(ids(onRejected.mock.calls.at(-1)?.[0])).toEqual([CARD]);

    fireEvent.click(cardButton("e2", "Confirm"));
    update({ events: append(first, decisionFor("ALLOW", "c9"), FINISHED) });
    expect(onResolved).toHaveBeenCalledTimes(2);
    expect(ids(onResolved.mock.calls.at(-1)?.[0])).toEqual([CARD, "e2"].sort());
    expect(ids(onRejected.mock.calls.at(-1)?.[0])).toEqual([CARD]);
  });

  it("does not report a card that is only sending or in conflict [I4]", () => {
    const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
    const { update } = mount(TO_REQUEST, { onResolvedChange: onResolved });
    fireEvent.click(button("Confirm"));
    expect(stateOf()).toBe("sending");
    update({ closeCode: 4409 });
    expect(stateOf()).toBe("conflict");
    expect(onResolved).not.toHaveBeenCalled();
  });

  it("reports a replaced card and a blocked card as answered [I4]", () => {
    for (const events of [REPLACED, BLOCKED]) {
      cleanup();
      const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
      mount(events, { onResolvedChange: onResolved });
      expect(ids(onResolved.mock.calls.at(-1)?.[0])).toEqual([CARD]);
    }
  });
});
