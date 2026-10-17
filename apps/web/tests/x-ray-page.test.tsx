import { markerTone } from "@notary/ui";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { XRayView } from "@/components/x-ray-view";
import type { XRayViewProps } from "@/components/x-ray-view";

import { socketFactory, stubRest } from "./fake-run";
import type { RestState } from "./fake-run";
import { must, viewOf } from "./golden";

const API = "http://localhost:8000";
const NOTARY = viewOf("poisoned_bill.notary");
const ANCHOR = { head: "0123456789abcdef0123456789abcdef", length: 7 };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function pendingItem(remaining: number): unknown {
  const endorsement = must(NOTARY.endorsements[0], "an endorsement").endorsement;
  return {
    run_id: must(NOTARY.runId, "run id"),
    endorsement,
    card_text: "payee: DE00ATTACKER0000000001",
    remaining_approvals: remaining,
  };
}

function open(
  props: Partial<XRayViewProps> = {},
  rest: Partial<RestState> = {},
  socketOptions: Parameters<typeof socketFactory>[0] = {},
) {
  const sockets = socketFactory(socketOptions);
  const stub = stubRest({ modes: ["golden"], pending: [], anchor: ANCHOR, ...rest });
  const utils = render(
    <XRayView apiUrl={API} scenario="poisoned_bill" webSocket={sockets.factory} {...props} />,
  );
  return { ...utils, ...sockets, rest: stub };
}

async function opened(
  props: Partial<XRayViewProps> = {},
  rest: Partial<RestState> = {},
  socketOptions: Parameters<typeof socketFactory>[0] = {},
) {
  const page = open(props, rest, socketOptions);
  await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
  return page;
}

function region(label: string): HTMLElement {
  return screen.getByLabelText(label);
}

function row(callId: string): HTMLElement {
  return must(
    region("Decision stream").querySelector<HTMLElement>(`[data-call-id="${callId}"]`),
    `row ${callId}`,
  );
}

function graphNode(id: string): HTMLElement {
  return must(
    region("Graph nodes").querySelector<HTMLElement>(`[data-node-id="${id}"]`),
    `graph node ${id}`,
  );
}

function hashLink(callId: string, param: string): HTMLElement {
  const chip = must(row(callId).querySelector(`[data-chip="${param}"]`), `${param} chip`);
  return must(chip.parentElement?.querySelector<HTMLElement>("[data-hash-link]"), "hash link");
}

function sent(socketUrlPart: string, page: ReturnType<typeof open>): string[] {
  return page.sockets.filter((s) => s.url.includes(socketUrlPart)).flatMap((s) => s.sent);
}

describe("x-ray page regions", () => {
  it("renders the regions of the poisoned NOTARY stream [A3]", async () => {
    await opened();
    const contract = must(NOTARY.contract, "contract");
    const pay = must(
      contract.allowed_tools.find((t) => t.tool === "pay_bill"),
      "pay_bill",
    );
    const marker = must(pay.params.payee, "payee marker");
    const chip = must(
      region("Intent contract").querySelector('[data-param="payee"]'),
      "payee chip",
    );
    expect(chip.getAttribute("data-marker-kind")).toBe(marker.kind);
    expect(chip.getAttribute("data-tone")).toBe(markerTone(marker));

    expect(
      region("Graph nodes").querySelector('[data-node="gate"][data-state="escalate"]'),
    ).not.toBeNull();
    expect(row("c2").getAttribute("data-verdict")).toBe("ESCALATE");
    expect(row("c1").getAttribute("data-verdict")).toBe("ALLOW");
    expect(region("Oracle panel").querySelector('[data-light="attacker"]')).not.toBeNull();
    expect(
      region("Oracle panel").querySelector('[data-light="user"]')?.getAttribute("data-state"),
    ).toBe("pending");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toContain("NOTARY");
  });

  it("shows one row per call, not the event list [I6]", async () => {
    await opened();
    expect(region("Decision stream").querySelectorAll("[data-call-id]")).toHaveLength(2);
    expect(region("Decision stream").querySelector('[data-event-type="run_started"]')).toBeNull();
  });

  it("gives every component label exactly one element [I6]", async () => {
    await opened();
    for (const label of [
      "Intent contract",
      "Provenance graph",
      "Decision stream",
      "Oracle panel",
      "Content inspector",
      "Graph nodes",
    ]) {
      expect(screen.getAllByLabelText(label), label).toHaveLength(1);
    }
    expect(screen.queryAllByLabelText("Three lanes")).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    expect(await screen.findAllByLabelText("Three lanes")).toHaveLength(1);
    expect(screen.getAllByLabelText("Provenance graph")).toHaveLength(1);
  });

  it("lists only the read under 'What changed' for the NOTARY stream [A3]", async () => {
    await opened();
    const items = [...region("What changed").querySelectorAll("li")].map((li) => li.textContent);
    expect(items).toEqual(["read_inbox: read 2 messages"]);
  });

  it("pays silently on the legitimate stream [I1]", async () => {
    await opened({ scenario: "legitimate_bill" });
    expect(screen.queryByRole("group", { name: "Endorsement request" })).toBeNull();
    expect(row("c1").getAttribute("data-verdict")).toBe("ALLOW");
    expect(row("c2").getAttribute("data-verdict")).toBe("ALLOW");
    await waitFor(() => {
      expect(
        region("Oracle panel").querySelector('[data-light="user"]')?.getAttribute("data-state"),
      ).toBe("good");
    });
    expect(region("What changed").querySelectorAll("li")).toHaveLength(2);
  });
});

describe("x-ray page selection", () => {
  it("drives the graph and the inspector from a decision chip [A3]", async () => {
    await opened();
    fireEvent.click(hashLink("c2", "payee"));
    expect(graphNode("v:v-payee").getAttribute("data-selected")).toBe("true");
    expect(graphNode("v:v-amount").getAttribute("data-selected")).toBe("false");
    expect(row("c2").getAttribute("aria-current")).toBe("true");
    const inspector = within(region("Content inspector"));
    expect(inspector.getByTestId("untrusted-tag").textContent).toContain("untrusted");
    expect(inspector.getByTestId("preview").textContent).toBe("DE00ATTACKER0000000001");
  });

  it("marks the row and inspects the first untrusted argument for a gate node [A3]", async () => {
    await opened();
    fireEvent.click(graphNode("g:c2"));
    expect(row("c2").getAttribute("aria-current")).toBe("true");
    expect(row("c1").hasAttribute("aria-current")).toBe(false);
    expect(within(region("Content inspector")).getByTestId("preview").textContent).toBe(
      "DE00ATTACKER0000000001",
    );
  });

  it("clears the selection when the empty graph pane is clicked [I6]", async () => {
    const { container } = await opened();
    fireEvent.click(graphNode("g:c2"));
    expect(row("c2").getAttribute("aria-current")).toBe("true");
    fireEvent.click(must(container.querySelector(".react-flow__pane"), "graph pane"));
    expect(row("c2").hasAttribute("aria-current")).toBe(false);
    expect(region("Content inspector").textContent).toBe("Select a node or chip to inspect it");
  });

  it("resets the selection when the run is started again [I6]", async () => {
    const page = await opened();
    fireEvent.click(graphNode("g:c2"));
    expect(row("c2").getAttribute("aria-current")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Run again" }));
    expect(page.sockets).toHaveLength(2);
    await screen.findByText(/ESCALATE for c2/);
    expect(row("c2").hasAttribute("aria-current")).toBe(false);
  });
});

describe("x-ray page endorsement", () => {
  it("shows the card and sends exactly the approve command [I4]", async () => {
    const page = await opened({}, { pending: [pendingItem(3)] });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    expect(await within(card).findByText("Approvals left: 3")).toBeTruthy();
    expect(row("c2").querySelector("[data-awaiting]")).not.toBeNull();

    fireEvent.click(within(card).getByRole("button", { name: "Confirm" }));
    const frames = sent("lane=notary", page);
    expect(frames).toHaveLength(1);
    expect(JSON.parse(frames[0] ?? "null")).toEqual({
      type: "endorsement_decision",
      run_id: must(NOTARY.runId, "run id"),
      endorsement_id: must(NOTARY.endorsements[0], "endorsement").endorsement.endorsement_id,
      decision: "approve",
    });
  });

  it("clears the 'awaiting your confirmation' tag once the card is answered [I4]", async () => {
    const page = await opened({}, { pending: [pendingItem(3)] });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    await within(card).findByText("Approvals left: 3");
    expect(row("c2").querySelector("[data-awaiting]")).not.toBeNull();

    page.rest.state.pending = [];
    fireEvent.click(within(card).getByRole("button", { name: "Confirm" }));
    await waitFor(() => {
      expect(card.getAttribute("data-state")).toBe("approved");
    });
    await waitFor(() => {
      expect(row("c2").querySelector("[data-awaiting]")).toBeNull();
    });
  });

  it("turns the card into a conflict when the socket closes with 4409 [I4]", async () => {
    const page = await opened({}, { pending: [pendingItem(3)] });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    act(() => {
      must(page.sockets[0], "socket").closeWith(4409, "unknown endorsement");
    });
    await waitFor(() => {
      expect(card.getAttribute("data-state")).toBe("conflict");
    });
    expect(screen.getByRole("alert").textContent).toBe("This request is no longer open.");
  });
});

describe("x-ray page three-lane view", () => {
  it("opens the two baseline sockets and never a second NOTARY socket [A3]", async () => {
    const page = await opened({ mode: "cassette" });
    expect(page.urls().filter((u) => u.includes("lane=notary"))).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    await screen.findByLabelText("Three lanes");
    const lanes = page.urls().map((u) => new URL(u).searchParams.get("lane"));
    expect(lanes.filter((l) => l === "notary")).toHaveLength(1);
    expect(lanes.filter((l) => l === "undefended")).toHaveLength(1);
    expect(lanes.filter((l) => l === "classifier")).toHaveLength(1);
    expect(
      screen.getByRole("button", { name: "Three-lane view" }).getAttribute("aria-pressed"),
    ).toBe("true");
  });

  it("shows the payment under the baseline lanes only [A3]", async () => {
    await opened({ initialViewMode: "three-lane" });
    const lanes = region("Three lanes");
    const effects = (name: string) =>
      within(must(lanes.querySelector<HTMLElement>(`[data-lane="${name}"]`), name)).getByLabelText(
        "Effects",
      ).textContent;
    await waitFor(() => {
      expect(effects("undefended")).toContain("DE00ATTACKER0000000001");
    });
    await waitFor(() => {
      expect(effects("classifier")).toContain("DE00ATTACKER0000000001");
    });
    expect(effects("notary")).toBe("read 2 messages");
    expect(
      [...lanes.querySelectorAll("[data-lane]")].map((el) => el.getAttribute("data-lane")),
    ).toEqual(["undefended", "classifier", "notary"]);
  });

  it("does not show a stream under a lane it does not belong to [A3]", async () => {
    // The server's golden mode ignores the lane and sends the NOTARY stream every time.
    await opened({ initialViewMode: "three-lane" }, {}, { ignoreLane: true });
    const lanes = region("Three lanes");
    const lane = (name: string) =>
      must(lanes.querySelector<HTMLElement>(`[data-lane="${name}"]`), name);
    await waitFor(() => {
      expect(lane("undefended").querySelector("[data-status]")?.getAttribute("data-status")).toBe(
        "error",
      );
    });
    for (const name of ["undefended", "classifier"]) {
      expect(within(lane(name)).getByRole("alert").textContent).toBe(
        `The server sent the notary stream for the ${name} lane. Try another mode.`,
      );
      expect(within(lane(name)).getByLabelText("Effects").textContent).toBe("No effects");
    }
    expect(lane("notary").querySelector("[data-status]")?.getAttribute("data-status")).not.toBe(
      "error",
    );
    expect(within(lane("notary")).getByLabelText("Effects").textContent).toBe("read 2 messages");
  });

  it("disables the toggle with a note for a scenario with one stream [I6]", async () => {
    await opened({ scenario: "legitimate_bill" });
    const toggle = screen.getByRole<HTMLButtonElement>("button", { name: "Three-lane view" });
    expect(toggle.disabled).toBe(true);
    expect(
      screen.getByText("only the NOTARY lane has a recorded stream for this scenario"),
    ).toBeTruthy();
    cleanup();
    await opened({ scenario: "legitimate_bill", initialViewMode: "three-lane" });
    expect(screen.queryByLabelText("Three lanes")).toBeNull();
  });
});

describe("x-ray page anchor and errors", () => {
  it("shows the audit head and length after the run finished [I1]", async () => {
    await opened();
    const footer = await screen.findByLabelText("Audit anchor");
    expect(footer.textContent).toBe(
      `Audit head ${ANCHOR.head.slice(0, 12)} | 7 entries | persisted outside the log`,
    );
  });

  it("shows 'no anchor available' for a 404 and for a failing request [I1]", async () => {
    for (const anchor of ["missing", "fail"] as const) {
      await opened({}, { anchor });
      expect((await screen.findByLabelText("Audit anchor")).textContent).toBe(
        "no anchor available",
      );
      cleanup();
    }
  });

  it("fetches the anchor once per run, however often the page re-renders [I6]", async () => {
    const page = await opened();
    await screen.findByLabelText("Audit anchor");
    fireEvent.click(graphNode("g:c2"));
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    await screen.findByLabelText("Three lanes");
    expect(page.rest.calls.filter((path) => path.endsWith("/anchor"))).toHaveLength(1);
  });

  it("shows the sentence for a closed stream and keeps what was folded [I6]", async () => {
    const page = await opened();
    act(() => {
      must(page.sockets[0], "socket").closeWith(4404, "unknown scenario");
    });
    expect((await screen.findByRole("alert")).textContent).toBe("Unknown scenario.");
    expect(row("c2").getAttribute("data-verdict")).toBe("ESCALATE");
  });

  it("explains an unreachable server [I6]", async () => {
    const page = await opened();
    act(() => {
      must(page.sockets[0], "socket").closeWith(1006, "");
    });
    expect((await screen.findByRole("alert")).textContent).toBe(
      `Could not reach the server at ${API}. Start the server and press Run again.`,
    );
  });
});

describe("x-ray page controls", () => {
  it("offers the modes the server lists, and all three when it cannot be asked [I6]", async () => {
    await opened({}, { modes: ["golden", "cassette"] });
    const select = screen.getByLabelText<HTMLSelectElement>("Mode");
    await waitFor(() => {
      expect([...select.options].map((o) => o.value)).toEqual(["golden", "cassette"]);
    });
    cleanup();

    await opened({}, { modes: "fail" });
    const failed = screen.getByLabelText<HTMLSelectElement>("Mode");
    await waitFor(() => {
      expect([...failed.options].map((o) => o.value)).toEqual(["golden", "cassette", "live"]);
    });
  });

  it("warns that live runs are not reproducible [I6]", async () => {
    await opened({ mode: "live" });
    expect(screen.getByText("live runs are not reproducible")).toBeTruthy();
  });

  it("starts the streams again on 'Run again' [I6]", async () => {
    const page = await opened();
    expect(page.sockets).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Run again" }));
    expect(page.sockets).toHaveLength(2);
    await screen.findByText(/ESCALATE for c2/);
  });

  it("writes the choice to the address and reopens the stream [I6]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = await opened({ mode: "cassette" });
    fireEvent.change(screen.getByLabelText("Scenario"), { target: { value: "legitimate_bill" } });
    expect(replace).toHaveBeenLastCalledWith(
      null,
      "",
      "/x-ray?scenario=legitimate_bill&mode=cassette&view=single",
    );
    expect(page.urls().at(-1)).toContain("/ws/runs/legitimate_bill?lane=notary");
    await waitFor(() => {
      expect(row("c2").getAttribute("data-verdict")).toBe("ALLOW");
    });

    fireEvent.change(screen.getByLabelText("Scenario"), { target: { value: "poisoned_bill" } });
    await screen.findByText(/ESCALATE for c2/);
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    expect(replace).toHaveBeenLastCalledWith(
      null,
      "",
      "/x-ray?scenario=poisoned_bill&mode=cassette&view=three",
    );
  });

  it("writes nothing to localStorage, sessionStorage or cookies [I6]", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const cookie = vi.spyOn(document, "cookie", "set");
    await opened({}, { pending: [pendingItem(3)] });
    fireEvent.click(hashLink("c2", "payee"));
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    fireEvent.click(screen.getByRole("button", { name: "Run again" }));
    await screen.findByText(/ESCALATE for c2/);
    expect(setItem).not.toHaveBeenCalled();
    expect(cookie).not.toHaveBeenCalled();
    expect(document.cookie).toBe("");
  });
});
