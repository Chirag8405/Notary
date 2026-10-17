// The tab's read token (#235): one per tab, on every cassette/live socket and on the pending list,
// and the panel's rule that only a successful list resolves a card.
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
const TOKEN = "123e4567-e89b-12d3-a456-426614174000";
const CARD_ID = must(NOTARY.endorsements[0], "an endorsement").endorsement.endorsement_id;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function pendingItem(id: string, remaining = 3): unknown {
  const base = must(NOTARY.endorsements[0], "an endorsement").endorsement;
  return {
    run_id: must(NOTARY.runId, "run id"),
    endorsement: { ...base, endorsement_id: id },
    card_text: "",
    remaining_approvals: remaining,
  };
}

async function open(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const sockets = socketFactory();
  const makeToken = vi.fn(() => TOKEN);
  const stub = stubRest({
    modes: ["live", "cassette", "golden"],
    pending: [pendingItem(CARD_ID)],
    anchor: ANCHOR,
    ...rest,
  });
  const utils = render(
    <XRayView
      apiUrl={API}
      scenario="poisoned_bill"
      webSocket={sockets.factory}
      makeToken={makeToken}
      {...props}
    />,
  );
  await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
  return { ...utils, ...sockets, rest: stub, makeToken };
}

const cardState = (): string | null =>
  must(
    document.querySelector<HTMLElement>(`[data-endorsement-id="${CARD_ID}"]`),
    "the card",
  ).getAttribute("data-state");

async function confirm(): Promise<void> {
  const card = await screen.findByRole("group", { name: "Endorsement request" });
  await act(async () => {
    fireEvent.click(within(card).getByRole("button", { name: "Confirm" }));
    await Promise.resolve();
  });
}

const tokenOf = (url: string): string | null => new URL(url).searchParams.get("token");

describe("the tab's read token on the sockets", () => {
  it("is on the cassette socket and on every socket of the three-lane view [I4]", async () => {
    const page = await open({ mode: "cassette", initialViewMode: "three-lane" });
    expect(page.sockets.length).toBeGreaterThanOrEqual(3);
    expect(page.urls().map(tokenOf)).toEqual(page.urls().map(() => TOKEN));
    expect(page.urls().every((url) => url.includes("mode=cassette"))).toBe(true);
  });

  it("is on a live socket too [I4]", async () => {
    const page = await open({ mode: "live" });
    expect(page.urls().map(tokenOf)).toEqual([TOKEN]);
  });

  it("is not sent in golden mode [I6]", async () => {
    const page = await open({ mode: "golden" });
    expect(page.urls().map(tokenOf)).toEqual([null]);
    expect(page.urls().every((url) => !url.includes("token"))).toBe(true);
  });

  it("is made once per tab, not per render, and survives Run again [I4]", async () => {
    const page = await open({ mode: "cassette" });
    expect(page.makeToken).toHaveBeenCalledTimes(1);
    page.rerender(
      <XRayView
        apiUrl={API}
        scenario="poisoned_bill"
        mode="cassette"
        webSocket={page.factory}
        makeToken={page.makeToken}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /run again/i }));
    await waitFor(() => {
      expect(page.sockets.length).toBeGreaterThanOrEqual(2);
    });
    expect(page.makeToken).toHaveBeenCalledTimes(1);
    expect(new Set(page.urls().map(tokenOf))).toEqual(new Set([TOKEN]));
  });

  it("makes a different, well-formed token for every tab by default [I4]", async () => {
    const urls: string[] = [];
    for (let tab = 0; tab < 2; tab += 1) {
      const sockets = socketFactory();
      const view = render(
        <XRayView
          apiUrl={API}
          scenario="poisoned_bill"
          mode="cassette"
          webSocket={sockets.factory}
        />,
      );
      await waitFor(() => {
        expect(sockets.sockets).toHaveLength(1);
      });
      urls.push(...sockets.urls());
      view.unmount();
    }
    const [first, second] = urls.map((url) => tokenOf(url) ?? "");
    expect(first).toMatch(/^[A-Za-z0-9_-]{32,128}$/);
    expect(second).toMatch(/^[A-Za-z0-9_-]{32,128}$/);
    expect(first).not.toBe(second);
  });
});

describe("the tab's read token on the pending list", () => {
  it("is sent as X-Notary-Token and never in the path or the query [I4]", async () => {
    const page = await open({ mode: "cassette" });
    await waitFor(() => {
      expect(page.rest.tokens.length).toBeGreaterThan(0);
    });
    expect(new Set(page.rest.tokens)).toEqual(new Set([TOKEN]));
    expect(page.rest.calls.filter((path) => path.endsWith("/endorsements"))).not.toHaveLength(0);
    expect(page.rest.calls.every((path) => !path.includes(TOKEN))).toBe(true);
  });
});

describe("only a successful list resolves a card", () => {
  it("a 200 list without the card, even an empty one, resolves it [I4]", async () => {
    const page = await open({ mode: "cassette" });
    expect(cardState()).toBe("pending");
    page.rest.state.pending = [];
    await confirm();
    await waitFor(() => {
      expect(cardState()).toBe("approved");
    });
  });

  it("a 200 list with other cards but not this one resolves it [I4]", async () => {
    const page = await open({ mode: "cassette" });
    page.rest.state.pending = [pendingItem("e-other", 2)];
    await confirm();
    await waitFor(() => {
      expect(cardState()).toBe("approved");
    });
  });

  it("a 200 list that still has the card keeps it sending [I4]", async () => {
    await open({ mode: "cassette" });
    await confirm();
    expect(cardState()).toBe("sending");
  });

  it("an HTTP error leaves the card as it was [I4]", async () => {
    const page = await open({ mode: "cassette" });
    page.rest.state.pendingStatus = 500;
    page.rest.state.pending = [];
    await confirm();
    expect(page.rest.tokens.length).toBeGreaterThan(1);
    expect(cardState()).toBe("sending");
  });

  it("a request that fails leaves the card as it was [I4]", async () => {
    const page = await open({ mode: "cassette" });
    const real = page.rest.fetchMock.getMockImplementation();
    page.rest.fetchMock.mockImplementation((input) => {
      const url = input instanceof Request ? input.url : String(input);
      return new URL(url).pathname.endsWith("/endorsements")
        ? Promise.reject(new Error("network down"))
        : (real?.(input) ?? Promise.reject(new Error("no stub")));
    });
    await confirm();
    expect(cardState()).toBe("sending");
  });

  it("a closed socket leaves the card as it was [I4]", async () => {
    const page = await open({ mode: "cassette" });
    await confirm();
    expect(cardState()).toBe("sending");
    await act(async () => {
      must(page.sockets[0], "the socket").closeWith(1006, "");
      await Promise.resolve();
    });
    expect(cardState()).toBe("sending");
  });
});
