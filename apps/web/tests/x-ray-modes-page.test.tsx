import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { XRayView } from "@/components/x-ray-view";
import type { XRayViewProps } from "@/components/x-ray-view";
import { LIVE_UNAVAILABLE } from "@/lib/x-ray-state";

import { socketFactory, stubRest } from "./fake-run";
import type { RestState } from "./fake-run";
import { must } from "./golden";

const API = "http://localhost:8000";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function opened(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const sockets = socketFactory();
  stubRest({ modes: ["cassette", "golden", "live"], pending: [], anchor: "missing", ...rest });
  const utils = render(
    <XRayView apiUrl={API} scenario="poisoned_bill" webSocket={sockets.factory} {...props} />,
  );
  await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
  return { ...utils, ...sockets };
}

const modeSelect = () => screen.getByLabelText<HTMLSelectElement>("Mode");
const optionValues = () => [...modeSelect().options].map((o) => o.value);
const socketModes = (page: { urls: () => string[] }) =>
  page.urls().map((u) => new URL(u).searchParams.get("mode"));

describe("x-ray page modes", () => {
  it("defaults to golden and shows exactly the mode the sockets use [I6]", async () => {
    // The server lists the modes alphabetically; a different order must change nothing.
    const page = await opened({}, { modes: ["live", "golden", "cassette"] });
    await waitFor(() => {
      expect(optionValues()).toEqual(["golden", "cassette", "live"]);
    });
    expect(modeSelect().value).toBe("golden");
    expect(new Set(socketModes(page))).toEqual(new Set(["golden"]));
    const live = must(
      [...modeSelect().options].find((o) => o.value === "live"),
      "live option",
    );
    expect(live.textContent).toBe("live (a real Groq model; needs an API key; not reproducible)");
    expect(live.disabled).toBe(false);
  });

  it("keeps the select equal to the sockets' mode when live is chosen in the address [I6]", async () => {
    const page = await opened({ mode: "live" }, { modes: ["cassette", "golden", "live"] });
    await waitFor(() => {
      expect(optionValues()).toEqual(["golden", "cassette", "live"]);
    });
    expect(modeSelect().value).toBe("live");
    expect(new Set(socketModes(page))).toEqual(new Set(["live"]));
  });

  it("opens golden for legitimate_bill on the NOTARY lane, with golden still offered [I6]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = await opened({ scenario: "legitimate_bill" });
    expect(new Set(socketModes(page))).toEqual(new Set(["golden"]));
    expect(modeSelect().value).toBe("golden");
    expect(screen.queryByRole("status")).toBeNull();
    const golden = must(
      [...modeSelect().options].find((o) => o.value === "golden"),
      "golden option",
    );
    expect(golden.disabled).toBe(false);
    expect(page.urls().map((u) => new URL(u).searchParams.get("lane"))).toEqual(["notary"]);
    expect(replace).not.toHaveBeenCalledWith(null, "", expect.stringContaining("mode=cassette"));
  });

  it("keeps golden when the three-lane view is switched on over golden [I6]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = await opened();
    expect(modeSelect().value).toBe("golden");
    fireEvent.click(screen.getByRole("button", { name: "Three-lane view" }));
    await screen.findByLabelText("Three lanes");
    expect(modeSelect().value).toBe("golden");
    expect(screen.queryByRole("status")).toBeNull();
    const lanes = page
      .urls()
      .filter((u) => new URL(u).searchParams.get("mode") === "golden")
      .map((u) => new URL(u).searchParams.get("lane"));
    expect(new Set(lanes)).toEqual(new Set(["notary", "undefended", "classifier"]));
    expect(replace).toHaveBeenLastCalledWith(
      null,
      "",
      "/x-ray?scenario=poisoned_bill&mode=golden&view=three",
    );
  });

  it("opens the three-lane view on golden from the start [I6]", async () => {
    const page = await opened({ initialViewMode: "three-lane" });
    expect(new Set(socketModes(page))).toEqual(new Set(["golden"]));
    expect(modeSelect().value).toBe("golden");
  });

  it("keeps golden when the scenario changes and needs no switch note [I6]", async () => {
    await opened({ scenario: "legitimate_bill" });
    fireEvent.change(screen.getByLabelText("Scenario"), { target: { value: "poisoned_bill" } });
    await screen.findByText(/ESCALATE for c2/);
    expect(screen.queryByRole("status")).toBeNull();
    expect(modeSelect().value).toBe("golden");
  });
});

describe("x-ray page unavailable mode", () => {
  it("explains a closed live stream and offers cassette without retrying [I6]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = await opened({ mode: "live" });
    act(() => {
      must(page.sockets[0], "socket").closeWith(4501, "mode not available");
    });
    expect((await screen.findByRole("alert")).textContent).toBe(LIVE_UNAVAILABLE);
    const button = screen.getByRole("button", { name: "Use cassette instead" });
    expect(page.sockets).toHaveLength(1);

    fireEvent.click(button);
    expect(page.sockets).toHaveLength(2);
    expect(socketModes(page)).toEqual(["live", "cassette"]);
    expect(modeSelect().value).toBe("cassette");
    expect(replace).toHaveBeenLastCalledWith(
      null,
      "",
      "/x-ray?scenario=poisoned_bill&mode=cassette&view=single",
    );
    await screen.findByText(/ESCALATE for c2/);
    expect(screen.queryByRole("button", { name: "Use cassette instead" })).toBeNull();
  });

  it("offers cassette when a live run fails to connect [I6]", async () => {
    const page = await opened({ mode: "live" });
    act(() => {
      must(page.sockets[0], "socket").closeWith(1006, "");
    });
    expect((await screen.findByRole("alert")).textContent).toBe(
      `Could not reach the server at ${API}. Start the server and press Run again.`,
    );
    expect(screen.getByRole("button", { name: "Use cassette instead" })).toBeTruthy();
  });

  it("keeps the generic wording and no button for an unknown scenario [I6]", async () => {
    const page = await opened();
    act(() => {
      must(page.sockets[0], "socket").closeWith(4404, "unknown scenario");
    });
    expect((await screen.findByRole("alert")).textContent).toBe("Unknown scenario.");
    expect(screen.queryByRole("button", { name: "Use cassette instead" })).toBeNull();
  });
});

describe("x-ray page headings", () => {
  const TITLES = [
    "Contract",
    "Provenance graph",
    "Decision stream",
    "Content inspector",
    "What changed",
  ];

  it("prints every panel title once, with one element and one class [I6]", async () => {
    await opened();
    const headings: HTMLElement[] = [];
    for (const name of TITLES) {
      const found = screen.getAllByRole("heading", { name });
      expect(found, name).toHaveLength(1);
      headings.push(must(found[0], name));
    }
    // The oracle panel prints its own title, with the lane next to it.
    const oracle = screen.getAllByRole("heading", { name: /^Oracle/ });
    expect(oracle).toHaveLength(1);
    headings.push(must(oracle[0], "Oracle"));
    expect(screen.queryAllByRole("heading", { name: "Oracle" })).toHaveLength(0);

    expect(new Set(headings.map((h) => h.tagName))).toEqual(new Set(["H2"]));
    expect(new Set(headings.map((h) => h.className))).toEqual(new Set(["text-sm font-semibold"]));
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("titles the three-lane panel once as well [I6]", async () => {
    await opened({ initialViewMode: "three-lane" });
    const found = screen.getAllByRole("heading", { name: "Three lanes" });
    expect(found).toHaveLength(1);
    expect(found[0]?.tagName).toBe("H2");
    expect(found[0]?.className).toBe("text-sm font-semibold");
    expect(screen.getAllByLabelText("Three lanes")).toHaveLength(1);
  });

  it("keeps the component labels unique [I6]", async () => {
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
  });
});
