import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Home from "@/app/page";
import { XRayView } from "@/components/x-ray-view";
import type { XRayViewProps } from "@/components/x-ray-view";
import { DEMO_STEPS, stepUrl } from "@/lib/demo-steps";

import { socketFactory, stubRest } from "./fake-run";
import type { RestState } from "./fake-run";
import { must, viewOf } from "./golden";

const API = "http://localhost:8000";
const NOTARY = viewOf("poisoned_bill.notary");

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function pendingItem(): unknown {
  return {
    run_id: must(NOTARY.runId, "run id"),
    endorsement: must(NOTARY.endorsements[0], "an endorsement").endorsement,
    card_text: "",
    remaining_approvals: 3,
  };
}

function open(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const sockets = socketFactory();
  stubRest({
    modes: ["cassette", "golden", "live"],
    pending: [pendingItem()],
    anchor: "missing",
    ...rest,
  });
  const utils = render(
    <XRayView apiUrl={API} scenario="poisoned_bill" webSocket={sockets.factory} {...props} />,
  );
  return { ...utils, ...sockets };
}

async function opened(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const page = open(props, rest);
  await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
  return page;
}

const stepButton = (id: number): HTMLElement =>
  must(document.querySelector<HTMLElement>(`[data-step="${id}"]`), `step button ${id}`);

const guideText = (id: number): string =>
  must(document.querySelector(`[data-demo-guide="${id}"]`), `guide ${id}`).textContent;

function lanesOf(urls: string[], mode: string): string[] {
  return urls
    .map((url) => new URL(url))
    .filter((url) => url.searchParams.get("mode") === mode)
    .map((url) => `${url.pathname.replace("/ws/runs/", "")}:${url.searchParams.get("lane")}`);
}

describe("the root", () => {
  it("redirects to the first demo step [I6]", () => {
    let thrown: unknown = null;
    try {
      Home();
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    const digest = thrown instanceof Error && "digest" in thrown ? String(thrown.digest) : "";
    expect(digest.startsWith("NEXT_REDIRECT")).toBe(true);
    expect(digest).toContain(stepUrl(1));
  });
});

describe("the demo steps", () => {
  it("shows four step buttons, with the first one active on the demo address [I6]", async () => {
    await opened({ mode: "cassette", initialViewMode: "three-lane" });
    expect(screen.getAllByLabelText("Demo steps")).toHaveLength(1);
    const buttons = [...document.querySelectorAll("[data-step]")];
    expect(buttons.map((b) => b.getAttribute("data-step"))).toEqual(["1", "2", "3", "4"]);
    expect(stepButton(1).getAttribute("aria-current")).toBe("step");
    expect(stepButton(2).hasAttribute("aria-current")).toBe(false);
    expect(screen.getAllByRole("note")).toHaveLength(1);
    expect(guideText(1)).toContain(must(DEMO_STEPS[0], "step 1").description);
  });

  it("updates the address, the sockets and the guide on every click [A3]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = await opened();

    fireEvent.click(stepButton(1));
    await screen.findByLabelText("Three lanes");
    expect(replace).toHaveBeenLastCalledWith(null, "", stepUrl(1));
    expect(new Set(lanesOf(page.urls(), "cassette"))).toEqual(
      new Set(["poisoned_bill:notary", "poisoned_bill:undefended", "poisoned_bill:classifier"]),
    );
    // One NOTARY socket for this run, whatever else is shown.
    expect(lanesOf(page.urls(), "cassette").filter((l) => l.endsWith(":notary"))).toHaveLength(1);
    expect(stepButton(1).getAttribute("aria-current")).toBe("step");
    expect(guideText(1)).toContain(must(DEMO_STEPS[0], "step 1").description);
    const opened1 = page.urls().length;

    // Step 2 is the same screen: only the address and the guide change, no socket is opened.
    fireEvent.click(stepButton(2));
    expect(replace).toHaveBeenLastCalledWith(null, "", stepUrl(2));
    expect(page.urls()).toHaveLength(opened1);
    expect(stepButton(2).getAttribute("aria-current")).toBe("step");
    expect(stepButton(1).hasAttribute("aria-current")).toBe(false);
    expect(guideText(2)).toContain(must(DEMO_STEPS[1], "step 2").description);

    // Step 3 drops the baseline lanes and keeps the NOTARY stream.
    fireEvent.click(stepButton(3));
    expect(replace).toHaveBeenLastCalledWith(null, "", stepUrl(3));
    expect(page.urls()).toHaveLength(opened1);
    expect(screen.queryByLabelText("Three lanes")).toBeNull();
    expect(guideText(3)).toContain("Reject");
    await screen.findByRole("group", { name: "Endorsement request" });

    // Step 4 opens the legitimate bill on the NOTARY lane.
    fireEvent.click(stepButton(4));
    expect(replace).toHaveBeenLastCalledWith(null, "", stepUrl(4));
    expect(page.urls().at(-1)).toContain("/ws/runs/legitimate_bill?lane=notary&mode=cassette");
    expect(guideText(4)).toContain(must(DEMO_STEPS[3], "step 4").description);
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: "Endorsement request" })).toBeNull();
    });
  });

  it("reads step 2 from the address [I6]", async () => {
    await opened({ mode: "cassette", initialViewMode: "three-lane", initialStep: 2 });
    expect(stepButton(2).getAttribute("aria-current")).toBe("step");
    expect(guideText(2)).toContain(must(DEMO_STEPS[1], "step 2").description);
  });

  it("highlights no step and shows no guide on a screen that is none [I6]", async () => {
    await opened();
    expect(document.querySelector('[aria-current="step"]')).toBeNull();
    expect(screen.queryByRole("note")).toBeNull();
  });
});

describe("the header", () => {
  it("shows the status as a badge in each state [I6]", async () => {
    const connecting = open({ mode: "cassette" });
    expect(document.querySelector("[data-status]")?.getAttribute("data-status")).toBe("connecting");
    expect(document.querySelector("[data-status]")?.getAttribute("data-variant")).toBe("muted");
    await screen.findAllByText(/ESCALATE for c2/);
    expect(document.querySelector("[data-status]")?.getAttribute("data-variant")).toBe("secondary");
    expect(document.querySelector("[data-status]")?.textContent).toBe("open");
    act(() => {
      must(connecting.sockets[0], "socket").closeWith(1000, "");
    });
    await waitFor(() => {
      expect(document.querySelector("[data-status]")?.getAttribute("data-variant")).toBe("default");
    });
    expect(document.querySelector("[data-status]")?.textContent).toBe("finished");
    cleanup();

    const failing = await opened({ mode: "cassette" });
    act(() => {
      must(failing.sockets[0], "socket").closeWith(4404, "unknown scenario");
    });
    await waitFor(() => {
      expect(document.querySelector("[data-status]")?.getAttribute("data-variant")).toBe(
        "destructive",
      );
    });
  });

  it("puts the lane label in the single h1, under a small NOTARY line [I6]", async () => {
    await opened({ mode: "cassette" });
    const h1 = screen.getAllByRole("heading", { level: 1 });
    expect(h1).toHaveLength(1);
    expect(h1[0]?.textContent).toContain("Trust X-ray");
    expect(h1[0]?.textContent).toContain("NOTARY");
  });
});

describe("the advanced controls", () => {
  it("are collapsed, hold the selects and the toggle, and leave Run again outside [I6]", async () => {
    await opened({ mode: "cassette" });
    const details = must(document.querySelector("details"), "advanced details");
    expect(details.open).toBe(false);
    expect(within(details).getByText("Advanced")).toBeTruthy();
    expect(within(details).getByLabelText("Scenario")).toBeTruthy();
    expect(within(details).getByLabelText("Mode")).toBeTruthy();
    expect(within(details).getByRole("button", { name: "Three-lane view" })).toBeTruthy();
    const run = screen.getByRole("button", { name: "Run again" });
    expect(details.contains(run)).toBe(false);
    for (const select of details.querySelectorAll("select")) {
      expect(select.className).toContain("border-input");
      expect(select.className).toContain("h-9");
    }
  });

  it("stay open when a new run starts [I6]", async () => {
    await opened({ mode: "cassette" });
    const details = must(document.querySelector("details"), "advanced details");
    fireEvent.click(must(details.querySelector("summary"), "summary"));
    await waitFor(() => {
      expect(details.open).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: "Run again" }));
    await screen.findAllByText(/ESCALATE for c2/);
    expect(must(document.querySelector("details"), "details").open).toBe(true);
  });
});

describe("the endorsement buttons", () => {
  it("are real, enabled buttons with a clear hierarchy: Reject filled, Confirm outlined [I4]", async () => {
    await opened({ mode: "cassette" });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    const buttons = within(card).getAllByRole<HTMLButtonElement>("button");
    expect(buttons.map((b) => b.textContent)).toEqual([
      "Confirm",
      "Reject",
      "Use nearest known value",
    ]);
    for (const button of buttons) {
      expect(button.tagName).toBe("BUTTON");
      expect(button.type).toBe("button");
      expect(button.disabled).toBe(false);
      expect(button.className).toContain("cursor-pointer");
      expect(button.className).toContain("h-9");
    }
    const [confirm, reject] = buttons;
    expect(reject?.className).toContain("bg-primary");
    expect(reject?.className).toContain("text-primary-foreground");
    expect(confirm?.className).toContain("border-amber-500");
    expect(confirm?.className).not.toContain("bg-primary");
    expect(document.activeElement).not.toBe(confirm);
    expect(document.activeElement).not.toBe(reject);
  });
});
