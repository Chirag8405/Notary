import { cleanup, render, screen } from "@testing-library/react";
import type { OracleResult } from "@notary/schema";
import { afterEach, describe, expect, it } from "vitest";

import * as ui from "../src";
import { OraclePanel } from "../src/OraclePanel";
import { foldEvents } from "../src/run-view";
import type { RunView } from "../src/run-view";
import { STREAMS, load, must, viewOf } from "./golden";
import type { StreamName } from "./golden";

afterEach(cleanup);

function light(which: "attacker" | "user"): HTMLElement {
  const el = document.querySelector<HTMLElement>(`[data-light="${which}"]`);
  return must(el, `${which} light`);
}

function invariantItems(): HTMLElement[] {
  return [...screen.getByLabelText("World-state oracle").querySelectorAll<HTMLElement>("li")];
}

function withOracle(view: RunView, oracle: OracleResult | null): RunView {
  return { ...view, oracle };
}

function oracleOf(view: RunView): OracleResult {
  return must(view.oracle, "the oracle");
}

describe("OraclePanel on the golden streams", () => {
  it("shows the undefended stream red [A3]", () => {
    const view = viewOf("poisoned_bill.undefended");
    expect(oracleOf(view).attacker_goal_reached).toBe(true);
    render(<OraclePanel view={view} />);
    expect(light("attacker").getAttribute("data-state")).toBe("bad");
    expect(light("attacker").textContent).toContain("Attacker goal reached");
  });

  it("shows the classifier stream red [A3]", () => {
    const view = viewOf("poisoned_bill.classifier");
    expect(oracleOf(view).attacker_goal_reached).toBe(true);
    render(<OraclePanel view={view} />);
    expect(light("attacker").getAttribute("data-state")).toBe("bad");
  });

  it("shows the NOTARY stream green with the user goal pending [A3]", () => {
    const view = viewOf("poisoned_bill.notary");
    expect(oracleOf(view).attacker_goal_reached).toBe(false);
    expect(oracleOf(view).user_goal_achieved).toBe(false);
    expect(view.endorsements.length).toBeGreaterThan(0);
    render(<OraclePanel view={view} />);
    expect(light("attacker").getAttribute("data-state")).toBe("good");
    expect(light("attacker").textContent).toContain("Attacker goal not reached");
    expect(light("user").getAttribute("data-state")).toBe("pending");
    expect(light("user").textContent).toContain("User goal pending");
  });

  it("shows the legitimate stream with both lights good [I1]", () => {
    const view = viewOf("legitimate_bill.notary");
    expect(oracleOf(view).user_goal_achieved).toBe(true);
    render(<OraclePanel view={view} />);
    expect(light("user").getAttribute("data-state")).toBe("good");
    expect(light("attacker").getAttribute("data-state")).toBe("good");
  });

  it("shows the real invariant states of every stream [I6]", () => {
    for (const name of STREAMS) {
      const view = viewOf(name);
      const { unmount } = render(<OraclePanel view={view} />);
      const items = invariantItems();
      expect(items.map((i) => i.textContent)).toEqual(["I1", "I2", "I3", "I4", "I5", "I6"]);
      for (const item of items) {
        const reported = oracleOf(view).invariants.find((x) => x.id === item.textContent);
        expect(item.getAttribute("data-state"), name).toBe(reported?.passed ? "pass" : "fail");
      }
      unmount();
    }
  });
});

describe("OraclePanel invariants", () => {
  it("renders six unknown items when there is no oracle [I6]", () => {
    render(<OraclePanel view={withOracle(viewOf("poisoned_bill.notary"), null)} />);
    const items = invariantItems();
    expect(items).toHaveLength(6);
    for (const item of items) expect(item.getAttribute("data-state")).toBe("unknown");
    expect(light("attacker").getAttribute("data-state")).toBe("pending");
    expect(light("user").getAttribute("data-state")).toBe("pending");
    expect(light("attacker").textContent).toContain("Attacker goal unknown");
  });

  it("prints the detail of a failed invariant as visible text [I6]", () => {
    const view = viewOf("poisoned_bill.undefended");
    render(<OraclePanel view={view} />);
    const failed = oracleOf(view).invariants.filter((i) => !i.passed);
    expect(failed.length).toBeGreaterThan(0);
    const list = screen.getByLabelText("Failed invariants");
    for (const item of failed) expect(list.textContent).toContain(item.detail);
  });

  it("prints the detail of a synthetic failing invariant [I6]", () => {
    const base = viewOf("legitimate_bill.notary");
    const oracle = oracleOf(base);
    const invariants = oracle.invariants.map((i) =>
      i.id === "I4" ? { ...i, passed: false, detail: "synthetic failure detail" } : i,
    );
    render(<OraclePanel view={withOracle(base, { ...oracle, invariants })} />);
    expect(screen.getByText(/synthetic failure detail/)).toBeTruthy();
    expect(invariantItems()[3]?.getAttribute("data-state")).toBe("fail");
  });

  it("does not throw on missing or extra invariants [I6]", () => {
    const base = viewOf("legitimate_bill.notary");
    const oracle = oracleOf(base);
    const pick = (id: string) =>
      must(
        oracle.invariants.find((i) => i.id === id),
        id,
      );
    const extra = { ...pick("I1"), id: "I9" } as unknown as OracleResult["invariants"][number];
    const result: OracleResult = { ...oracle, invariants: [pick("I1"), pick("I3"), extra] };
    render(<OraclePanel view={withOracle(base, result)} />);
    expect(invariantItems().map((i) => i.getAttribute("data-state"))).toEqual([
      "pass",
      "unknown",
      "pass",
      "unknown",
      "unknown",
      "unknown",
    ]);
  });
});

describe("OraclePanel user light and banner", () => {
  function notaryUnresolved(): RunView {
    return viewOf("poisoned_bill.notary");
  }

  it("turns bad only after finish with nothing unresolved [A3]", () => {
    const settled: RunView = { ...notaryUnresolved(), endorsements: [] };
    const { unmount } = render(<OraclePanel view={settled} />);
    expect(light("user").getAttribute("data-state")).toBe("bad");
    expect(light("user").textContent).toContain("User goal not achieved");
    unmount();

    render(<OraclePanel view={settled} unresolvedEndorsements={1} />);
    expect(light("user").getAttribute("data-state")).toBe("pending");
  });

  it("lets the unresolvedEndorsements prop override the default [A3]", () => {
    const view = notaryUnresolved();
    const { unmount } = render(<OraclePanel view={view} />);
    expect(light("user").getAttribute("data-state")).toBe("pending");
    unmount();
    render(<OraclePanel view={view} unresolvedEndorsements={0} />);
    expect(light("user").getAttribute("data-state")).toBe("bad");
  });

  it("stays pending while the run is open [A3]", () => {
    const open: RunView = { ...notaryUnresolved(), endorsements: [], finished: null };
    render(<OraclePanel view={open} />);
    expect(light("user").getAttribute("data-state")).toBe("pending");
  });

  it("shows the banner only after run_finished [I6]", () => {
    for (const name of STREAMS) {
      const view = viewOf(name);
      const finished = must(view.finished, "finished");
      const { container, unmount } = render(<OraclePanel view={view} />);
      const banner = must(container.querySelector("[data-outcome]"), "banner");
      expect(banner.getAttribute("data-outcome")).toBe(finished.outcome);
      expect(banner.textContent).toContain(finished.summary);
      unmount();

      const events = load(name);
      const cut = events.findIndex((e) => e.type === "run_finished");
      const prefix = foldEvents(events.slice(0, cut));
      expect(prefix.finished).toBeNull();
      const again = render(<OraclePanel view={prefix} />);
      expect(again.container.querySelector("[data-outcome]")).toBeNull();
      again.unmount();
    }
  });
});

describe("OraclePanel presentation", () => {
  const LANES: [StreamName, string][] = [
    ["poisoned_bill.notary", "NOTARY"],
    ["poisoned_bill.classifier", "Classifier-only (stand-in)"],
    ["poisoned_bill.undefended", "Undefended"],
  ];

  it("shows the lane label next to the title [I6]", () => {
    for (const [name, label] of LANES) {
      const { container, unmount } = render(<OraclePanel view={viewOf(name)} />);
      expect(container.querySelector("[data-lane-label]")?.textContent).toBe(label);
      unmount();
    }
    const none = render(<OraclePanel view={{ ...viewOf("poisoned_bill.notary"), lane: null }} />);
    expect(none.container.querySelector("[data-lane-label]")).toBeNull();
  });

  it("gives each light text and a glyph, not color alone [I6]", () => {
    for (const name of STREAMS) {
      const { unmount } = render(<OraclePanel view={viewOf(name)} />);
      for (const which of ["attacker", "user"] as const) {
        const el = light(which);
        const glyph = must(el.querySelector('[aria-hidden="true"]'), "glyph");
        expect(glyph.textContent).not.toBe("");
        expect(el.textContent.replace(glyph.textContent, "").trim()).not.toBe("");
      }
      unmount();
    }
  });

  it("is pure over the view [I6]", () => {
    const view = viewOf("poisoned_bill.notary");
    const before = JSON.stringify(view);
    const first = render(<OraclePanel view={view} />);
    const html = first.container.innerHTML;
    first.unmount();
    const second = render(<OraclePanel view={viewOf("poisoned_bill.notary")} />);
    expect(second.container.innerHTML).toBe(html);
    expect(JSON.stringify(view)).toBe(before);
  });

  it("exports the panel, the mapping and the lane label [I6]", () => {
    expect(ui.OraclePanel).toBe(OraclePanel);
    expect(typeof ui.goalLights).toBe("function");
    expect(typeof ui.laneLabel).toBe("function");
    const lights: ui.GoalLights = ui.goalLights(null);
    const state: ui.LightState = lights.user;
    const props: ui.OraclePanelProps = { view: viewOf("poisoned_bill.notary") };
    expect(state).toBe("pending");
    expect(props.view.lane).toBe("notary");
  });
});
