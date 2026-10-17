import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import * as ui from "../src";
import { laneLabel } from "../src/goal-lights";
import type { LaneInput } from "../src/lane-summary";
import { emptyRunView } from "../src/run-view";
import type { RunView } from "../src/run-view";
import { ThreeLaneView } from "../src/ThreeLaneView";
import { load, must, viewOf } from "./golden";

afterEach(cleanup);

const PAYMENT = "paid 120.00 EUR to DE00ATTACKER0000000001";

function lanes(): LaneInput[] {
  return [
    { lane: "undefended", view: viewOf("poisoned_bill.undefended"), status: "finished" },
    { lane: "classifier", view: viewOf("poisoned_bill.classifier"), status: "finished" },
    { lane: "notary", view: viewOf("poisoned_bill.notary"), status: "finished" },
  ];
}

function section(lane: string): HTMLElement {
  return must(document.querySelector<HTMLElement>(`[data-lane="${lane}"]`), `lane ${lane}`);
}

function count(lane: string, name: string): string {
  const el = must(section(lane).querySelector(`[data-count="${name}"] span`), `${lane} ${name}`);
  return el.textContent;
}

function effects(lane: string): string[] {
  return [...within(section(lane)).getByLabelText("Effects").querySelectorAll("li")].map(
    (li) => li.textContent,
  );
}

function light(lane: string, which: string): HTMLElement {
  return must(
    section(lane).querySelector<HTMLElement>(`[data-light="${which}"]`),
    `${which} light`,
  );
}

describe("ThreeLaneView lanes", () => {
  it("renders the columns in the given order with the right headings [A3]", () => {
    render(<ThreeLaneView lanes={lanes()} />);
    const headings = [...document.querySelectorAll("[data-lane] h3")].map((h) => h.textContent);
    const classifier = must(viewOf("poisoned_bill.classifier").classifier, "classifier name");
    expect(headings).toEqual(["Undefended", `Classifier-only (stand-in: ${classifier})`, "NOTARY"]);
    expect(headings[1]).toContain("stand-in");
  });

  it("shows the counts of every golden lane [A3]", () => {
    render(<ThreeLaneView lanes={lanes()} />);
    const read = (lane: string) =>
      ["calls", "allowed", "escalated", "blocked", "executed"].map((n) => count(lane, n));
    expect(read("undefended")).toEqual(["2", "0", "0", "0", "2"]);
    expect(read("classifier")).toEqual(["2", "0", "0", "0", "2"]);
    expect(read("notary")).toEqual(["2", "1", "1", "0", "1"]);
  });

  it("shows the payment under undefended and classifier, not under NOTARY [A3]", () => {
    render(<ThreeLaneView lanes={lanes()} />);
    expect(effects("undefended")).toEqual(["read 2 messages", PAYMENT]);
    expect(effects("classifier")).toEqual(["read 2 messages", PAYMENT]);
    expect(effects("notary")).toEqual(["read 2 messages"]);
    expect(within(section("notary")).queryByText(PAYMENT)).toBeNull();
  });

  it("follows the oracle panel rule for the lights [A3]", () => {
    render(<ThreeLaneView lanes={lanes()} />);
    expect(light("undefended", "attacker").getAttribute("data-state")).toBe("bad");
    expect(light("undefended", "attacker").textContent).toContain("Attacker goal reached");
    expect(light("undefended", "user").getAttribute("data-state")).toBe("bad");
    expect(light("classifier", "attacker").getAttribute("data-state")).toBe("bad");
    expect(light("notary", "attacker").getAttribute("data-state")).toBe("good");
    expect(light("notary", "attacker").textContent).toContain("Attacker goal not reached");
    expect(light("notary", "user").getAttribute("data-state")).toBe("pending");
    cleanup();

    render(
      <ThreeLaneView
        lanes={[{ lane: "notary", view: viewOf("legitimate_bill.notary"), status: "finished" }]}
      />,
    );
    expect(light("notary", "user").getAttribute("data-state")).toBe("good");
    expect(light("notary", "attacker").getAttribute("data-state")).toBe("good");
  });

  it("marks the attacker outcome on the lane, and not on a waiting lane [A3]", () => {
    const input: LaneInput[] = [
      ...lanes().slice(0, 3),
      { lane: "classifier", view: emptyRunView, status: "waiting" },
    ];
    render(<ThreeLaneView lanes={input.slice(0, 3)} />);
    expect(section("undefended").getAttribute("data-attacker")).toBe("reached");
    expect(section("classifier").getAttribute("data-attacker")).toBe("reached");
    expect(section("notary").getAttribute("data-attacker")).toBe("stopped");
    cleanup();
    render(<ThreeLaneView lanes={[must(input[3], "waiting lane")]} />);
    expect(section("classifier").hasAttribute("data-attacker")).toBe(false);
  });

  it('shows "no policy check" on the baseline lanes only [I6]', () => {
    render(<ThreeLaneView lanes={lanes()} />);
    expect(within(section("undefended")).getByText("no policy check")).toBeTruthy();
    expect(within(section("classifier")).getByText("no policy check")).toBeTruthy();
    expect(within(section("notary")).queryByText("no policy check")).toBeNull();
  });

  it("does not claim there is no policy check while the lane is still waiting [I6]", () => {
    const view = viewOf("poisoned_bill.undefended");
    render(<ThreeLaneView lanes={[{ lane: "undefended", view, status: "waiting" }]} />);
    expect(within(section("undefended")).queryByText("no policy check")).toBeNull();
  });

  it("counts the latest decision after an approval [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const escalate = must(base.calls[1]?.decision, "the escalation");
    const view: RunView = {
      ...base,
      calls: base.calls.map((call) =>
        call.callId === "c2"
          ? {
              ...call,
              decision: { verdict: "ALLOW" as const, reasons: [], diff_card: null },
              decisionHistory: [{ decision: escalate, seq: 50 }],
            }
          : call,
      ),
    };
    render(<ThreeLaneView lanes={[{ lane: "notary", view, status: "finished" }]} />);
    expect(count("notary", "allowed")).toBe("2");
    expect(count("notary", "escalated")).toBe("0");
  });

  it("keeps the input order instead of sorting [I6]", () => {
    const [undefended, , notary] = lanes();
    render(<ThreeLaneView lanes={[must(notary, "notary"), must(undefended, "undefended")]} />);
    expect(
      [...document.querySelectorAll("[data-lane]")].map((s) => s.getAttribute("data-lane")),
    ).toEqual(["notary", "undefended"]);
  });
});

describe("ThreeLaneView waiting and error lanes", () => {
  it("shows the waiting text and an empty summary with pending lights [I6]", () => {
    render(<ThreeLaneView lanes={[{ lane: "notary", view: emptyRunView, status: "waiting" }]} />);
    expect(screen.getByText(/Waiting for the run/)).toBeTruthy();
    expect(count("notary", "calls")).toBe("0");
    expect(within(section("notary")).getByText("No effects")).toBeTruthy();
    expect(light("notary", "attacker").getAttribute("data-state")).toBe("pending");
    expect(light("notary", "user").getAttribute("data-state")).toBe("pending");
    expect(within(section("notary")).queryByText("no policy check")).toBeNull();
    expect(section("notary").querySelector("[data-outcome]")).toBeNull();
  });

  it("shows the error message without crashing on an empty or partial view [I6]", () => {
    const partial = foldPrefix();
    render(
      <ThreeLaneView
        lanes={[
          { lane: "undefended", view: emptyRunView, status: "error", error: "no such lane" },
          { lane: "notary", view: partial, status: "error" },
        ]}
      />,
    );
    expect(within(section("undefended")).getByText("no such lane")).toBeTruthy();
    expect(
      within(section("undefended")).getByText("error", { selector: "[data-status]" }),
    ).toBeTruthy();
    expect(within(section("notary")).getByRole("alert").textContent).toBe("error");
    expect(Number(count("notary", "calls"))).toBeGreaterThan(0);
  });

  it("names the classifier lane a stand-in before its stream starts [A3]", () => {
    render(
      <ThreeLaneView lanes={[{ lane: "classifier", view: emptyRunView, status: "waiting" }]} />,
    );
    expect(section("classifier").querySelector("h3")?.textContent).toBe(
      "Classifier-only (stand-in)",
    );
  });
});

describe("ThreeLaneView legacy events prop and exports", () => {
  it("still renders the three event columns [I6]", () => {
    const events = load("poisoned_bill.notary");
    render(<ThreeLaneView events={events} />);
    expect(
      [...document.querySelectorAll("[data-lane]")].map((n) => n.getAttribute("data-lane")),
    ).toEqual(["proposed", "decided", "executed"]);
  });

  it("exports the new names and keeps the laneLabel from the oracle panel [I6]", () => {
    expect(typeof ui.summarizeLane).toBe("function");
    expect(typeof ui.laneHeading).toBe("function");
    expect(ui.laneLabel).toBe(laneLabel);
    const input: ui.LaneInput = { lane: "notary", view: emptyRunView, status: "waiting" };
    const status: ui.LaneStatus = input.status;
    const summary: ui.LaneSummary = ui.summarizeLane(input.view);
    const props: ui.ThreeLaneViewProps = { lanes: [input] };
    expect(status).toBe("waiting");
    expect(summary.calls).toBe(0);
    expect("lanes" in props).toBe(true);
  });
});

/** The notary stream cut before any decision: calls exist, the run is not finished. */
function foldPrefix(): RunView {
  const base = viewOf("poisoned_bill.notary");
  return { ...base, finished: null, oracle: null };
}
