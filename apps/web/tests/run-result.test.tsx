import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ErrorBanner } from "@/components/error-banner";
import { RunResult } from "@/components/run-result";

import { load } from "./golden";

afterEach(cleanup);

describe("RunResult", () => {
  it("shows the NOTARY run: attacker not reached, an ESCALATE row [A3]", () => {
    render(<RunResult title="NOTARY lane" events={load("poisoned_bill.notary")} />);
    expect(screen.getByText("Attacker goal not reached")).toBeTruthy();
    expect(screen.getAllByText(/ESCALATE/).length).toBeGreaterThan(0);
  });

  it("shows the undefended run: attacker reached [A3]", () => {
    render(<RunResult title="Undefended" events={load("poisoned_bill.undefended")} />);
    expect(screen.getByText("Attacker goal reached")).toBeTruthy();
  });

  it("an empty run says so and shows no oracle [-]", () => {
    render(<RunResult title="Empty" events={[]} />);
    expect(screen.getByText("No events")).toBeTruthy();
    expect(screen.queryByText(/Attacker goal/)).toBeNull();
  });
});

describe("RunResult replay", () => {
  const notary = load("poisoned_bill.notary");

  function position(): string {
    return screen.getByTestId("replay-position").textContent;
  }

  function click(name: string) {
    fireEvent.click(screen.getByRole("button", { name }));
  }

  it("opens on the whole run, with the player at its end [A3]", () => {
    render(<RunResult title="NOTARY" events={notary} />);
    expect(position()).toBe(`Event ${notary.length} of ${notary.length}`);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Next" }).disabled).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Last" }).disabled).toBe(true);
    expect(screen.getByRole("group", { name: "NOTARY: replay" })).toBeTruthy();
    expect(screen.getByText("Attacker goal not reached")).toBeTruthy();
  });

  it("at position 0 there are no decision rows and the attacker light is unknown [A3]", () => {
    render(<RunResult title="NOTARY" events={notary} />);
    click("First");
    expect(position()).toBe(`Start (0 of ${notary.length})`);
    expect(screen.queryAllByText(/ESCALATE/)).toHaveLength(0);
    expect(screen.getByText("Attacker goal unknown")).toBeTruthy();
    expect(screen.queryByText("Attacker goal not reached")).toBeNull();
  });

  it("stepping with Next brings the ESCALATE in, and Last ends on the verdict [A3]", () => {
    render(<RunResult title="NOTARY" events={notary} />);
    click("First");
    let steps = 0;
    while (screen.queryAllByText(/ESCALATE/).length === 0) {
      click("Next");
      steps += 1;
      expect(steps).toBeLessThanOrEqual(notary.length);
    }
    const escalate = notary.findIndex(
      (event) => event.type === "decision_made" && event.decision.verdict === "ESCALATE",
    );
    expect(steps).toBe(escalate + 1); // the row appears with the decision_made event
    expect(screen.getByText("Attacker goal unknown")).toBeTruthy(); // the oracle has not run yet
    click("Last");
    expect(position()).toBe(`Event ${notary.length} of ${notary.length}`);
    expect(screen.getByText("Attacker goal not reached")).toBeTruthy();
    expect(screen.getAllByText(/ESCALATE/).length).toBeGreaterThan(0);
  });

  it("Previous steps back one event at a time: the oracle verdict leaves with its event [A3]", () => {
    const undefended = load("poisoned_bill.undefended");
    render(<RunResult title="Undefended" events={undefended} />);
    expect(screen.getByText("Attacker goal reached")).toBeTruthy();
    const oracle = undefended.findIndex((event) => event.type === "oracle_updated");
    const toKeepIt = undefended.length - (oracle + 1); // events after the oracle event
    for (let step = 0; step < toKeepIt; step += 1) click("Previous");
    expect(position()).toBe(`Event ${oracle + 1} of ${undefended.length}`);
    expect(screen.getByText("Attacker goal reached")).toBeTruthy(); // the oracle event is still in
    click("Previous");
    expect(position()).toBe(`Event ${oracle} of ${undefended.length}`);
    expect(screen.queryByText("Attacker goal reached")).toBeNull();
    expect(screen.getByText("Attacker goal unknown")).toBeTruthy();
  });

  it("another run opens on its own end, not on the position of the last one [A3]", () => {
    const { rerender } = render(<RunResult title="Run" events={notary} />);
    click("First");
    const undefended = load("poisoned_bill.undefended");
    rerender(<RunResult title="Run" events={undefended} />);
    expect(position()).toBe(`Event ${undefended.length} of ${undefended.length}`);
    expect(screen.getByText("Attacker goal reached")).toBeTruthy();
  });

  it("an empty run has no player", () => {
    render(<RunResult title="Empty" events={[]} />);
    expect(screen.queryByRole("group", { name: "Empty: replay" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Next" })).toBeNull();
  });
});

describe("ErrorBanner", () => {
  it("renders nothing for null and an alert for text [-]", () => {
    const { container } = render(<ErrorBanner message={null} />);
    expect(container.innerHTML).toBe("");
    render(<ErrorBanner message="boom" />);
    expect(screen.getByRole("alert").textContent).toBe("boom");
  });
});
