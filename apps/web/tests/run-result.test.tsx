import { cleanup, render, screen } from "@testing-library/react";
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

describe("ErrorBanner", () => {
  it("renders nothing for null and an alert for text [-]", () => {
    const { container } = render(<ErrorBanner message={null} />);
    expect(container.innerHTML).toBe("");
    render(<ErrorBanner message="boom" />);
    expect(screen.getByRole("alert").textContent).toBe("boom");
  });
});
