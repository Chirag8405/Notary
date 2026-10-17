import type { Decision, Reason } from "@notary/schema";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as ui from "../src";
import { DecisionStream } from "../src/DecisionStream";
import type { RunView } from "../src/run-view";
import { emptyRunView } from "../src/run-view";
import { load, must, viewOf } from "./golden";

afterEach(cleanup);

function row(callId: string): HTMLElement {
  return must(document.querySelector<HTMLElement>(`[data-call-id="${callId}"]`), `row ${callId}`);
}

function reason(
  outcome: Reason["outcome"],
  code: string,
  check: Reason["check"] = "origin",
): Reason {
  return { check, outcome, code, detail: `${code} detail` } as Reason;
}

function withCall(
  view: RunView,
  callId: string,
  change: Partial<RunView["calls"][number]>,
): RunView {
  return {
    ...view,
    calls: view.calls.map((call) => (call.callId === callId ? { ...call, ...change } : call)),
  };
}

function decision(verdict: Decision["verdict"], reasons: Reason[]): Decision {
  return { verdict, reasons, diff_card: null };
}

describe("DecisionStream rows", () => {
  it("draws one row per call with the verdict, headline and chips [A3]", () => {
    render(<DecisionStream view={viewOf("poisoned_bill.notary")} />);
    expect(document.querySelectorAll("[data-call-id]")).toHaveLength(2);
    expect(row("c1").getAttribute("data-verdict")).toBe("ALLOW");
    const pay = row("c2");
    expect(pay.getAttribute("data-verdict")).toBe("ESCALATE");
    expect(
      within(pay).getByText("LEDGER_NOVEL_ESCALATE", { selector: "[data-headline]" }),
    ).toBeTruthy();
    expect(within(pay).getByText("awaiting your confirmation")).toBeTruthy();

    const payee = must(pay.querySelector<HTMLElement>('[data-chip="payee"]'), "payee chip");
    expect(payee.getAttribute("data-origin")).toBe("email");
    expect(payee.getAttribute("data-integrity")).toBe("untrusted");
    expect(payee.textContent).toBe("payee: email untrusted");
    const amount = must(pay.querySelector<HTMLElement>('[data-chip="amount"]'), "amount chip");
    expect(amount.getAttribute("data-origin")).toBe("user");
    expect(amount.textContent).toBe("amount: user");
    const hashes = [...pay.querySelectorAll<HTMLElement>("[data-hash-link]")];
    expect(hashes).toHaveLength(2);
    for (const hash of hashes) expect(hash.textContent).toMatch(/^[0-9a-f]{8}$/);
  });

  it("keeps the legacy summary text [I6]", () => {
    render(<DecisionStream view={viewOf("poisoned_bill.notary")} />);
    expect(screen.getByText(/ESCALATE for c2/)).toBeTruthy();
    expect(screen.getByText(/ALLOW for c1/)).toBeTruthy();
  });

  it("lists the reasons in the received order [I6]", () => {
    const view = viewOf("poisoned_bill.notary");
    render(<DecisionStream view={view} />);
    const shown = [...row("c2").querySelectorAll<HTMLElement>("[data-check]")];
    const sent = must(view.calls[1]?.decision, "decision").reasons;
    expect(shown.map((r) => r.getAttribute("data-code"))).toEqual(sent.map((r) => r.code));
    expect(shown.map((r) => r.getAttribute("data-outcome"))).toEqual(sent.map((r) => r.outcome));
  });

  it("shows both allowed rows and their effects on the legitimate stream [I1]", () => {
    render(<DecisionStream view={viewOf("legitimate_bill.notary")} />);
    for (const id of ["c1", "c2"]) {
      expect(row(id).getAttribute("data-verdict")).toBe("ALLOW");
      expect(row(id).querySelector("[data-executed]")).not.toBeNull();
      expect(row(id).querySelector("[data-awaiting]")).toBeNull();
    }
  });

  it('shows "no policy check" and the effect on the baseline lanes [A3]', () => {
    for (const name of ["poisoned_bill.undefended", "poisoned_bill.classifier"] as const) {
      const { unmount } = render(<DecisionStream view={viewOf(name)} />);
      for (const id of ["c1", "c2"]) {
        expect(row(id).getAttribute("data-state")).toBe("ungated");
        expect(row(id).hasAttribute("data-verdict")).toBe(false);
        expect(within(row(id)).getByText("no policy check")).toBeTruthy();
        expect(row(id).querySelector("[data-executed]")).not.toBeNull();
      }
      unmount();
    }
  });

  it("never shows pending on a lane without the monitor, even while the run is open [I6]", () => {
    const open: RunView = { ...viewOf("poisoned_bill.classifier"), finished: null };
    render(<DecisionStream view={open} />);
    expect(row("c2").getAttribute("data-state")).toBe("ungated");
    expect(within(row("c2")).getByText("no policy check")).toBeTruthy();
    expect(screen.queryByText("pending decision")).toBeNull();
  });

  it("separates pending from no policy check, and neither on a decided row [I6]", () => {
    const base = viewOf("poisoned_bill.notary");
    const open: RunView = {
      ...withCall(base, "c2", { decision: null, decidedSeq: null }),
      finished: null,
    };
    const { unmount } = render(<DecisionStream view={open} />);
    expect(row("c2").getAttribute("data-state")).toBe("pending");
    expect(within(row("c2")).getByText("pending decision")).toBeTruthy();
    expect(screen.queryByText("no policy check")).toBeNull();
    unmount();

    const done: RunView = withCall(base, "c2", { decision: null, decidedSeq: null });
    render(<DecisionStream view={done} />);
    expect(within(row("c2")).getByText("no policy check")).toBeTruthy();
    expect(row("c1").getAttribute("data-state")).toBe("decided");
    expect(within(row("c1")).queryByText("no policy check")).toBeNull();
    expect(within(row("c1")).queryByText("pending decision")).toBeNull();
  });
});

describe("DecisionStream selection", () => {
  it("reports the call and the value from the hash link [A3]", () => {
    const onSelect = vi.fn();
    render(<DecisionStream view={viewOf("poisoned_bill.notary")} onSelect={onSelect} />);
    const payee = must(row("c2").querySelector<HTMLElement>('[data-chip="payee"]'), "chip");
    const hash = must(payee.parentElement?.querySelector<HTMLElement>("[data-hash-link]"), "hash");
    fireEvent.click(hash);
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith({ callId: "c2", valueId: "v-payee" });
  });

  it("reports the value from a chip and only the call from the row [A3]", () => {
    const onSelect = vi.fn();
    render(<DecisionStream view={viewOf("poisoned_bill.notary")} onSelect={onSelect} />);
    fireEvent.click(must(row("c2").querySelector('[data-chip="amount"]'), "chip"));
    expect(onSelect).toHaveBeenLastCalledWith({ callId: "c2", valueId: "v-amount" });
    fireEvent.click(row("c1"));
    expect(onSelect).toHaveBeenLastCalledWith({ callId: "c1" });
    fireEvent.click(must(row("c2").querySelector("[data-row-select]"), "tool button"));
    expect(onSelect).toHaveBeenLastCalledWith({ callId: "c2" });
    expect(onSelect).toHaveBeenCalledTimes(3);
  });

  it("marks only the selected row, and the mark follows the prop [I6]", () => {
    const view = viewOf("poisoned_bill.notary");
    const { rerender } = render(<DecisionStream view={view} selectedCallId="c2" />);
    const marked = () =>
      [...document.querySelectorAll('[aria-current="true"]')].map((n) =>
        n.getAttribute("data-call-id"),
      );
    expect(marked()).toEqual(["c2"]);
    rerender(<DecisionStream view={view} selectedCallId="c1" />);
    expect(marked()).toEqual(["c1"]);
    rerender(<DecisionStream view={view} />);
    expect(marked()).toEqual([]);
  });
});

describe("DecisionStream synthetic cases", () => {
  it("shows the latest decision and the earlier ones, without the tag after approval [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const escalate = must(base.calls[1]?.decision, "escalation");
    const allow = decision("ALLOW", [reason("pass", "STEP_PASS", "budget")]);
    const approved = withCall(base, "c2", {
      decision: allow,
      decisionHistory: [{ decision: escalate, seq: 50 }],
    });
    const { unmount } = render(<DecisionStream view={approved} />);
    expect(row("c2").getAttribute("data-verdict")).toBe("ALLOW");
    expect(row("c2").querySelector("[data-awaiting]")).toBeNull();
    const earlier = must(row("c2").querySelector("[data-earlier-decisions]"), "earlier decisions");
    expect(earlier.textContent).toBe("earlier decisions: ESCALATE (LEDGER_NOVEL_ESCALATE)");
    unmount();

    render(<DecisionStream view={base} />);
    expect(row("c2").querySelector("[data-awaiting]")).not.toBeNull();
    expect(row("c2").querySelector("[data-earlier-decisions]")).toBeNull();
  });

  it("hides the tag for a resolved endorsement [A3]", () => {
    render(
      <DecisionStream
        view={viewOf("poisoned_bill.notary")}
        resolvedEndorsements={new Set(["e1"])}
      />,
    );
    expect(row("c2").querySelector("[data-awaiting]")).toBeNull();
  });

  it("shows a BLOCK row with a failing marker and flags an executed effect [A4]", () => {
    const base = viewOf("poisoned_bill.notary");
    const block = decision("BLOCK", [
      reason("pass", "STEP_PASS", "scope"),
      reason("fail", "ORIGIN_UNTRUSTED"),
    ]);
    const { unmount } = render(
      <DecisionStream view={withCall(base, "c2", { decision: block, endorsementId: null })} />,
    );
    expect(row("c2").getAttribute("data-verdict")).toBe("BLOCK");
    const failing = must(row("c2").querySelector('[data-outcome="fail"]'), "failing reason");
    expect(failing.getAttribute("data-code")).toBe("ORIGIN_UNTRUSTED");
    expect(failing.textContent).toContain("fail");
    expect(
      within(row("c2")).getByText("ORIGIN_UNTRUSTED", { selector: "[data-headline]" }),
    ).toBeTruthy();
    expect(row("c2").hasAttribute("data-anomaly")).toBe(false);
    unmount();

    const ran = withCall(base, "c2", { decision: block, executed: { summary: "paid", seq: 99 } });
    render(<DecisionStream view={ran} />);
    expect(row("c2").getAttribute("data-anomaly")).toBe("executed after block");
    expect(within(row("c2")).getByText("executed after block")).toBeTruthy();
    expect(row("c1").hasAttribute("data-anomaly")).toBe(false);
  });

  it("writes a tool origin as tool:<name> and copes with a missing preview [A3]", () => {
    const base = viewOf("poisoned_bill.notary");
    const payee = must(base.calls[1]?.args.payee, "payee");
    const toolRef = {
      ...payee,
      label: { ...payee.label, origin: { kind: "tool" as const, name: "read_file" } },
    };
    const view: RunView = {
      ...withCall(base, "c2", { args: { ...must(base.calls[1], "c2").args, payee: toolRef } }),
      values: base.values.filter((v) => v.ref.id !== payee.id),
    };
    render(<DecisionStream view={view} />);
    const chip = must(row("c2").querySelector('[data-chip="payee"]'), "payee chip");
    expect(chip.getAttribute("data-origin")).toBe("tool");
    expect(chip.textContent).toContain("payee: tool:read_file");
    expect(chip.parentElement?.querySelector("[data-preview]")?.textContent).toBe("");
  });
});

describe("DecisionStream props", () => {
  it("keeps the events path: one item per event, as before [I6]", () => {
    const events = load("poisoned_bill.notary");
    render(<DecisionStream events={events} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(events.length);
    expect(screen.getByText(/ESCALATE for c2/)).toBeTruthy();
    expect(document.querySelectorAll("[data-call-id]")).toHaveLength(0);
  });

  it("shows the waiting text for both props when empty [I6]", () => {
    const { unmount } = render(<DecisionStream events={[]} />);
    expect(screen.getByText("Waiting for events…")).toBeTruthy();
    unmount();
    render(<DecisionStream view={emptyRunView} />);
    expect(screen.getByText("Waiting for events…")).toBeTruthy();
  });

  it("exports the mapping and the types [I6]", () => {
    expect(typeof ui.toDecisionRows).toBe("function");
    const rows: readonly ui.DecisionRow[] = ui.toDecisionRows(viewOf("poisoned_bill.notary"));
    const chip: ui.ArgChip | undefined = rows[1]?.args[0];
    const props: ui.DecisionStreamProps = { view: viewOf("poisoned_bill.notary") };
    expect(chip?.param).toBe("amount");
    expect("view" in props).toBe(true);
  });
});
