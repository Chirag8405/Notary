import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { AttackRunResponse } from "@notary/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AttackLibraryPanel } from "@/components/attack-library-panel";
import { PANELS } from "@/components/playground-panels";
import { DEFERRED_TEXT, PRIMARY_STOPS } from "@/lib/attack-library";

import { fixture, stubPlayground } from "./playground-fixtures";
import type { Recorded } from "./playground-fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const API = "http://localhost:8000";

function stub(overrides: Record<string, Recorded> = {}) {
  return stubPlayground((request) => {
    if (request.path === "/attacks") return fixture("attacks.list");
    const override = overrides[request.path];
    if (override !== undefined) return override;
    if (request.path === "/playground/attacks/A3/run") return fixture("attack.A3");
    if (request.path === "/playground/attacks/A13/run") return fixture("attack.A13");
    if (request.path === "/playground/attacks/B1/run") return fixture("attack.B1");
    return undefined;
  });
}

async function loaded() {
  render(<AttackLibraryPanel apiUrl={API} />);
  await screen.findByText("Data-only poisoning");
}

function card(id: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`[data-attack="${id}"]`);
  if (found === null) throw new Error(`no card ${id}`);
  return found;
}

function resultHeading(): string {
  return document.querySelector("[data-result-heading]")?.textContent ?? "";
}

function resultRows(): string[][] {
  return within(screen.getByRole("table", { name: "Checks" }))
    .getAllByRole("row")
    .slice(1)
    .map((row) => [...row.children].map((cell) => cell.textContent));
}

describe("AttackLibraryPanel", () => {
  it("is registered for the library mode", () => {
    expect(PANELS.library).toBe(AttackLibraryPanel);
  });

  it("list renders 14 cards in order [A1-A14]", async () => {
    stub();
    await loaded();
    const runs = screen.getAllByRole("button", { name: "Run" });
    expect(runs).toHaveLength(14);
    const order = [...document.querySelectorAll("[data-attack]")].map((node) =>
      node.getAttribute("data-attack"),
    );
    expect(order).toEqual(Array.from({ length: 14 }, (_, index) => `A${index + 1}`));
    expect(
      runs.map((button) => button.closest("[data-attack]")?.getAttribute("data-attack")),
    ).toEqual(order);
    const a3 = within(card("A3"));
    expect(a3.getByText("Data-only poisoning")).toBeTruthy();
    expect(a3.getByText("Expected: ESCALATE corroboration LEDGER_NOVEL_ESCALATE")).toBeTruthy();
    expect(a3.getByText(`Primary stop: ${PRIMARY_STOPS.A3}`)).toBeTruthy();
  });

  it("does not run any attack on mount", async () => {
    const { calls } = stub();
    await loaded();
    expect(calls.map((call) => call.path)).toEqual(["/attacks"]);
  });

  it("controls row", async () => {
    stub();
    await loaded();
    const section = within(screen.getByRole("region", { name: "Benign controls" }));
    expect(section.getByRole("heading", { name: "Benign controls" })).toBeTruthy();
    expect(section.getAllByRole("button").map((button) => button.textContent)).toEqual([
      "B1",
      "B2",
      "B3",
      "B4",
    ]);
  });

  it("run A3 [A3, I2]", async () => {
    const { calls } = stub();
    await loaded();
    fireEvent.click(within(card("A3")).getByRole("button", { name: "Run" }));
    await screen.findByRole("heading", { level: 2, name: "A3 Data-only poisoning" });
    const run = calls.filter((call) => call.path.startsWith("/playground"));
    expect(run).toEqual([{ method: "POST", path: "/playground/attacks/A3/run", body: undefined }]);
    expect(screen.getByText("Monitor matches the taxonomy")).toBeTruthy();
    expect(resultRows()).toEqual([
      ["A3.c0", "read_inbox", "ALLOW READ_ONLY_UNGATED", "ALLOW READ_ONLY_UNGATED", "yes"],
      [
        "A3.c1",
        "pay_bill",
        "ESCALATE corroboration LEDGER_NOVEL_ESCALATE",
        "ESCALATE corroboration LEDGER_NOVEL_ESCALATE",
        "yes",
      ],
    ]);
    expect(screen.getByText("Attacker goal not reached")).toBeTruthy();
    const dots = within(screen.getByTestId("response-oracle")).getAllByRole("listitem");
    expect(dots).toHaveLength(6);
    expect(dots.map((dot) => dot.getAttribute("data-state"))).toEqual(Array(6).fill("pass"));
  });

  it("run A13 is deferred [A13]", async () => {
    stub();
    await loaded();
    fireEvent.click(within(card("A13")).getByRole("button", { name: "Run" }));
    await screen.findByText("Deferred to the Output Guard");
    expect(screen.getByText(DEFERRED_TEXT)).toBeTruthy();
    expect(DEFERRED_TEXT).toBe(
      "This class is output behavior: the monitor only has to allow the benign read. The Output Guard (P3a) handles the text.",
    );
  });

  it("run B1 [A14]", async () => {
    const { calls } = stub();
    await loaded();
    fireEvent.click(screen.getByRole("button", { name: "B1" }));
    await screen.findByText("Monitor matches the taxonomy");
    expect(resultHeading().startsWith("B1 Legitimate bill pays silently via ledger match")).toBe(
      true,
    );
    expect(screen.getByText("Monitor matches the taxonomy")).toBeTruthy();
    expect(calls.at(-1)?.path).toBe("/playground/attacks/B1/run");
  });

  it("a mismatch is shown", async () => {
    const body = structuredClone(fixture("attack.A3").body as AttackRunResponse);
    body.ok = false;
    const second = body.checks[1];
    if (second?.actual == null) throw new Error("fixture changed");
    second.matches = false;
    second.actual = { ...second.actual, verdict: "ALLOW" };
    stub({ "/playground/attacks/A3/run": { status: 200, body } });
    await loaded();
    fireEvent.click(within(card("A3")).getByRole("button", { name: "Run" }));
    await screen.findByText("MISMATCH: the monitor decided differently");
    const row = resultRows()[1];
    expect(row?.[4]).toBe("NO");
    expect(row?.[3]).toBe("ALLOW corroboration LEDGER_NOVEL_ESCALATE");
  });

  it("oracle agrees with the events [I6]", () => {
    const body = fixture("attack.A3").body as AttackRunResponse;
    const updates = body.events.filter((event) => event.type === "oracle_updated");
    expect(updates.at(-1)?.result).toEqual(body.oracle);
  });

  it("list failure and retry", async () => {
    let attempts = 0;
    stubPlayground((request) => {
      if (request.path !== "/attacks") return undefined;
      attempts += 1;
      return attempts === 1 ? { status: 500, body: { detail: "boom" } } : fixture("attacks.list");
    });
    render(<AttackLibraryPanel apiUrl={API} />);
    expect((await screen.findByRole("alert")).textContent).toBe("boom (HTTP 500)");
    expect(screen.queryAllByRole("button", { name: "Run" })).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByText("Data-only poisoning");
    expect(screen.getAllByRole("button", { name: "Run" })).toHaveLength(14);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("a failed run shows the error banner and no result", async () => {
    stub({ "/playground/attacks/A3/run": { status: 404, body: { detail: "unknown attack id" } } });
    await loaded();
    fireEvent.click(within(card("A3")).getByRole("button", { name: "Run" }));
    expect((await screen.findByRole("alert")).textContent).toBe("unknown attack id (HTTP 404)");
    expect(screen.queryByRole("table", { name: "Checks" })).toBeNull();
  });

  it("the running card is disabled and reads Running... while others stay usable", async () => {
    const pending: ((response: Response) => void)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: Request | string | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/attacks")) {
          return Promise.resolve(
            new Response(JSON.stringify(fixture("attacks.list").body), {
              status: 200,
              headers: { "content-type": "application/json" },
            }),
          );
        }
        return new Promise<Response>((resolve) => {
          pending.push(resolve);
        });
      }),
    );
    await loaded();
    fireEvent.click(within(card("A1")).getByRole("button", { name: "Run" }));
    const busy = within(card("A1")).getByRole<HTMLButtonElement>("button", { name: "Running..." });
    expect(busy.disabled).toBe(true);
    expect(
      within(card("A2")).getByRole<HTMLButtonElement>("button", { name: "Run" }).disabled,
    ).toBe(false);
  });

  it("stale answers are ignored", async () => {
    const pending = new Map<string, (response: Response) => void>();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: Request | string | URL) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.endsWith("/attacks")) {
          return Promise.resolve(
            new Response(JSON.stringify(fixture("attacks.list").body), {
              status: 200,
              headers: { "content-type": "application/json" },
            }),
          );
        }
        return new Promise<Response>((resolve) => {
          pending.set(url.split("/").at(-2) ?? "", resolve);
        });
      }),
    );
    const base = fixture("attack.A3").body as AttackRunResponse;
    const answer = (id: string, name: string) =>
      new Response(JSON.stringify({ ...base, attack_id: id, name }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    await loaded();
    fireEvent.click(within(card("A1")).getByRole("button", { name: "Run" }));
    fireEvent.click(within(card("A2")).getByRole("button", { name: "Run" }));
    await waitFor(() => {
      expect(pending.size).toBe(2);
    });
    pending.get("A2")?.(answer("A2", "Authority impersonation"));
    await screen.findByRole("heading", { level: 2, name: "A2 Authority impersonation" });
    pending.get("A1")?.(answer("A1", "Instruction override"));
    await waitFor(() => {
      expect(within(card("A1")).getByRole("button", { name: "Run" })).toBeTruthy();
    });
    expect(resultHeading()).toBe("A2 Authority impersonation");
  });
});
