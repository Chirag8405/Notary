import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ArenaResult } from "@notary/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ARENA_NOTE, ArenaPanel } from "@/components/arena-panel";
import { PANELS } from "@/components/playground-panels";

import { fixture, stubPlayground } from "./playground-fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const API = "http://localhost:8000";
const CASSETTE_MISS =
  "This input has no recorded run. The playground replays recorded runs: use a sample input, or run the server in live mode.";

/** The recorded three-round arena: set up the form as in the fixture (3 rounds, two lanes). */
function fillRecordedForm() {
  fireEvent.change(screen.getByLabelText("Rounds"), { target: { value: "3" } });
  fireEvent.click(screen.getByLabelText("Undefended"));
}

function polylinePoints(label: string): string[] {
  const line = document.querySelector(`polyline[data-series="${label}"]`);
  return (line?.getAttribute("points") ?? "").split(" ");
}

function ys(label: string): string[] {
  return polylinePoints(label).map((point) => point.split(",")[1] ?? "");
}

async function runRecorded() {
  fillRecordedForm();
  fireEvent.click(screen.getByRole("button", { name: "Run arena" }));
  await screen.findByRole("img", { name: "Attack success rate per round" });
}

describe("ArenaPanel", () => {
  it("is registered for the arena mode", () => {
    expect(PANELS.arena).toBe(ArenaPanel);
  });

  it("panel runs the recorded arena [A3, I2]", async () => {
    const { calls } = stubPlayground(() => fixture("arena.seed0"));
    render(<ArenaPanel apiUrl={API} />);
    await runRecorded();
    expect(calls).toEqual([
      {
        method: "POST",
        path: "/playground/arena",
        body: {
          type: "arena_start",
          scenario: "poisoned_bill",
          rounds: 3,
          lanes: ["classifier", "notary"],
          seed: 0,
        },
      },
    ]);
    expect(document.querySelectorAll("polyline[data-series]")).toHaveLength(2);
    const totals = [...document.querySelectorAll("[data-lane-total]")].map(
      (node) => node.textContent,
    );
    expect(totals).toEqual([
      "Classifier-only (stand-in): 3 of 3 rounds reached the goal",
      "NOTARY: 0 of 3 rounds reached the goal",
    ]);
    const flat = ys("NOTARY");
    expect(flat).toHaveLength(3);
    expect(new Set(flat).size).toBe(1);
    const classifierTable = within(
      document.querySelector<HTMLElement>('[data-lane-table="classifier"]') ?? document.body,
    );
    expect(classifierTable.getByText("Classifier-only (stand-in)")).toBeTruthy();
    expect(classifierTable.getAllByRole("row")[0]?.textContent).toBe(
      "Round 1: email, 34 characters, goal reached",
    );
  });

  it("classifier climbs, NOTARY stays flat [A3]", async () => {
    stubPlayground(() => fixture("arena.seed0"));
    render(<ArenaPanel apiUrl={API} />);
    await runRecorded();
    const rates = (lane: string) =>
      within(screen.getByRole("table", { name: "Attack success rate per round" }))
        .getAllByRole("row")
        .slice(1)
        .filter((row) => row.children[0]?.textContent === lane)
        .map((row) => row.children[2]?.textContent);
    expect(rates("Classifier-only (stand-in)")).toEqual(["100%", "100%", "100%"]);
    expect(rates("NOTARY")).toEqual(["0%", "0%", "0%"]);
  });

  it("cassette miss [A3]", async () => {
    stubPlayground(() => fixture("arena.cassette-miss"));
    render(<ArenaPanel apiUrl={API} />);
    fireEvent.change(screen.getByLabelText("Seed"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: "Run arena" }));
    expect((await screen.findByRole("alert")).textContent).toBe(CASSETTE_MISS);
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("too many rounds is stopped client-side", () => {
    const { calls } = stubPlayground(() => fixture("arena.seed0"));
    render(<ArenaPanel apiUrl={API} />);
    fireEvent.change(screen.getByLabelText("Rounds"), { target: { value: "11" } });
    fireEvent.click(screen.getByRole("button", { name: "Run arena" }));
    expect(screen.getByRole("alert").textContent).toBe("Rounds must be between 1 and 10");
    expect(calls).toHaveLength(0);
  });

  it("server 422 is shown", async () => {
    stubPlayground(() => ({ status: 422, body: { detail: "too many rounds" } }));
    render(<ArenaPanel apiUrl={API} />);
    fireEvent.click(screen.getByRole("button", { name: "Run arena" }));
    expect((await screen.findByRole("alert")).textContent).toBe("too many rounds (HTTP 422)");
  });

  it("the button reads Running... and is disabled while a call is open", async () => {
    let release: (response: Response) => void = () => undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            release = resolve;
          }),
      ),
    );
    render(<ArenaPanel apiUrl={API} />);
    fireEvent.click(screen.getByRole("button", { name: "Run arena" }));
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Running..." }).disabled).toBe(
      true,
    );
    release(
      new Response(JSON.stringify(fixture("arena.seed0").body), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    await screen.findByRole("img", { name: "Attack success rate per round" });
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Run arena" }).disabled).toBe(
      false,
    );
  });

  it("stale response is ignored", async () => {
    const full = fixture("arena.seed0").body as ArenaResult;
    const second: ArenaResult = { ...full, lanes: full.lanes.slice(1) };
    const pending: ((response: Response) => void)[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(
        () =>
          new Promise<Response>((resolve) => {
            pending.push(resolve);
          }),
      ),
    );
    const answer = (body: unknown) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    const { container } = render(<ArenaPanel apiUrl={API} />);
    const form = container.querySelector("form");
    if (form === null) throw new Error("form missing");
    fireEvent.submit(form);
    fireEvent.submit(form);
    await waitFor(() => {
      expect(pending).toHaveLength(2);
    });
    pending[1]?.(answer(second));
    await screen.findByRole("img", { name: "Attack success rate per round" });
    pending[0]?.(answer(full));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const totals = [...document.querySelectorAll("[data-lane-total]")].map(
      (node) => node.textContent,
    );
    expect(totals).toEqual(["NOTARY: 0 of 3 rounds reached the goal"]);
  });

  it("standing note and labels", async () => {
    stubPlayground(() => fixture("arena.seed0"));
    render(<ArenaPanel apiUrl={API} />);
    expect(ARENA_NOTE).toBe(
      'The attacker is replayed from a recording: seed 0 on the poisoned bill. Other seeds answer "no recorded run".',
    );
    expect(screen.getByText(ARENA_NOTE)).toBeTruthy();
    expect(screen.getByLabelText("Classifier-only (stand-in)")).toBeTruthy();
    await runRecorded();
    const legend = within(screen.getByRole("list", { name: "Legend" }));
    expect(legend.getByText("Classifier-only (stand-in)")).toBeTruthy();
  });
});
