// CP3: stage-script steps 1-4 played against the /x-ray page.
//
// The fake socket replays the golden stream that matches the lane in the URL (see fake-run.ts); the
// `mode` in the URL only has to be right. The three-lane steps ask for mode "cassette" because the
// server's golden mode serves ONE stream (the NOTARY one) for every lane, so a three-lane test in
// golden mode would prove nothing: the page switches to cassette by itself in that case.
import { CommandSchema } from "@notary/schema";
import type { Event } from "@notary/schema";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { XRayView } from "@/components/x-ray-view";
import type { XRayViewProps } from "@/components/x-ray-view";

import { socketFactory, stubRest } from "./fake-run";
import type { RestState } from "./fake-run";
import { STREAMS, load, must, viewOf } from "./golden";

const API = "http://localhost:8000";
const NOTARY = viewOf("poisoned_bill.notary");
const ANCHOR = { head: "0123456789abcdef0123456789abcdef", length: 7 };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

type Executed = Extract<Event, { type: "effect_executed" }>;

/** The effect summaries of a golden stream, as the stream really has them. */
function effects(name: (typeof STREAMS)[number]): Executed[] {
  return load(name).filter((event): event is Executed => event.type === "effect_executed");
}

function paymentOf(name: (typeof STREAMS)[number]): string {
  return must(
    effects(name).find((effect) => effect.tool === "pay_bill"),
    `pay_bill effect of ${name}`,
  ).summary;
}

function pendingItem(remaining: number): unknown {
  return {
    run_id: must(NOTARY.runId, "run id"),
    endorsement: must(NOTARY.endorsements[0], "an endorsement").endorsement,
    card_text: "",
    remaining_approvals: remaining,
  };
}

function open(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const sockets = socketFactory();
  // The modes come in an order the page must not depend on.
  const stub = stubRest({
    modes: ["live", "cassette", "golden"],
    pending: [pendingItem(3)],
    anchor: ANCHOR,
    ...rest,
  });
  const utils = render(
    <XRayView apiUrl={API} scenario="poisoned_bill" webSocket={sockets.factory} {...props} />,
  );
  return { ...utils, ...sockets, rest: stub };
}

async function opened(props: Partial<XRayViewProps> = {}, rest: Partial<RestState> = {}) {
  const page = open(props, rest);
  await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
  return page;
}

const region = (label: string): HTMLElement => screen.getByLabelText(label);

function lane(name: string): HTMLElement {
  return must(
    region("Three lanes").querySelector<HTMLElement>(`[data-lane="${name}"]`),
    `lane ${name}`,
  );
}

function laneEffects(name: string): string {
  return within(lane(name)).getByLabelText("Effects").textContent;
}

function count(name: string, what: string): string {
  return must(lane(name).querySelector(`[data-count="${what}"] span`), `${name} ${what}`)
    .textContent;
}

function light(scope: HTMLElement, which: "attacker" | "user"): string | null {
  return must(scope.querySelector(`[data-light="${which}"]`), `${which} light`).getAttribute(
    "data-state",
  );
}

function socketOf(page: ReturnType<typeof open>, laneName: string) {
  return must(
    page.sockets.find((socket) => socket.url.includes(`lane=${laneName}`)),
    `${laneName} socket`,
  );
}

function modesOf(page: ReturnType<typeof open>): (string | null)[] {
  return page.urls().map((url) => new URL(url).searchParams.get("mode"));
}

describe("stage steps 1 and 2: the baseline lanes lose the money", () => {
  it("step 1: the undefended lane is red [A3]", async () => {
    const page = await opened({ mode: "cassette", initialViewMode: "three-lane" });
    expect(new Set(modesOf(page))).toEqual(new Set(["cassette"]));
    expect(page.urls().map((url) => new URL(url).searchParams.get("lane"))).toEqual(
      expect.arrayContaining(["undefended", "classifier", "notary"]),
    );

    const payment = paymentOf("poisoned_bill.undefended");
    expect(payment).toMatch(/ATTACKER/);
    await waitFor(() => {
      expect(laneEffects("undefended")).toContain(payment);
    });
    const column = lane("undefended");
    expect(light(column, "attacker")).toBe("bad");
    expect(column.getAttribute("data-attacker")).toBe("reached");
    for (const what of ["allowed", "escalated", "blocked"])
      expect(count("undefended", what)).toBe("0");
    expect(count("undefended", "executed")).toBe("2");
    expect(within(column).getByText("no policy check")).toBeTruthy();
  });

  it("step 2: the classifier lane is labelled a stand-in and loses the money too [A3]", async () => {
    await opened({ mode: "cassette", initialViewMode: "three-lane" });
    const column = lane("classifier");
    await waitFor(() => {
      expect(laneEffects("classifier")).toContain(paymentOf("poisoned_bill.classifier"));
    });
    expect(paymentOf("poisoned_bill.classifier")).toBe(paymentOf("poisoned_bill.undefended"));
    expect(must(column.querySelector("h3"), "heading").textContent).toContain("stand-in");
    expect(light(column, "attacker")).toBe("bad");
    expect(column.getAttribute("data-attacker")).toBe("reached");
    expect(within(column).getByText("no policy check")).toBeTruthy();
    for (const what of ["allowed", "escalated", "blocked"])
      expect(count("classifier", what)).toBe("0");
  });
});

describe("stage step 3: NOTARY escalates and asks", () => {
  it("shows one escalate gate, one waiting row and a card with the differing characters [A3]", async () => {
    const page = await opened({ mode: "cassette", initialViewMode: "three-lane" });
    const card = await screen.findByRole("group", { name: "Endorsement request" });

    expect(
      region("Graph nodes").querySelectorAll('[data-node="gate"][data-state="escalate"]'),
    ).toHaveLength(1);
    const escalated = region("Decision stream").querySelectorAll('[data-verdict="ESCALATE"]');
    expect(escalated).toHaveLength(1);
    expect(
      within(escalated[0] as HTMLElement).getByText("awaiting your confirmation"),
    ).toBeTruthy();
    expect(within(region("Decision stream")).getAllByText(/ESCALATE for/)).toHaveLength(1);

    const row = must(
      must(NOTARY.endorsements[0], "endorsement").endorsement.card.rows[0],
      "the card row",
    );
    expect(within(card).getByText(row.param)).toBeTruthy();
    expect(card.querySelector("[data-proposed]")?.textContent).toBe(row.preview);
    const length = Array.from(row.preview).length;
    const unique = new Set(
      row.differing_positions.filter((p) => Number.isInteger(p) && p >= 0 && p < length),
    );
    expect(unique.size).toBeGreaterThan(0);
    const marked = [...card.querySelectorAll("[data-proposed] mark[data-differs]")].reduce(
      (n, mark) => n + Array.from(mark.textContent).length,
      0,
    );
    expect(marked).toBe(unique.size);
    expect(within(card).getByText("This value is not in your ledger.")).toBeTruthy();
    await within(card).findByText("Approvals left: 3");

    // The attacker did not get the money; the user goal waits for the answer.
    expect(light(region("Oracle panel"), "attacker")).toBe("good");
    expect(light(region("Oracle panel"), "user")).toBe("pending");
    expect(lane("notary").getAttribute("data-attacker")).toBe("stopped");
    expect(laneEffects("notary")).toBe("read 2 messages");
    expect(socketOf(page, "notary").sent).toEqual([]);
  });

  it("confirm sends exactly one valid command, on the NOTARY socket only [I4]", async () => {
    const page = await opened({ mode: "cassette", initialViewMode: "three-lane" });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    const confirm = within(card).getByRole("button", { name: "Confirm" });

    // Two clicks in the same tick still make one frame.
    act(() => {
      confirm.click();
      confirm.click();
    });
    const frames = socketOf(page, "notary").sent;
    expect(frames).toHaveLength(1);
    const command: unknown = JSON.parse(frames[0] ?? "null");
    expect(CommandSchema.safeParse(command).success).toBe(true);
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: must(NOTARY.runId, "run id"),
      endorsement_id: must(NOTARY.endorsements[0], "endorsement").endorsement.endorsement_id,
      decision: "approve",
    });
    expect(socketOf(page, "undefended").sent).toEqual([]);
    expect(socketOf(page, "classifier").sent).toEqual([]);
  });

  it("reject sends exactly one reject command [I4]", async () => {
    const page = await opened({ mode: "cassette", initialViewMode: "three-lane" });
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    fireEvent.click(within(card).getByRole("button", { name: "Reject" }));
    const frames = socketOf(page, "notary").sent;
    expect(frames).toHaveLength(1);
    expect(JSON.parse(frames[0] ?? "null")).toEqual({
      type: "endorsement_decision",
      run_id: must(NOTARY.runId, "run id"),
      endorsement_id: must(NOTARY.endorsements[0], "endorsement").endorsement.endorsement_id,
      decision: "reject",
    });
    expect(socketOf(page, "undefended").sent).toEqual([]);
    expect(socketOf(page, "classifier").sent).toEqual([]);
  });

  it("shows the same card, gate and lights in the default golden single-lane view [A3]", async () => {
    const page = await opened();
    expect(new Set(modesOf(page))).toEqual(new Set(["golden"]));
    const card = await screen.findByRole("group", { name: "Endorsement request" });
    expect(within(card).getByText("This value is not in your ledger.")).toBeTruthy();
    expect(
      region("Graph nodes").querySelectorAll('[data-node="gate"][data-state="escalate"]'),
    ).toHaveLength(1);
    expect(light(region("Oracle panel"), "attacker")).toBe("good");
    expect(light(region("Oracle panel"), "user")).toBe("pending");
  });
});

describe("stage step 4: the legitimate bill pays silently", () => {
  it("has no card, two ALLOW rows and both lights good [I1]", async () => {
    const page = await opened({ scenario: "legitimate_bill" });
    // legitimate_bill has no golden stream on the server: the page uses cassette.
    expect(new Set(modesOf(page))).toEqual(new Set(["cassette"]));
    expect(screen.queryByRole("group", { name: "Endorsement request" })).toBeNull();

    const decision = region("Decision stream");
    expect(decision.querySelectorAll('[data-verdict="ALLOW"]')).toHaveLength(2);
    expect(decision.querySelector('[data-verdict="ESCALATE"]')).toBeNull();
    expect(document.body.textContent).not.toContain("ESCALATE");
    await waitFor(() => {
      expect(light(region("Oracle panel"), "user")).toBe("good");
    });
    expect(light(region("Oracle panel"), "attacker")).toBe("good");
    expect(page.sockets.flatMap((socket) => socket.sent)).toEqual([]);

    // The payment goes to the ledger payee, as the real stream says.
    const payment = paymentOf("legitimate_bill.notary");
    expect(payment).toMatch(/ACME/);
    expect(
      [...region("What changed").querySelectorAll("li")].map((li) => li.textContent),
    ).toContain(`pay_bill: ${payment}`);
  });
});

// --- no content from outside the events is drawn

function visibleText(root: HTMLElement): string {
  const copy = root.cloneNode(true) as HTMLElement;
  // The React Flow canvas is library chrome (its own accessibility texts); the same nodes are in
  // the "Graph nodes" list, which is scanned. Styles and scripts are not visible text.
  for (const element of copy.querySelectorAll(".react-flow, style, script")) element.remove();
  const walker = document.createTreeWalker(copy, NodeFilter.SHOW_TEXT);
  const parts: string[] = [];
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    parts.push(node.textContent ?? "");
  }
  // Separate adjacent elements so that their texts do not glue into one token.
  return parts.join(" ");
}

/**
 * Tokens of 8 or more characters that are not in the corpus. The graph names its nodes `v:<value id>`
 * and `g:<call id>` (see graph-model.ts); those prefixes are not in the events, so they are removed
 * before the id itself is looked up.
 */
function unknownTokens(text: string, corpus: string): string[] {
  const tokens = text
    .split(/\s+/)
    .map((token) => token.replace(/^[^A-Za-z0-9_]+|[^A-Za-z0-9_]+$/g, "").replace(/^[vg]:/, ""))
    .filter((token) => token.length >= 8);
  return [...new Set(tokens)].filter((token) => !corpus.includes(token));
}

function sourceText(directory: string, extensions: readonly string[]): string {
  return readdirSync(directory)
    .filter((name) => extensions.some((extension) => name.endsWith(extension)))
    .map((name) => readFileSync(resolve(directory, name), "utf8"))
    .join("\n");
}

describe("no raw content leaks into the page", () => {
  // Everything the page may show: the events of the four golden streams (previews, summaries,
  // reason codes and details, the contract, ids, hashes), the values the REST stubs return, and
  // the fixed strings of the components, which are read from their source files.
  const corpus = [
    ...STREAMS.map((name) => JSON.stringify(load(name))),
    JSON.stringify(ANCHOR),
    sourceText(resolve(import.meta.dirname, "../../../packages/ui/src"), [".ts", ".tsx"]),
    sourceText(resolve(import.meta.dirname, "../components"), [".tsx"]),
    readFileSync(resolve(import.meta.dirname, "../lib/x-ray-state.ts"), "utf8"),
  ].join("\n");

  it("has a corpus that is not vacuous, and a detector that flags an unknown token [I6]", () => {
    const attacker = must(
      /DE00ATTACKER\d+/.exec(paymentOf("poisoned_bill.undefended")),
      "attacker IBAN",
    )[0];
    expect(corpus).toContain(attacker);
    expect(corpus).toContain("LEDGER_NOVEL_ESCALATE");
    expect(corpus).toContain("pay_bill");
    expect(unknownTokens("see ZZZ-NOT-IN-FIXTURES-999 here", corpus)).toEqual([
      "ZZZ-NOT-IN-FIXTURES-999",
    ]);
    expect(unknownTokens("DE00ATTACKER0000000001 LEDGER_NOVEL_ESCALATE", corpus)).toEqual([]);
  });

  it("draws only text from the events and the components, on every stream [I6]", async () => {
    const screens: [string, Partial<XRayViewProps>][] = [
      ["poisoned_bill golden, single lane", {}],
      ["poisoned_bill cassette, three lanes", { mode: "cassette", initialViewMode: "three-lane" }],
      ["legitimate_bill cassette", { scenario: "legitimate_bill" }],
    ];
    for (const [name, props] of screens) {
      const page = await opened(props);
      if (props.scenario !== "legitimate_bill") {
        await screen.findByRole("group", { name: "Endorsement request" });
      }
      if (props.initialViewMode === "three-lane") {
        await waitFor(() => {
          expect(laneEffects("undefended")).toContain(paymentOf("poisoned_bill.undefended"));
        });
      }
      await screen.findByLabelText("Audit anchor");
      const text = visibleText(document.body);
      expect(text.length, name).toBeGreaterThan(200);
      expect(unknownTokens(text, corpus), name).toEqual([]);
      page.unmount();
      cleanup();
    }
  });
});
