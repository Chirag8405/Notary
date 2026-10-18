import type { Event } from "@notary/schema";
import type { WebSocketFactory } from "@notary/client";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { XRayView } from "@/components/x-ray-view";
import { CHAIN_BROKEN } from "@/lib/x-ray-state";

import { stubRest } from "./fake-run";
import type { McpRunBody } from "./fake-run";
import { load, must } from "./golden";

const API = "http://localhost:8000";
const RUN = "mcp-0123456789ab";
const OLDER = "mcp-ba9876543210";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** The golden NOTARY stream of the poisoned bill, as a proxy run (the same Event union). */
function proxyRun(runId: string): Event[] {
  return load("poisoned_bill.notary").map((event) => ({ ...event, run_id: runId }));
}

/** A socket the test feeds: it stays open until the test pushes events or closes it. */
class McpSocket extends EventTarget {
  readyState = 1;
  readonly sent: string[] = [];
  readonly url: string;
  constructor(url: string) {
    super();
    this.url = url;
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {
    this.readyState = 3;
  }
  push(...events: Event[]): void {
    for (const event of events) {
      this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(event) }));
    }
  }
  closeWith(code: number, reason: string): void {
    this.readyState = 3;
    this.dispatchEvent(new CloseEvent("close", { code, reason }));
  }
}

function sockets() {
  const opened: McpSocket[] = [];
  const factory: WebSocketFactory = (url) => {
    const socket = new McpSocket(url);
    opened.push(socket);
    return socket as unknown as WebSocket;
  };
  return { opened, factory };
}

const RUNS: McpRunBody[] = [
  { run_id: RUN, length: 4, head: "a".repeat(64), finished: false },
  { run_id: OLDER, length: 11, head: "b".repeat(64), finished: true },
];

function open(mcpRuns: readonly McpRunBody[] | "off" | "fail" = RUNS, scenario = "") {
  const feed = sockets();
  const rest = stubRest({
    modes: ["cassette", "golden", "live", "mcp"],
    anchor: "missing",
    mcpRuns,
  });
  render(<XRayView apiUrl={API} scenario={scenario} mode="mcp" webSocket={feed.factory} />);
  return { ...feed, rest };
}

/** The picker sits under "Advanced". */
async function picker() {
  must(document.querySelector("details"), "advanced").open = true;
  return await screen.findByLabelText<HTMLSelectElement>("MCP run");
}

async function socketOpened(page: { opened: McpSocket[] }, count = 1) {
  await waitFor(() => {
    expect(page.opened).toHaveLength(count);
  });
  return must(page.opened[count - 1], "socket");
}

describe("x-ray mode mcp", () => {
  it("shows a run picker, no scenario picker, and opens no socket until a run is chosen [I6]", async () => {
    const page = open();
    const select = await picker();
    await waitFor(() => {
      expect([...select.options].map((o) => o.value)).toEqual(["", RUN, OLDER]);
    });
    expect(screen.queryByLabelText("Scenario")).toBeNull();
    expect(screen.queryByRole("button", { name: "Three-lane view" })).toBeNull();
    expect(document.querySelector("[data-mcp-idle]")).not.toBeNull();
    expect(page.opened).toHaveLength(0);
    expect(select.options[1]?.textContent).toBe(`${RUN} (4 entries, live)`);
    expect(select.options[2]?.textContent).toBe(`${OLDER} (11 entries, finished)`);
  });

  it("opens /ws/runs/<id>?lane=notary&mode=mcp for the chosen run [I6]", async () => {
    const replace = vi.spyOn(window.history, "replaceState");
    const page = open();
    const select = await picker();
    await waitFor(() => {
      expect(select.options).toHaveLength(3);
    });
    fireEvent.change(select, { target: { value: RUN } });
    const url = new URL((await socketOpened(page)).url);
    expect(url.pathname).toBe(`/ws/runs/${RUN}`);
    expect(url.searchParams.get("mode")).toBe("mcp");
    expect(url.searchParams.get("lane")).toBe("notary");
    expect(replace).toHaveBeenLastCalledWith(
      null,
      "",
      `/x-ray?scenario=${RUN}&mode=mcp&view=single`,
    );
  });

  it("renders a stubbed proxy run, live until run_finished [I6]", async () => {
    const page = open(RUNS, RUN);
    const socket = await socketOpened(page);
    const events = proxyRun(RUN);
    const last = events.length - 1;
    act(() => {
      socket.push(...events.slice(0, last));
    });
    await screen.findAllByText(/(ESCALATE|ALLOW) for c2/);
    expect(document.querySelector("[data-live]")?.textContent).toBe("live");
    expect(document.querySelector("[data-mcp-run]")?.textContent).toContain(RUN);
    act(() => {
      socket.push(must(events[last], "run_finished"));
    });
    await waitFor(() => {
      expect(document.querySelector("[data-live]")).toBeNull();
    });
    act(() => {
      socket.closeWith(1000, "");
    });
    await waitFor(() => {
      expect(document.querySelector("[data-status]")?.getAttribute("data-status")).toBe("finished");
    });
  });

  it("does not offer approval for an escalation, which the server would refuse [I6]", async () => {
    const page = open(RUNS, RUN);
    const socket = await socketOpened(page);
    act(() => {
      socket.push(...proxyRun(RUN));
    });
    await screen.findByText(/A call escalated and is not allowed to run/);
    expect(screen.queryByRole("button", { name: /approve|confirm|reject/i })).toBeNull();
    expect(socket.sent).toEqual([]);
  });

  it("says the chain failed verification when the server closes 4503 [I6]", async () => {
    const page = open(RUNS, RUN);
    const socket = await socketOpened(page);
    act(() => {
      socket.push(...proxyRun(RUN).slice(0, 3));
      socket.closeWith(4503, "chain broken");
    });
    expect((await screen.findByRole("alert")).textContent).toBe(CHAIN_BROKEN);
    expect(screen.queryByRole("button", { name: "Use cassette instead" })).toBeNull();
    expect(document.querySelector("[data-live]")).toBeNull();
  });

  it("goes back to a scenario when the mode is changed away from mcp [I6]", async () => {
    const page = open(RUNS, RUN);
    await socketOpened(page);
    must(document.querySelector("details"), "advanced").open = true;
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "cassette" } });
    const url = new URL((await socketOpened(page, 2)).url);
    expect(url.pathname).toBe("/ws/runs/poisoned_bill");
    expect(url.searchParams.get("mode")).toBe("cassette");
  });

  it("says so when there are no runs or the list cannot be read [I6]", async () => {
    open([]);
    await picker();
    await screen.findByText(/No MCP runs yet/);
    cleanup();
    open("fail");
    await picker();
    await screen.findByText("The list of MCP runs could not be read.");
  });

  it("reads the list again on Refresh [I6]", async () => {
    const page = open([]);
    await picker();
    await screen.findByText(/No MCP runs yet/);
    page.rest.state.mcpRuns = RUNS;
    fireEvent.click(screen.getByRole("button", { name: "Refresh runs" }));
    await waitFor(() => {
      expect(screen.getByLabelText<HTMLSelectElement>("MCP run").options).toHaveLength(3);
    });
    expect(page.rest.calls.filter((path) => path === "/mcp/runs")).toHaveLength(2);
  });

  it("does not list mcp when the server does not [I6]", async () => {
    const feed = sockets();
    stubRest({ modes: ["cassette", "golden", "live"], anchor: "missing" });
    render(<XRayView apiUrl={API} scenario="poisoned_bill" webSocket={feed.factory} />);
    const mode = await screen.findByLabelText<HTMLSelectElement>("Mode");
    await waitFor(() => {
      expect([...mode.options].map((o) => o.value)).toEqual(["golden", "cassette", "live"]);
    });
  });
});
