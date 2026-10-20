import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GuidedDemo } from "@/components/guided-demo";

import { socketFactory, stubRest } from "./fake-run";

const API = "http://localhost:8000";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function open(initialStep: string, socketOptions: Parameters<typeof socketFactory>[0] = {}) {
  const sockets = socketFactory(socketOptions);
  stubRest({ modes: ["cassette"], anchor: "missing" });
  vi.spyOn(window.history, "replaceState").mockImplementation(() => undefined);
  render(<GuidedDemo apiUrl={API} initialStep={initialStep} webSocket={sockets.factory} />);
  return sockets;
}

describe("the guided demo", () => {
  it("opens on the step named in the address and falls back to the first", () => {
    open("normal");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("A normal bill");
    cleanup();
    open("nonsense");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("See the attack");
  });

  it("shows both unprotected agents paying the attacker, in plain words", async () => {
    const page = open("attack");
    await waitFor(() => {
      expect(screen.getAllByText("The attacker got the money")).toHaveLength(2);
    });
    expect(page.urls().some((url) => url.includes("lane=undefended"))).toBe(true);
    expect(page.urls().some((url) => url.includes("lane=classifier"))).toBe(true);
    expect(page.urls().some((url) => url.includes("lane=notary"))).toBe(false);
  });

  it("asks before paying a new account and sends the answer; rejecting is safe", async () => {
    const page = open("pause", { stopAtCard: true });
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("Is this account right?");
    expect(screen.getByRole("region", { name: "Result", hidden: true }).textContent).toContain(
      "Waiting for your decision",
    );

    fireEvent.click(screen.getByRole("button", { name: "No, stop this" }));
    const frames = page.sockets.flatMap((socket) => socket.sent);
    expect(frames).toHaveLength(1);
    expect(JSON.parse(frames[0] ?? "{}")).toMatchObject({
      type: "endorsement_decision",
      decision: "reject",
    });
  });

  it("offers the account the user normally pays, and Approve anyway is a warning button", async () => {
    open("pause", { stopAtCard: true });
    await screen.findByRole("dialog");
    expect(screen.getByRole("button", { name: "Use the account I normally use" })).toBeTruthy();
    const approve = screen.getByRole("button", { name: /Approve anyway/ });
    expect(approve.getAttribute("data-variant") ?? approve.className).toBeTruthy();
    expect(screen.getByText(/NOTARY cannot stop a choice you make yourself/)).toBeTruthy();
  });

  it("pays a known bill with no question", async () => {
    open("normal");
    await waitFor(() => {
      expect(screen.getByRole("region", { name: "Result" }).textContent).toContain(
        "Your bill was paid safely",
      );
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("moves with Next and Back and keeps the address in step", () => {
    const sockets = socketFactory();
    stubRest({ modes: ["cassette"], anchor: "missing" });
    const replace = vi.spyOn(window.history, "replaceState").mockImplementation(() => undefined);
    render(<GuidedDemo apiUrl={API} initialStep="try" webSocket={sockets.factory} />);
    expect(screen.getByRole("button", { name: /Next/ }).hasAttribute("disabled")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: /Back/ }));
    expect(replace).toHaveBeenLastCalledWith(null, "", "/demo?step=normal");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("A normal bill");
    act(() => undefined);
  });

  it("says so and turns the answers off when the connection closes while a card is open", async () => {
    const page = open("pause", { stopAtCard: true });
    await screen.findByRole("dialog");
    act(() => {
      page.sockets[page.sockets.length - 1]?.closeWith(1006, "");
    });
    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain(
        "The connection to the server closed",
      );
    });
    for (const name of [/Use the account I normally use/, /No, stop this/, /Approve anyway/]) {
      expect(screen.getByRole("button", { name }).hasAttribute("disabled")).toBe(true);
    }
    expect(screen.getByRole("button", { name: "Run again" })).toBeTruthy();
  });
});
