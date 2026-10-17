import { createRestClient } from "@notary/client";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AnchorFooter } from "@/components/anchor-footer";

import { stubRest } from "./fake-run";

const API = "http://localhost:8000";
const ANCHOR = { head: "sha256:0123456789abcdef0123456789abcdef", length: 4 };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function setup() {
  // The REST client binds `fetch` when it is created, so the stub comes first.
  const rest = stubRest({ modes: [], anchor: ANCHOR });
  return { rest, client: createRestClient(API) };
}

async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("AnchorFooter", () => {
  it("asks nothing and shows nothing until the run has finished [I1]", async () => {
    const { rest, client } = setup();
    const { rerender, container } = render(
      <AnchorFooter client={client} runId="run-1" finished={false} />,
    );
    await settle();
    expect(rest.calls).toEqual([]);
    expect(container.textContent).toBe("");

    rerender(<AnchorFooter client={client} runId="run-1" finished />);
    expect((await screen.findByLabelText("Audit anchor")).textContent).toBe(
      "Audit head 0123456789ab | 4 entries | persisted outside the log",
    );
    expect(rest.calls).toEqual(["/runs/run-1/anchor"]);
  });

  it("shows nothing for a run without an id [I1]", async () => {
    const { rest, client } = setup();
    const { container } = render(<AnchorFooter client={client} runId={null} finished />);
    await settle();
    expect(rest.calls).toEqual([]);
    expect(container.textContent).toBe("");
  });

  it("asks once per run id and again for another run [I6]", async () => {
    const { rest, client } = setup();
    const { rerender } = render(<AnchorFooter client={client} runId="run-1" finished />);
    await screen.findByLabelText("Audit anchor");
    rerender(<AnchorFooter client={client} runId="run-1" finished />);
    await settle();
    expect(rest.calls).toEqual(["/runs/run-1/anchor"]);

    rerender(<AnchorFooter client={client} runId="run-2" finished />);
    await settle();
    await screen.findByLabelText("Audit anchor");
    expect(rest.calls).toEqual(["/runs/run-1/anchor", "/runs/run-2/anchor"]);
  });

  it("does not update state after unmount [I6]", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { client } = setup();
    const { unmount } = render(<AnchorFooter client={client} runId="run-1" finished />);
    unmount();
    await settle();
    expect(error).not.toHaveBeenCalled();
    error.mockRestore();
  });
});
