import { CommandSchema, EventSchema } from "@notary/schema";
import type { Command } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import type { EndorsementView } from "@notary/ui";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementPanel } from "@/components/endorsement-panel";
import type { PendingItem } from "@/components/endorsement-panel";

const file = resolve(
  import.meta.dirname,
  "../../../packages/world/fixtures/streams/poisoned_bill.notary.json",
);
const view = foldEvents(EventSchema.array().parse(JSON.parse(readFileSync(file, "utf8"))));
const FIRST = view.endorsements[0];
if (FIRST === undefined) throw new Error("fixture has no endorsement");
const ID = FIRST.endorsement.endorsement_id;
const RUN_ID = view.runId ?? "";

afterEach(cleanup);

async function settle(run: () => void = () => undefined): Promise<void> {
  await act(async () => {
    run();
    await Promise.resolve();
  });
}

function mount(list: readonly PendingItem[][]) {
  const send = vi.fn<(command: Command) => void>();
  const fetchPending = vi.fn<() => Promise<readonly PendingItem[]>>();
  for (const answer of list.slice(0, -1)) fetchPending.mockResolvedValueOnce(answer);
  fetchPending.mockResolvedValue(list.at(-1) ?? []);
  const onResolved = vi.fn<(resolved: ReadonlySet<string>) => void>();
  const onRejected = vi.fn<(rejected: ReadonlySet<string>) => void>();
  render(
    <EndorsementPanel
      runId={RUN_ID}
      endorsements={[FIRST] as readonly EndorsementView[]}
      send={send}
      fetchPending={fetchPending}
      onResolvedChange={onResolved}
      onRejectedChange={onRejected}
    />,
  );
  return { send, onResolved, onRejected };
}

const pending: PendingItem = { endorsement: { endorsement_id: ID }, remaining_approvals: 3 };
const nearest = (): HTMLButtonElement =>
  screen.getByRole<HTMLButtonElement>("button", { name: "Use nearest known value" });

describe("EndorsementPanel: use the nearest known value", () => {
  it("sends exactly one valid use_nearest command [I4]", async () => {
    const d = mount([[pending]]);
    await settle();
    fireEvent.click(nearest());
    fireEvent.click(nearest());
    expect(d.send).toHaveBeenCalledTimes(1);
    const command: unknown = d.send.mock.calls[0]?.[0];
    expect(CommandSchema.safeParse(command).success).toBe(true);
    expect(command).toEqual({
      type: "endorsement_decision",
      run_id: RUN_ID,
      endorsement_id: ID,
      decision: "use_nearest",
    });
  });

  it("resolves to replaced once the card leaves the pending list, and is not a rejection [I4]", async () => {
    const d = mount([[pending], []]);
    await settle();
    fireEvent.click(nearest());
    await settle();
    expect(
      document.querySelector(`[data-endorsement-id="${ID}"]`)?.getAttribute("data-state"),
    ).toBe("replaced");
    expect(screen.getByText("You asked for the nearest known value instead")).toBeTruthy();
    expect([...(d.onResolved.mock.calls.at(-1)?.[0] ?? [])]).toEqual([ID]);
    expect(d.onRejected).not.toHaveBeenCalled();
  });
});
