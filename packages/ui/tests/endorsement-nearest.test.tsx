import type { DiffRow, Endorsement } from "@notary/schema";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EndorsementCard } from "../src/EndorsementCard";
import type { CardState } from "../src/EndorsementCard";
import { must, viewOf } from "./golden";

afterEach(cleanup);

const REAL: Endorsement = must(
  viewOf("poisoned_bill.notary").endorsements[0],
  "an endorsement",
).endorsement;
const ROW: DiffRow = must(REAL.card.rows[0], "the payee row");
const NEAREST = "Use nearest known value";

function show(
  endorsement: Endorsement,
  state: CardState = "pending",
  approvals: number | null = 3,
) {
  const onDecide = vi.fn<(decision: "approve" | "reject" | "use_nearest") => void>();
  render(
    <EndorsementCard
      endorsement={endorsement}
      remainingApprovals={approvals}
      state={state}
      onDecide={onDecide}
    />,
  );
  return onDecide;
}

describe("EndorsementCard: use the nearest known value", () => {
  it("is offered when the ledger has a value for the row, and reports use_nearest once [I4]", () => {
    expect(ROW.nearest_ledger_value).not.toBeNull();
    const onDecide = show(REAL);
    fireEvent.click(screen.getByRole("button", { name: NEAREST }));
    expect(onDecide).toHaveBeenCalledTimes(1);
    expect(onDecide).toHaveBeenCalledWith("use_nearest");
  });

  it("is not offered without a known value for every row, or without rows [I4]", () => {
    show({
      ...REAL,
      card: { rows: [{ ...ROW, nearest_ledger_value: null, differing_positions: [] }] },
    });
    expect(screen.queryByRole("button", { name: NEAREST })).toBeNull();
    expect(screen.getAllByRole("button")).toHaveLength(2);
    cleanup();
    const second: DiffRow = {
      ...ROW,
      param: "memo",
      value_id: "c2.arg.memo",
      nearest_ledger_value: null,
    };
    show({ ...REAL, card: { rows: [ROW, second] } });
    expect(screen.queryByRole("button", { name: NEAREST })).toBeNull();
    cleanup();
    show({ ...REAL, card: { rows: [] } });
    expect(screen.queryByRole("button", { name: NEAREST })).toBeNull();
  });

  it("stays available when no approvals are left, because it approves nothing [I4]", () => {
    const onDecide = show(REAL, "pending", 0);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Confirm" }).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: NEAREST }));
    expect(onDecide).toHaveBeenCalledWith("use_nearest");
  });

  it("is disabled once the card is not pending, and says what happened [I4]", () => {
    for (const state of ["sending", "approved", "rejected", "replaced"] as const) {
      const onDecide = show(REAL, state);
      expect(screen.getByRole<HTMLButtonElement>("button", { name: NEAREST }).disabled, state).toBe(
        true,
      );
      fireEvent.click(screen.getByRole("button", { name: NEAREST }));
      expect(onDecide).not.toHaveBeenCalled();
      cleanup();
    }
    show(REAL, "replaced");
    expect(screen.getByText("You asked for the nearest known value instead")).toBeTruthy();
  });

  it("is gone with the other buttons when the request is no longer open [I4]", () => {
    show(REAL, "conflict");
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});
