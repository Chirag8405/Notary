import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import type { AttackRunResponse } from "@notary/client";

import {
  CONTROL_IDS,
  PRIMARY_STOPS,
  checkRows,
  compareAttacks,
  describeOutcome,
  runBadge,
} from "@/lib/attack-library";

import { fixture } from "./playground-fixtures";

const threatModel = readFileSync(
  resolve(import.meta.dirname, "../../../docs/threat-model.md"),
  "utf8",
);

describe("attack library helpers", () => {
  it("describeOutcome", () => {
    expect(describeOutcome(null)).toBe("none");
    expect(
      describeOutcome({ verdict: "ALLOW", deciding_check: null, code: "READ_ONLY_UNGATED" }),
    ).toBe("ALLOW READ_ONLY_UNGATED");
    expect(
      describeOutcome({
        verdict: "ESCALATE",
        deciding_check: "corroboration",
        code: "LEDGER_NOVEL_ESCALATE",
      }),
    ).toBe("ESCALATE corroboration LEDGER_NOVEL_ESCALATE");
    expect(
      describeOutcome({
        verdict: "BLOCK",
        deciding_check: "scope",
        code: "SCOPE_TOOL_NOT_IN_CONTRACT",
      }),
    ).toBe("BLOCK scope SCOPE_TOOL_NOT_IN_CONTRACT");
    expect(describeOutcome({ verdict: "BLOCK", deciding_check: null, code: null })).toBe("BLOCK");
  });

  it("runBadge precedence [A13]", () => {
    expect(runBadge({ ok: true, deferred: true })).toBe("deferred");
    expect(runBadge({ ok: true, deferred: false })).toBe("matches");
    expect(runBadge({ ok: false, deferred: false })).toBe("mismatch");
    expect(runBadge({ ok: false, deferred: true })).toBe("deferred");
  });

  it("checkRows [A3]", () => {
    const body = fixture("attack.A3").body as AttackRunResponse;
    expect(checkRows(body.checks)).toEqual([
      {
        callId: "A3.c0",
        tool: "read_inbox",
        expected: "ALLOW READ_ONLY_UNGATED",
        actual: "ALLOW READ_ONLY_UNGATED",
        matches: true,
      },
      {
        callId: "A3.c1",
        tool: "pay_bill",
        expected: "ESCALATE corroboration LEDGER_NOVEL_ESCALATE",
        actual: "ESCALATE corroboration LEDGER_NOVEL_ESCALATE",
        matches: true,
      },
    ]);
  });

  it("checkRows shows a missing actual as none", () => {
    const [row] = checkRows([
      {
        call_id: "X.c0",
        tool: "pay_bill",
        expected: { verdict: "BLOCK", deciding_check: "scope", code: null },
        actual: null,
        matches: false,
      },
    ]);
    expect(row?.actual).toBe("none");
    expect(row?.expected).toBe("BLOCK scope");
  });

  it("PRIMARY_STOPS covers every attack [A1-A14]", () => {
    const ids = Array.from({ length: 14 }, (_, index) => `A${index + 1}`);
    expect(Object.keys(PRIMARY_STOPS).sort()).toEqual([...ids].sort());
    // Each hint is the "Primary stop" cell of the attack's row in the threat model.
    for (const id of ids) {
      const row = threatModel.split("\n").find((line) => line.startsWith(`| ${id} `));
      const cells = (row ?? "").split("|").map((cell) => cell.trim());
      expect(cells[4], id).toBe(PRIMARY_STOPS[id as keyof typeof PRIMARY_STOPS]);
    }
    expect(CONTROL_IDS).toEqual(["B1", "B2", "B3", "B4"]);
  });

  it("compareAttacks orders numerically", () => {
    const sorted = (["A10", "A2", "A1", "A9"] as const)
      .map((id) => ({ id }))
      .sort(compareAttacks)
      .map((item) => item.id);
    expect(sorted).toEqual(["A1", "A2", "A9", "A10"]);
  });
});
