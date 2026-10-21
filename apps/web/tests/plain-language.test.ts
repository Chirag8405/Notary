import type { Decision, Reason } from "@notary/schema";
import { describe, expect, it } from "vitest";

import {
  CHECK_TEXT,
  REASON_TEXT,
  decidingReason,
  explainDecision,
  paramText,
  reasonTextFor,
  toolText,
  verdictText,
} from "@/lib/plain-language";

function reason(code: Reason["code"], outcome: Reason["outcome"], check: Reason["check"]): Reason {
  return { code, outcome, check, detail: "" };
}

describe("plain language", () => {
  it("names the three verdicts in words", () => {
    expect(verdictText("ALLOW").label).toBe("Allowed");
    expect(verdictText("ESCALATE").label).toBe("Needs your approval");
    expect(verdictText("BLOCK").label).toBe("Stopped");
  });

  it("covers every check and every reason code with no code left in the text", () => {
    for (const text of [...Object.values(CHECK_TEXT), ...Object.values(REASON_TEXT)]) {
      expect(text).not.toMatch(/[A-Z]{3,}_[A-Z_]+/);
      expect(text.length).toBeGreaterThan(0);
    }
  });

  it("explains a decision by the first reason that did not pass", () => {
    const decision: Decision = {
      verdict: "ESCALATE",
      diff_card: null,
      reasons: [
        reason("STEP_PASS", "pass", "scope"),
        reason("LEDGER_NOVEL_ESCALATE", "escalate", "corroboration"),
        reason("STEP_PASS", "pass", "budget"),
      ],
    };
    expect(decidingReason(decision)?.code).toBe("LEDGER_NOVEL_ESCALATE");
    expect(explainDecision(decision)).toBe(REASON_TEXT.LEDGER_NOVEL_ESCALATE);
  });

  it("falls back to the verdict sentence when there are no reasons", () => {
    const decision: Decision = { verdict: "ALLOW", diff_card: null, reasons: [] };
    expect(decidingReason(decision)).toBeNull();
    expect(explainDecision(decision)).toBe(verdictText("ALLOW").sentence);
  });

  it("speaks of tools and parameters as a person does, and humanizes unknown ones", () => {
    expect(toolText("pay_bill")).toBe("Pay a bill");
    expect(toolText("archive_thread")).toBe("Archive thread");
    expect(paramText("iban")).toBe("Account (IBAN)");
    expect(paramText("due_date")).toBe("Due date");
  });

  it("looks up a reason code given as text, and answers null for an unknown one", () => {
    expect(reasonTextFor("LEDGER_NOVEL_ESCALATE")).toBe(REASON_TEXT.LEDGER_NOVEL_ESCALATE);
    expect(reasonTextFor("NOT_A_CODE")).toBeNull();
    expect(reasonTextFor("toString")).toBeNull();
  });
});
