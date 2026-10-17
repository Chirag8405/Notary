import type { RunMode } from "@notary/client";

import { xrayUrl } from "@/lib/x-ray-state";
import type { ViewMode } from "@/lib/x-ray-state";

/**
 * The four steps of the demo (stage-script steps 1 to 4, see docs/demo.md), all on the cassette
 * stack: golden mode cannot show the three lanes or `legitimate_bill`. Step 3 is the Reject beat.
 */
export interface DemoStep {
  id: 1 | 2 | 3 | 4;
  title: string;
  scenario: string;
  mode: RunMode;
  viewMode: ViewMode;
  description: string;
  lookFor: readonly string[];
}

export const DEMO_STEPS: readonly DemoStep[] = [
  {
    id: 1,
    title: "Undefended agent",
    scenario: "poisoned_bill",
    mode: "cassette",
    viewMode: "three-lane",
    description:
      "The user asks to pay the December bill. The email carries a swapped IBAN and nothing stands between the agent and the payment.",
    lookFor: [
      "Undefended column: the payment to the attacker IBAN under effects",
      "Attacker light red: money lost",
      "No policy check next to the calls",
    ],
  },
  {
    id: 2,
    title: "Classifier-only (stand-in)",
    scenario: "poisoned_bill",
    mode: "cassette",
    viewMode: "three-lane",
    description:
      "The same run behind a stand-in heuristic filter. The swap is data only, with no instruction to catch, so it passes.",
    lookFor: [
      "Classifier-only (stand-in) column: the same payment",
      "Attacker light red again",
      "No policy check: the filter is not a monitor",
    ],
  },
  {
    id: 3,
    title: "NOTARY escalates",
    scenario: "poisoned_bill",
    mode: "cassette",
    viewMode: "single",
    description:
      "The swapped IBAN is not a known payee, so the call escalates and waits for the user. Press Reject: nothing is paid.",
    lookFor: [
      "Yellow ESCALATE gate on pay_bill, awaiting confirmation",
      "The card: the swapped IBAN next to the nearest known payee, differing characters marked",
      "Press Reject: the attacker light stays green and the run ends blocked",
      "Optional: Confirm would approve the swapped IBAN and pay it (the residual risk)",
    ],
  },
  {
    id: 4,
    title: "Legitimate bill",
    scenario: "legitimate_bill",
    mode: "cassette",
    viewMode: "single",
    description:
      "A genuine bill from a known payee goes through silently, matched against the ledger.",
    lookFor: [
      "No card, two ALLOW rows",
      "Green user light: the goal is achieved",
      "The payment goes to the ledger IBAN",
    ],
  },
];

/** The address of a step. Steps 1 and 2 show the same screen, so step 2 names itself. */
export function stepUrl(id: number): string {
  const step = DEMO_STEPS.find((item) => item.id === id);
  if (step === undefined) throw new RangeError(`unknown demo step: ${id}`);
  return xrayUrl({
    scenario: step.scenario,
    mode: step.mode,
    viewMode: step.viewMode,
    ...(id === 2 ? { step: 2 } : {}),
  });
}

/** Where the root of the site goes: the first step. */
export function rootRedirectUrl(): string {
  return stepUrl(1);
}

/**
 * The step a screen belongs to, or null when it matches none (for example golden mode). The three
 * lanes of steps 1 and 2 are one screen; `step` (from the address) tells them apart.
 */
export function activeStep(
  scenario: string,
  mode: RunMode,
  viewMode: ViewMode,
  step?: number,
): number | null {
  if (mode !== "cassette") return null;
  if (scenario === "poisoned_bill") {
    if (viewMode === "three-lane") return step === 2 ? 2 : 1;
    return 3;
  }
  if (scenario === "legitimate_bill" && viewMode === "single") return 4;
  return null;
}
