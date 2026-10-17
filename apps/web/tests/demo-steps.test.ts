import { describe, expect, it } from "vitest";

import { DEMO_STEPS, activeStep, rootRedirectUrl, stepUrl } from "@/lib/demo-steps";
import { MODES, SCENARIOS, parseXRayParams, xrayUrl } from "@/lib/x-ray-state";
import type { ViewMode } from "@/lib/x-ray-state";

const VIEWS: readonly ViewMode[] = ["single", "three-lane"];

function parse(url: string) {
  const query = new URL(url, "http://x").searchParams;
  return parseXRayParams({
    scenario: query.get("scenario") ?? undefined,
    mode: query.get("mode") ?? undefined,
    view: query.get("view") ?? undefined,
    step: query.get("step") ?? undefined,
  });
}

describe("DEMO_STEPS", () => {
  it("has the four stage-script steps in order, all on the cassette stack [I6]", () => {
    expect(DEMO_STEPS.map((s) => s.id)).toEqual([1, 2, 3, 4]);
    expect(DEMO_STEPS.map((s) => s.title)).toEqual([
      "Undefended agent",
      "Classifier-only (stand-in)",
      "NOTARY escalates",
      "Legitimate bill",
    ]);
    expect(new Set(DEMO_STEPS.map((s) => s.mode))).toEqual(new Set(["cassette"]));
    expect(DEMO_STEPS.map((s) => [s.scenario, s.viewMode])).toEqual([
      ["poisoned_bill", "three-lane"],
      ["poisoned_bill", "three-lane"],
      ["poisoned_bill", "single"],
      ["legitimate_bill", "single"],
    ]);
    for (const step of DEMO_STEPS) {
      expect(step.description.length).toBeGreaterThan(20);
      expect(step.lookFor.length).toBeGreaterThan(1);
    }
  });

  it("makes step 3 the Reject beat and never claims the correct payee is confirmed [I6]", () => {
    const three = DEMO_STEPS[2];
    const text = [three?.description, ...(three?.lookFor ?? [])].join(" ");
    expect(text).toContain("Reject");
    expect(text).toContain("attacker light stays green");
    expect(JSON.stringify(DEMO_STEPS)).not.toMatch(/correct payee is confirmed|completes once/);
  });
});

describe("stepUrl and rootRedirectUrl", () => {
  it("round-trips every step through parseXRayParams [I6]", () => {
    for (const step of DEMO_STEPS) {
      const parsed = parse(stepUrl(step.id));
      expect(parsed.scenario).toBe(step.scenario);
      expect(parsed.mode).toBe(step.mode);
      expect(parsed.viewMode).toBe(step.viewMode);
      expect(activeStep(parsed.scenario, parsed.mode, parsed.viewMode, parsed.step)).toBe(step.id);
    }
  });

  it("names the step in the address only for step 2, and sends the root to step 1 [I6]", () => {
    expect(stepUrl(1)).toBe("/x-ray?scenario=poisoned_bill&mode=cassette&view=three");
    expect(stepUrl(2)).toBe("/x-ray?scenario=poisoned_bill&mode=cassette&view=three&step=2");
    expect(stepUrl(3)).toBe("/x-ray?scenario=poisoned_bill&mode=cassette&view=single");
    expect(stepUrl(4)).toBe("/x-ray?scenario=legitimate_bill&mode=cassette&view=single");
    expect(rootRedirectUrl()).toBe(stepUrl(1));
    expect(() => stepUrl(5)).toThrow(RangeError);
  });
});

describe("activeStep", () => {
  it("matches a screen to a step, for every state [I6]", () => {
    for (const scenario of [...SCENARIOS, "other"]) {
      for (const mode of MODES) {
        for (const viewMode of VIEWS) {
          for (const hint of [undefined, 1, 2, 3, 4]) {
            const got = activeStep(scenario, mode, viewMode, hint);
            let expected: number | null = null;
            if (mode === "cassette") {
              if (scenario === "poisoned_bill") {
                expected = viewMode === "three-lane" ? (hint === 2 ? 2 : 1) : 3;
              } else if (scenario === "legitimate_bill" && viewMode === "single") {
                expected = 4;
              }
            }
            expect(got, `${scenario} ${mode} ${viewMode} ${String(hint)}`).toBe(expected);
          }
        }
      }
    }
  });

  it("ignores a step hint that the screen does not fit [I6]", () => {
    expect(activeStep("poisoned_bill", "cassette", "single", 2)).toBe(3);
    expect(activeStep("poisoned_bill", "golden", "three-lane", 2)).toBeNull();
    expect(activeStep("legitimate_bill", "cassette", "single", 1)).toBe(4);
  });
});

describe("the step parameter", () => {
  it("is whitelisted to 1-4 and absent when there is none [I6]", () => {
    expect(parseXRayParams({})).toEqual({
      scenario: "poisoned_bill",
      mode: "golden",
      viewMode: "single",
    });
    expect("step" in parseXRayParams({})).toBe(false);
    for (const bad of ["0", "5", "-1", "1.5", "abc", "", " ", "1e1", "NaN"]) {
      expect("step" in parseXRayParams({ step: bad }), bad).toBe(false);
    }
    for (const good of [1, 2, 3, 4]) {
      expect(parseXRayParams({ step: String(good) }).step).toBe(good);
    }
    expect(parseXRayParams({ step: ["3", "1"] }).step).toBe(3);
    expect(parseXRayParams({ step: [] })).not.toHaveProperty("step");
  });

  it("is written to the address only when given [I6]", () => {
    const base = { scenario: "poisoned_bill", mode: "cassette", viewMode: "three-lane" as const };
    expect(xrayUrl(base)).toBe("/x-ray?scenario=poisoned_bill&mode=cassette&view=three");
    expect(xrayUrl({ ...base, step: 2 })).toBe(`${xrayUrl(base)}&step=2`);
  });
});
