import { describe, expect, it } from "vitest";

import { MODE_INTRO, MODE_TITLES, PLAYGROUND_MODES } from "@/lib/playground-state";

describe("the playground mode intros", () => {
  it("explain every mode in one sentence", () => {
    for (const mode of PLAYGROUND_MODES) {
      expect(MODE_TITLES[mode].length).toBeGreaterThan(0);
      expect(MODE_INTRO[mode].length).toBeGreaterThan(0);
    }
  });
});
