import { cleanup, render } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import "./dom-stubs";
import { ProvenanceGraph } from "../src/ProvenanceGraph";
import { viewOf } from "./golden";

afterEach(cleanup);

describe("ProvenanceGraph attribution", () => {
  it("shows React Flow's own attribution, because no Pro subscription is recorded [I6]", () => {
    const { container } = render(<ProvenanceGraph view={viewOf("poisoned_bill.notary")} />);
    const attribution = container.querySelector(".react-flow__attribution");
    expect(attribution).not.toBeNull();
    const link = attribution?.querySelector("a");
    expect(link?.textContent).toBe("React Flow");
    expect(link?.getAttribute("aria-label")).toBe("React Flow attribution");
  });

  it("does not ask React Flow to hide the attribution [I6]", () => {
    // The option cannot be seen in the DOM when it is set (the element is then simply absent), so
    // the component source is checked as well.
    const source = readFileSync(resolve(import.meta.dirname, "../src/ProvenanceGraph.tsx"), "utf8");
    expect(source).not.toContain("hideAttribution");
    expect(source).not.toContain("proOptions");
  });
});
