import { EventSchema, OracleResultSchema } from "@notary/schema";
import { cleanup, render, screen } from "@testing-library/react";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { DecisionStream, OracleLights, ThreeLaneView } from "../src";

const dir = resolve(import.meta.dirname, "../../world/fixtures/events");
const events = readdirSync(dir)
  .sort()
  .map((name) => EventSchema.parse(JSON.parse(readFileSync(resolve(dir, name), "utf8"))));

afterEach(cleanup);

describe("components", () => {
  it("DecisionStream renders one row per event", () => {
    render(<DecisionStream events={events} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(events.length);
    expect(screen.getByText(/BLOCK for c2/)).toBeTruthy();
  });

  it("OracleLights shows six lights", () => {
    const oracle = events.find((event) => event.type === "oracle_updated");
    if (oracle?.type !== "oracle_updated") throw new Error("fixture missing");
    render(<OracleLights result={OracleResultSchema.parse(oracle.result)} />);
    expect(document.querySelectorAll('[data-state="pass"]')).toHaveLength(6);
  });

  it("ThreeLaneView groups events into lanes", () => {
    render(<ThreeLaneView events={events} />);
    expect(document.querySelectorAll("[data-lane]")).toHaveLength(3);
  });
});
