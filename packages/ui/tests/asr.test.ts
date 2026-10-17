import { describe, expect, it } from "vitest";

import { DEFAULT_GEOMETRY, asrSeries, chartPoints } from "../src/asr";

const CLASSIFIER = asrSeries({
  label: "Classifier-only (stand-in)",
  rounds: [
    { round: 1, cumulativeSuccesses: 1 },
    { round: 2, cumulativeSuccesses: 2 },
    { round: 3, cumulativeSuccesses: 3 },
  ],
});
const NOTARY = asrSeries({
  label: "NOTARY",
  rounds: [
    { round: 1, cumulativeSuccesses: 0 },
    { round: 2, cumulativeSuccesses: 0 },
    { round: 3, cumulativeSuccesses: 0 },
  ],
});

describe("asrSeries", () => {
  it("asrSeries rates", () => {
    const { points } = asrSeries({
      label: "L",
      rounds: [
        { round: 1, cumulativeSuccesses: 1 },
        { round: 2, cumulativeSuccesses: 1 },
        { round: 3, cumulativeSuccesses: 2 },
      ],
    });
    expect(points.map((point) => point.rate)[0]).toBe(1);
    expect(points[1]?.rate).toBe(0.5);
    expect(points[2]?.rate).toBeCloseTo(2 / 3);

    const clamped = asrSeries({
      label: "L",
      rounds: [
        { round: 1, cumulativeSuccesses: 5 },
        { round: 2, cumulativeSuccesses: -1 },
        { round: 3, cumulativeSuccesses: NaN },
      ],
    });
    expect(clamped.points.map((point) => point.rate)).toEqual([1, 0, 0]);
  });

  it("asrSeries sorts and drops", () => {
    const input = {
      label: "L",
      rounds: [
        { round: 3, cumulativeSuccesses: 1 },
        { round: 0, cumulativeSuccesses: 9 },
        { round: 1, cumulativeSuccesses: 1 },
      ],
    };
    const before = JSON.stringify(input);
    const result = asrSeries(input);
    expect(result.points.map((point) => point.round)).toEqual([1, 3]);
    expect(JSON.stringify(input)).toBe(before);
    expect(result.label).toBe("L");
  });
});

describe("chartPoints", () => {
  it("chartPoints worked example", () => {
    expect(chartPoints(CLASSIFIER, 3)).toEqual([
      { x: 44, y: 16 },
      { x: 254, y: 16 },
      { x: 464, y: 16 },
    ]);
    expect(chartPoints(NOTARY, 3, DEFAULT_GEOMETRY)).toEqual([
      { x: 44, y: 204 },
      { x: 254, y: 204 },
      { x: 464, y: 204 },
    ]);
  });

  it("chartPoints single round", () => {
    const single = asrSeries({ label: "L", rounds: [{ round: 1, cumulativeSuccesses: 1 }] });
    expect(chartPoints(single, 1)[0]?.x).toBe(44);
  });

  it("rounds coordinates to two decimals", () => {
    const third = asrSeries({ label: "L", rounds: [{ round: 3, cumulativeSuccesses: 1 }] });
    expect(chartPoints(third, 7)[0]).toEqual({ x: 254, y: 142.67 });
  });
});
