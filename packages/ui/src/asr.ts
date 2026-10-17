/**
 * Attack success rate (ASR) per round for the arena chart.
 *
 * Pure and deterministic: no React, clock, randomness or locale-dependent formatting. The input
 * types are the chart's own, so `packages/ui` does not import the REST client types.
 */

export interface AsrRoundInput {
  /** 1-based round number. */
  round: number;
  cumulativeSuccesses: number;
}

export interface AsrSeriesInput {
  label: string;
  rounds: readonly AsrRoundInput[];
}

export interface AsrPoint {
  round: number;
  /** In [0, 1]. */
  rate: number;
}

export interface AsrSeries {
  label: string;
  points: readonly AsrPoint[];
}

/** rate = cumulativeSuccesses / round, clamped to [0,1]; rounds sorted ascending; a round < 1 is dropped. */
export function asrSeries(input: AsrSeriesInput): AsrSeries {
  const points = input.rounds
    .filter((entry) => entry.round >= 1)
    .map((entry) => {
      const rate = entry.cumulativeSuccesses / entry.round;
      return {
        round: entry.round,
        rate: Number.isFinite(rate) ? Math.min(1, Math.max(0, rate)) : 0,
      };
    })
    .sort((a, b) => a.round - b.round);
  return { label: input.label, points };
}

export interface ChartGeometry {
  width: number;
  height: number;
  left: number;
  right: number;
  top: number;
  bottom: number;
}

export const DEFAULT_GEOMETRY: ChartGeometry = Object.freeze({
  width: 480,
  height: 240,
  left: 44,
  right: 16,
  top: 16,
  bottom: 36,
});

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** X coordinate of a round: rounds 1..maxRound spread evenly over the plot width. */
export function chartX(round: number, maxRound: number, geometry: ChartGeometry): number {
  const plotWidth = geometry.width - geometry.left - geometry.right;
  return round2(geometry.left + (plotWidth * (round - 1)) / Math.max(1, maxRound - 1));
}

/** Y coordinate of a rate in [0, 1]: 1 at the top of the plot, 0 at the bottom. */
export function chartY(rate: number, geometry: ChartGeometry): number {
  const plotHeight = geometry.height - geometry.top - geometry.bottom;
  return round2(geometry.top + (1 - rate) * plotHeight);
}

/** SVG user-space coordinates of the points of a series. */
export function chartPoints(
  series: AsrSeries,
  maxRound: number,
  geometry: ChartGeometry = DEFAULT_GEOMETRY,
): readonly { x: number; y: number }[] {
  return series.points.map((point) => ({
    x: chartX(point.round, maxRound, geometry),
    y: chartY(point.rate, geometry),
  }));
}
