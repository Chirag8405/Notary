import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { AsrChart, type AsrSeriesInput } from "../src";

afterEach(cleanup);

function rounds(count: number, successes: (round: number) => number) {
  return Array.from({ length: count }, (_, index) => ({
    round: index + 1,
    cumulativeSuccesses: successes(index + 1),
  }));
}

const CLASSIFIER: AsrSeriesInput = {
  label: "Classifier-only (stand-in)",
  rounds: rounds(3, (round) => round),
};
const NOTARY: AsrSeriesInput = { label: "NOTARY", rounds: rounds(3, () => 0) };

describe("AsrChart", () => {
  it("chart renders one polyline per series [A3]", () => {
    const { container } = render(<AsrChart series={[CLASSIFIER, NOTARY]} />);
    const lines = container.querySelectorAll("polyline[data-series]");
    expect([...lines].map((line) => line.getAttribute("data-series"))).toEqual([
      "Classifier-only (stand-in)",
      "NOTARY",
    ]);
    expect(lines[0]?.hasAttribute("stroke-dasharray")).toBe(false);
    expect(lines[1]?.getAttribute("stroke-dasharray")).toBe("6 4");
    expect(lines[0]?.getAttribute("points")).toBe("44,16 254,16 464,16");
    expect(lines[1]?.getAttribute("points")).toBe("44,204 254,204 464,204");
    expect(lines[0]?.getAttribute("class")).toContain("stroke-red-600");
    expect(lines[1]?.getAttribute("class")).toContain("stroke-blue-600");
    expect(container.querySelectorAll("circle[data-point]")).toHaveLength(6);
  });

  it("legend and accessible table", () => {
    render(<AsrChart series={[CLASSIFIER, NOTARY]} />);
    const legend = within(screen.getByRole("list", { name: "Legend" }));
    expect(legend.getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "Classifier-only (stand-in)",
      "NOTARY",
    ]);
    const table = within(screen.getByRole("table"));
    const body = table.getAllByRole("row").slice(1);
    expect(body).toHaveLength(6);
    expect(body.map((row) => row.textContent)).toEqual([
      "Classifier-only (stand-in)1100%",
      "Classifier-only (stand-in)2100%",
      "Classifier-only (stand-in)3100%",
      "NOTARY10%",
      "NOTARY20%",
      "NOTARY30%",
    ]);
  });

  it("aria label and title", () => {
    const { rerender } = render(<AsrChart series={[NOTARY]} />);
    expect(screen.getByRole("img", { name: "Attack success rate per round" })).toBeTruthy();
    rerender(<AsrChart series={[NOTARY]} title="X" />);
    expect(screen.getByRole("img", { name: "X" })).toBeTruthy();
  });

  it("labels the y axis at 0%, 50% and 100%", () => {
    const { container } = render(<AsrChart series={[NOTARY]} />);
    const labels = [...container.querySelectorAll('text[data-axis="y"]')].map(
      (node) => node.textContent,
    );
    expect(labels).toEqual(["0%", "50%", "100%"]);
  });

  it("empty input", () => {
    for (const series of [[], [{ label: "A", rounds: [] }]] as AsrSeriesInput[][]) {
      const { container } = render(<AsrChart series={series} />);
      expect(screen.getByText("No rounds to plot")).toBeTruthy();
      expect(container.querySelector("svg")).toBeNull();
      cleanup();
    }
  });

  it("long runs thin the x labels", () => {
    const { container } = render(
      <AsrChart series={[{ label: "A", rounds: rounds(12, () => 0) }]} />,
    );
    const labels = [...container.querySelectorAll('text[data-axis="x"]')].map(
      (node) => node.textContent,
    );
    expect(labels).toEqual(["1", "5", "10", "12"]);
  });

  it("labels every round up to ten rounds", () => {
    const { container } = render(
      <AsrChart series={[{ label: "A", rounds: rounds(10, () => 0) }]} />,
    );
    const labels = [...container.querySelectorAll('text[data-axis="x"]')].map(
      (node) => node.textContent,
    );
    expect(labels).toEqual(["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
  });

  it("uses the longest series for the x axis and cycles dash patterns", () => {
    const four = [0, 1, 2, 3].map((index) => ({
      label: `S${index}`,
      rounds: rounds(index + 1, () => 0),
    }));
    const { container } = render(<AsrChart series={four} />);
    const dashes = [...container.querySelectorAll("polyline[data-series]")].map((line) =>
      line.getAttribute("stroke-dasharray"),
    );
    expect(dashes).toEqual([null, "6 4", "2 3", "8 3 2 3"]);
    expect(container.querySelectorAll('text[data-axis="x"]')).toHaveLength(4);
  });

  it("determinism [I6]", () => {
    const first = render(<AsrChart series={[CLASSIFIER, NOTARY]} />).container.innerHTML;
    cleanup();
    const second = render(<AsrChart series={[CLASSIFIER, NOTARY]} />).container.innerHTML;
    expect(second).toBe(first);
  });
});
