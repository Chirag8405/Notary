import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import Home from "@/app/page";
import { PlaygroundView } from "@/components/playground-view";
import { RunControls } from "@/components/run-controls";

afterEach(cleanup);

const API = "http://localhost:8000";

describe("playground page", () => {
  it("renders the four tabs in order and selects the initial one [-]", () => {
    render(<PlaygroundView apiUrl={API} initialMode="arena" />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((tab) => tab.textContent)).toEqual([
      "Poison the world",
      "Be the hijacked LLM",
      "Attack library",
      "Attacker arena",
    ]);
    expect(tabs.map((tab) => tab.getAttribute("aria-selected"))).toEqual([
      "false",
      "false",
      "false",
      "true",
    ]);
    expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe("Attacker arena");
  });

  it("switching a tab swaps the panel and the address [-]", () => {
    render(<PlaygroundView apiUrl={API} />);
    expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe("Poison the world");
    fireEvent.click(screen.getByRole("tab", { name: "Attack library" }));
    expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
    expect(screen.getByRole("tabpanel").getAttribute("aria-label")).toBe("Attack library");
    expect(window.location.search).toBe("?mode=library");
  });

  it("the home page links to the playground [-]", () => {
    render(<Home />);
    const link = screen.getByRole("link", { name: "Open judge playground" });
    expect(link.getAttribute("href")).toBe("/playground");
  });

  it("the x-ray controls link to the playground [-]", () => {
    render(
      <RunControls
        apiUrl={API}
        scenario="poisoned_bill"
        mode="golden"
        viewMode="single"
        onScenarioChange={() => undefined}
        onModeChange={() => undefined}
        onViewModeChange={() => undefined}
        onRunAgain={() => undefined}
      />,
    );
    expect(screen.getByRole("link", { name: "Judge playground" }).getAttribute("href")).toBe(
      "/playground",
    );
  });
});
