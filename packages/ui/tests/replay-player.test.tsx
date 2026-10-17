import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ReplayPlayer, ReplayScrubber } from "../src";
import { load } from "./golden";

const events = load("poisoned_bill.notary");
const END = events.length;

afterEach(cleanup);

function setup(position: number, list = events) {
  const onPositionChange = vi.fn<(position: number) => void>();
  render(<ReplayPlayer events={list} position={position} onPositionChange={onPositionChange} />);
  return onPositionChange;
}

function button(name: string): HTMLButtonElement {
  const found = screen.getByRole("button", { name });
  if (!(found instanceof HTMLButtonElement)) throw new Error(`${name} is not a button`);
  return found;
}

describe("ReplayPlayer", () => {
  it("player buttons", () => {
    const onChange = setup(7);
    expect(screen.getByRole("group", { name: "Replay" })).toBeTruthy();
    expect(screen.getByTestId("replay-position").textContent).toBe(`Event 7 of ${END}`);

    fireEvent.click(button("Next"));
    expect(onChange).toHaveBeenLastCalledWith(8);
    fireEvent.click(button("Previous"));
    expect(onChange).toHaveBeenLastCalledWith(6);
    fireEvent.click(button("First"));
    expect(onChange).toHaveBeenLastCalledWith(0);
    fireEvent.click(button("Last"));
    expect(onChange).toHaveBeenLastCalledWith(END);
    expect(onChange).toHaveBeenCalledTimes(4);
  });

  it("disables the backward buttons at the start and the forward buttons at the end", () => {
    setup(0);
    expect(button("First").disabled).toBe(true);
    expect(button("Previous").disabled).toBe(true);
    expect(button("Next").disabled).toBe(false);
    expect(button("Last").disabled).toBe(false);
    expect(screen.getByTestId("replay-position").textContent).toBe(`Start (0 of ${END})`);
    cleanup();

    setup(END);
    expect(button("Next").disabled).toBe(true);
    expect(button("Last").disabled).toBe(true);
    expect(button("First").disabled).toBe(false);
    expect(button("Previous").disabled).toBe(false);
  });

  it("player range", () => {
    const onChange = setup(7);
    const range = screen.getByLabelText("Replay position");
    fireEvent.change(range, { target: { value: "5" } });
    expect(onChange).toHaveBeenLastCalledWith(5);
    fireEvent.change(range, { target: { value: "999" } });
    expect(onChange).toHaveBeenLastCalledWith(END);
  });

  it("uses the label prop for the group", () => {
    render(
      <ReplayPlayer
        events={events}
        position={1}
        onPositionChange={() => undefined}
        label="Lane run"
      />,
    );
    expect(screen.getByRole("group", { name: "Lane run" })).toBeTruthy();
  });

  it("empty run", () => {
    const onChange = setup(0, []);
    for (const name of ["First", "Previous", "Next", "Last"]) {
      expect(button(name).disabled).toBe(true);
    }
    expect(screen.getByLabelText<HTMLInputElement>("Replay position").disabled).toBe(true);
    expect(screen.getByTestId("replay-position").textContent).toBe("No events");
    expect(onChange).not.toHaveBeenCalled();
  });

  it("scrubber range includes length", () => {
    render(<ReplayScrubber length={20} index={20} onChange={() => undefined} />);
    const range = screen.getByLabelText<HTMLInputElement>("Replay position");
    expect(range.max).toBe("20");
    expect(range.disabled).toBe(false);
    cleanup();
    render(<ReplayScrubber length={0} index={0} onChange={() => undefined} />);
    expect(screen.getByLabelText<HTMLInputElement>("Replay position").disabled).toBe(true);
  });
});
