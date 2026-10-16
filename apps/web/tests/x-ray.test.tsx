import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { XRayView } from "@/components/x-ray-view";
import { cn } from "@/lib/utils";

const file = resolve(
  import.meta.dirname,
  "../../../packages/world/fixtures/streams/poisoned_bill.notary.json",
);
const messages = (JSON.parse(readFileSync(file, "utf8")) as unknown[]).map((event) =>
  JSON.stringify(event),
);

class FakeSocket extends EventTarget {
  constructor() {
    super();
    queueMicrotask(() => {
      for (const data of messages) this.dispatchEvent(new MessageEvent("message", { data }));
      this.dispatchEvent(new CloseEvent("close", { code: 1000 }));
    });
  }
  close(): void {
    // nothing to release in the fake
  }
}

afterEach(cleanup);

describe("web", () => {
  it("cn merges tailwind classes", () => {
    expect(cn("p-2", "p-4")).toBe("p-4");
  });

  it("/x-ray renders the live typed event stream", async () => {
    render(
      <XRayView
        apiUrl="http://localhost:8000"
        scenario="poisoned_bill"
        webSocket={() => new FakeSocket() as unknown as WebSocket}
      />,
    );
    await waitFor(() => {
      expect(screen.getByText(/ESCALATE for c2/)).toBeTruthy();
    });
    expect(screen.getByLabelText("Intent contract")).toBeTruthy();
  });
});
