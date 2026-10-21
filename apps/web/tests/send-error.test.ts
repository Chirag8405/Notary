import { describe, expect, it } from "vitest";

import { describeSendError } from "@/lib/send-error";

describe("describeSendError", () => {
  it("explains a closed connection and keeps the technical phrase", () => {
    const text = describeSendError(new Error("run socket is not open"));
    expect(text).toContain("The connection to the server closed");
    expect(text).toContain("Press Run again");
    expect(text).toContain("run socket is not open");
  });

  it("passes any other message through, and covers a non-error", () => {
    expect(describeSendError(new Error("payee is required"))).toBe("payee is required");
    expect(describeSendError("oops")).toBe("could not send the answer");
  });
});
