import { describe, expectTypeOf, it } from "vitest";
import type { z } from "zod";

import type * as T from "../src/generated/types";
import type { EventSchema, MarkerSchema, OriginSchema, ValueRefSchema } from "../src/generated/zod";

// The generated TS types and the Zod-inferred types must be mutually assignable.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

describe("generated types and Zod validators agree", () => {
  it("Event", () => {
    expectTypeOf<Same<z.infer<typeof EventSchema>, T.Event>>().toEqualTypeOf<true>();
  });
  it("Marker", () => {
    expectTypeOf<Same<z.infer<typeof MarkerSchema>, T.Marker>>().toEqualTypeOf<true>();
  });
  it("Origin", () => {
    expectTypeOf<Same<z.infer<typeof OriginSchema>, T.Origin>>().toEqualTypeOf<true>();
  });
  it("ValueRef", () => {
    expectTypeOf<Same<z.infer<typeof ValueRefSchema>, T.ValueRef>>().toEqualTypeOf<true>();
  });
});
