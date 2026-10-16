import { boundariesConfig } from "@notary/config-eslint/boundaries";
import { next } from "@notary/config-eslint/next";

export default [
  ...next(import.meta.dirname),
  ...boundariesConfig({
    self: "@notary/web",
    allowed: ["@notary/ui", "@notary/client", "@notary/schema"],
  }),
];
