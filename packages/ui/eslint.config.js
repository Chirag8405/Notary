import { boundariesConfig } from "@notary/config-eslint/boundaries";
import { react } from "@notary/config-eslint/react";

export default [
  ...react(import.meta.dirname),
  ...boundariesConfig({ self: "@notary/ui", allowed: ["@notary/schema"] }),
];
