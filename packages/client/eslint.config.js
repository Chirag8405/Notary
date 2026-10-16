import { boundariesConfig } from "@notary/config-eslint/boundaries";
import { react } from "@notary/config-eslint/react";

export default [
  ...react(import.meta.dirname),
  ...boundariesConfig({ self: "@notary/client", allowed: ["@notary/schema"] }),
];
