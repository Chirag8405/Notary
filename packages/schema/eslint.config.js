import { base } from "@notary/config-eslint/base";
import { boundariesConfig } from "@notary/config-eslint/boundaries";

export default [
  ...base(import.meta.dirname),
  ...boundariesConfig({ self: "@notary/schema", allowed: [] }),
];
