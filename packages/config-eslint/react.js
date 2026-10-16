import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

import { base } from "./base.js";

/** @param {string} tsconfigRootDir */
export function react(tsconfigRootDir) {
  return defineConfig(base(tsconfigRootDir), reactHooks.configs.flat["recommended-latest"], {
    languageOptions: { globals: { ...globals.browser } },
  });
}
