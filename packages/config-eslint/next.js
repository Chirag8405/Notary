import nextPlugin from "@next/eslint-plugin-next";
import { defineConfig, globalIgnores } from "eslint/config";

import { react } from "./react.js";

/** @param {string} tsconfigRootDir */
export function next(tsconfigRootDir) {
  return defineConfig(
    react(tsconfigRootDir),
    globalIgnores(["next-env.d.ts"]),
    nextPlugin.configs["core-web-vitals"],
  );
}
