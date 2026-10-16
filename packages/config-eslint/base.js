import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

/**
 * Base flat config: strict, type-aware TypeScript. `any` is an error everywhere.
 * @param {string} tsconfigRootDir directory of the consuming package (use import.meta.dirname)
 */
export function base(tsconfigRootDir) {
  return defineConfig(
    globalIgnores(["dist/**", ".next/**", ".turbo/**", "node_modules/**", "src/generated/**"]),
    js.configs.recommended,
    tseslint.configs.strictTypeChecked,
    tseslint.configs.stylisticTypeChecked,
    {
      languageOptions: {
        globals: { ...globals.node },
        parserOptions: { projectService: true, tsconfigRootDir },
      },
      rules: {
        "@typescript-eslint/no-explicit-any": "error",
        "@typescript-eslint/no-unsafe-assignment": "error",
        "@typescript-eslint/no-unsafe-argument": "error",
        "@typescript-eslint/no-unsafe-call": "error",
        "@typescript-eslint/no-unsafe-member-access": "error",
        "@typescript-eslint/no-unsafe-return": "error",
        "@typescript-eslint/consistent-type-imports": "error",
        "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      },
    },
    {
      files: ["**/*.{js,mjs,cjs}"],
      extends: [tseslint.configs.disableTypeChecked],
    },
    prettier,
  );
}
