import boundaries from "eslint-plugin-boundaries";

/** Every workspace TypeScript package that may be imported by name. */
const TS_PACKAGES = ["@notary/schema", "@notary/client", "@notary/ui", "@notary/web"];

/**
 * Dependency direction for TS packages (see CLAUDE.md):
 *   schema -> (nothing)    client -> schema    ui -> schema    web -> ui, client, schema
 * Any other `@notary/*` import fails lint.
 *
 * @param {{ self: string, allowed: string[] }} options
 */
export function boundariesConfig({ self, allowed }) {
  const forbidden = TS_PACKAGES.filter((name) => name !== self && !allowed.includes(name));
  return [
    {
      files: ["**/*.{ts,tsx,js,jsx,mjs}"],
      plugins: { boundaries },
      settings: {
        "boundaries/elements": [{ type: "source", pattern: "**/*" }],
      },
      rules: {
        "boundaries/dependencies": [
          2,
          {
            default: "allow",
            checkAllOrigins: true,
            policies: forbidden.map((source) => ({
              from: { element: { type: "source" } },
              disallow: { to: { module: { source } } },
              message: `${self} must not depend on ${source} (allowed: ${allowed.join(", ") || "none"})`,
            })),
          },
        ],
      },
    },
  ];
}
