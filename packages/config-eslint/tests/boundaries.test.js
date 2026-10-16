import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

import { boundariesConfig } from "../boundaries.js";

async function lint(self, allowed, source) {
  const eslint = new ESLint({
    cwd: import.meta.dirname,
    overrideConfigFile: true,
    overrideConfig: boundariesConfig({ self, allowed }),
  });
  const [result] = await eslint.lintText(`import { x } from "${source}";\nexport { x };\n`, {
    filePath: `${import.meta.dirname}/virtual.mjs`,
  });
  return (result?.messages ?? []).filter((m) => m.ruleId === "boundaries/dependencies");
}

describe("TS dependency direction", () => {
  it("schema may not import anything from the workspace", async () => {
    for (const pkg of ["client", "ui", "web"]) {
      expect(await lint("@notary/schema", [], `@notary/${pkg}`)).toHaveLength(1);
    }
  });

  it("client and ui may import schema only", async () => {
    expect(await lint("@notary/client", ["@notary/schema"], "@notary/schema")).toHaveLength(0);
    expect(await lint("@notary/client", ["@notary/schema"], "@notary/ui")).toHaveLength(1);
    expect(await lint("@notary/ui", ["@notary/schema"], "@notary/client")).toHaveLength(1);
  });

  it("web may import ui, client and schema", async () => {
    const allowed = ["@notary/ui", "@notary/client", "@notary/schema"];
    for (const pkg of allowed) expect(await lint("@notary/web", allowed, pkg)).toHaveLength(0);
  });

  it("nothing imports web", async () => {
    expect(await lint("@notary/ui", ["@notary/schema"], "@notary/web")).toHaveLength(1);
  });
});
