import type { NextConfig } from "next";
import { fileURLToPath } from "node:url";

const config: NextConfig = {
  output: "standalone",
  transpilePackages: ["@notary/ui", "@notary/client", "@notary/schema"],
  outputFileTracingRoot: fileURLToPath(new URL("../../", import.meta.url)),
};

export default config;
