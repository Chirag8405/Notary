import type { NextConfig } from "next";

const config: NextConfig = {
  output: "standalone",
  transpilePackages: ["@notary/ui", "@notary/client", "@notary/schema"],
  outputFileTracingRoot: new URL("../../", import.meta.url).pathname,
};

export default config;
