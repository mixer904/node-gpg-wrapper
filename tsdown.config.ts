import { defineConfig } from "tsdown";

export default defineConfig([
  {
    entry: ["./src/index.ts"],
    platform: "node",
    dts: false,
    sourcemap: true,
    format: ["esm", "cjs"],
  },
  {
    entry: ["./src/browser.ts"],
    platform: "browser",
    dts: false,
    minify: true,
    sourcemap: true,
  },
]);
