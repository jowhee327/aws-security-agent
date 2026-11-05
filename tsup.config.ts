import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "bin/aws-security-mcp.ts",
    "src/commands/dashboard.ts",
    "src/commands/deploy-dashboard.ts",
  ],
  format: ["esm"],
  outDir: "dist",
  splitting: false,
  clean: true,
  dts: true,
  sourcemap: true,
  // Transitive dep of the Azure SDK: keep external so ensureQuietAzureLogging() silences
  // the shared logger instance rather than a bundled copy.
  external: ["@azure/logger"],
});
