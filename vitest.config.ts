import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const packages = [
  "core",
  "server",
  "auth",
  "policy",
  "observability",
  "evals",
  "importers",
  "dom",
  "testing",
  "cli",
] as const;

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  resolve: {
    alias: packages.map((pkg) => ({
      find: new RegExp(`^gapmcp-${pkg}$`),
      replacement: `${root}packages/${pkg}/src/index.ts`,
    })),
  },
  test: {
    include: [
      "packages/*/test/**/*.test.ts",
      "packages/*/src/**/*.test.ts",
      "test/**/*.test.ts",
    ],
    exclude: ["**/node_modules/**", "**/dist/**", "python/**", "go/**"],
    testTimeout: 20_000,
    hookTimeout: 20_000,
    pool: "forks",
  },
});
