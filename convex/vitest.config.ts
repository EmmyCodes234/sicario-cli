import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["convex/__tests__/**/*.test.ts"],
  },
  resolve: {
    alias: {
      convex: path.resolve(__dirname, "convex"),
    },
  },
});
