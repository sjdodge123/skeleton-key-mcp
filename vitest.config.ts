import { defineConfig, defaultExclude } from "vitest/config";

export default defineConfig({
  test: {
    // Keep vitest out of .claude/ — stale agent worktrees there duplicate the
    // whole suite (and can drift from the real tree).
    exclude: [...defaultExclude, "**/.claude/**"],
  },
});
