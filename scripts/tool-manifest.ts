// Regenerate tools.manifest.json from the live tool definitions.
// `npm run manifest` writes it; src/mcp/tool-manifest.test.ts fails when it is stale.
import { writeFileSync } from "node:fs";
import path from "node:path";
import { renderToolManifest } from "../src/mcp/tool-manifest.js";

const out = path.resolve(import.meta.dirname, "..", "tools.manifest.json");
writeFileSync(out, renderToolManifest());
console.log(`wrote ${path.relative(process.cwd(), out)}`);
