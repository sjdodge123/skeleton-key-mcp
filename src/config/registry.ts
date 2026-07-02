import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import yaml from "js-yaml";
import { z } from "zod";
import type { Target } from "../connectors/types.js";
import { paths } from "./paths.js";

const targetSchema = z.object({
  name: z.string().min(1).regex(/^[a-z0-9][a-z0-9_-]*$/i, "Use letters, digits, dashes, underscores."),
  type: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().positive().optional(),
  credentialRef: z.string().min(1).optional(),
  options: z.record(z.unknown()).optional(),
});

const fileSchema = z.object({
  version: z.literal(1).default(1),
  targets: z.array(targetSchema).default([]),
});

/**
 * Persisted list of user-registered targets. Holds NO secrets — only a
 * `credentialRef` pointing at a Vaultwarden item. This is the single source of
 * truth for what services exist on *this* user's network; nothing is hard-coded.
 */
export class TargetRegistry {
  private targets: Target[] = [];

  private constructor(private readonly file: string) {}

  static async load(file: string = paths.registry): Promise<TargetRegistry> {
    const reg = new TargetRegistry(file);
    try {
      const raw = await readFile(file, "utf8");
      const parsed = fileSchema.parse(yaml.load(raw) ?? {});
      reg.targets = parsed.targets;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reg.targets = [];
      } else {
        throw err;
      }
    }
    return reg;
  }

  list(): readonly Target[] {
    return this.targets;
  }

  get(name: string): Target | undefined {
    return this.targets.find((t) => t.name === name);
  }

  async upsert(target: Target): Promise<void> {
    const parsed = targetSchema.parse(target);
    const idx = this.targets.findIndex((t) => t.name === parsed.name);
    if (idx >= 0) this.targets[idx] = parsed;
    else this.targets.push(parsed);
    await this.persist();
  }

  async remove(name: string): Promise<boolean> {
    const before = this.targets.length;
    this.targets = this.targets.filter((t) => t.name !== name);
    if (this.targets.length !== before) {
      await this.persist();
      return true;
    }
    return false;
  }

  private async persist(): Promise<void> {
    await mkdir(path.dirname(this.file), { recursive: true });
    const body = yaml.dump({ version: 1, targets: this.targets });
    await writeFile(this.file, body, { mode: 0o600 });
  }
}
