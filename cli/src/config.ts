import * as fs from "node:fs";
import * as path from "node:path";

export const CONFIG_FILE = "airlift.json";

export interface AirliftConfig {
  server: string;
  org: string;
  app: string;
  appId: string;
}

export interface CommonOptions {
  server?: string;
  org?: string;
  app?: string;
  token?: string;
}

/** Walk up from cwd looking for airlift.json. Returns null if not found. */
export function findConfig(
  startDir: string = process.cwd()
): { config: Partial<AirliftConfig>; dir: string } | null {
  let dir = path.resolve(startDir);
  for (;;) {
    const file = path.join(dir, CONFIG_FILE);
    if (fs.existsSync(file)) {
      let raw: string;
      try {
        raw = fs.readFileSync(file, "utf8");
      } catch (err) {
        throw new Error(`Failed to read ${file}: ${(err as Error).message}`);
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new Error(`${file} is not valid JSON`);
      }
      return { config: parsed as Partial<AirliftConfig>, dir };
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export interface ResolvedContext {
  server: string;
  org: string;
  app: string;
  /** Known app id, if it came from airlift.json and was not invalidated by flag overrides. */
  appId: string | null;
  token: string;
  /** Directory containing airlift.json, or cwd if none. */
  projectDir: string;
}

/**
 * Merge CLI flags over airlift.json and the AIRLIFT_TOKEN env var.
 * Throws with a clear message when something required is missing.
 */
export function resolveContext(opts: CommonOptions): ResolvedContext {
  const found = findConfig();
  const file = found?.config ?? {};

  const server = opts.server ?? file.server;
  const org = opts.org ?? file.org;
  const app = opts.app ?? file.app;

  const missing: string[] = [];
  if (!server) missing.push("--server");
  if (!org) missing.push("--org");
  if (!app) missing.push("--app");
  if (missing.length > 0) {
    throw new Error(
      `Missing ${missing.join(", ")}. Run "airlift init" first, or pass the flag(s) explicitly.`
    );
  }

  const token = opts.token ?? process.env.AIRLIFT_TOKEN;
  if (!token) {
    throw new Error(
      "No access token. Set the AIRLIFT_TOKEN environment variable or pass --token <pat>."
    );
  }

  // The cached appId is only trustworthy if org/app/server were not overridden.
  const overridden =
    (opts.org !== undefined && opts.org !== file.org) ||
    (opts.app !== undefined && opts.app !== file.app) ||
    (opts.server !== undefined && opts.server !== file.server);
  const appId = !overridden && file.appId ? file.appId : null;

  return {
    server: server!,
    org: org!,
    app: app!,
    appId,
    token,
    projectDir: found?.dir ?? process.cwd(),
  };
}

export function writeConfig(dir: string, config: AirliftConfig): string {
  const file = path.join(dir, CONFIG_FILE);
  fs.writeFileSync(file, JSON.stringify(config, null, 2) + "\n");
  return file;
}
