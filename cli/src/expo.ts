import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import JSZip from "jszip";

/**
 * Resolve the public Expo config via `npx expo config --json --type public`.
 * Stdout can contain leading non-JSON noise (package manager banners etc.),
 * so parse defensively starting at the first "{".
 */
export function resolveExpoConfig(cwd: string): Record<string, unknown> {
  const result = spawnSync("npx", ["expo", "config", "--json", "--type", "public"], {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: process.platform === "win32",
  });
  if (result.error) {
    throw new Error(`Failed to run "npx expo config": ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = (result.stderr ?? "").trim();
    throw new Error(
      `"npx expo config --json --type public" exited with code ${result.status}` +
        (stderr ? `:\n${stderr}` : "")
    );
  }
  const stdout = result.stdout ?? "";
  const start = stdout.indexOf("{");
  if (start < 0) {
    throw new Error(
      'Could not find JSON in the output of "npx expo config --json --type public".'
    );
  }
  const candidate = stdout.slice(start);
  try {
    return JSON.parse(candidate) as Record<string, unknown>;
  } catch {
    // There may be trailing noise too; retry up to the last "}".
    const end = stdout.lastIndexOf("}");
    if (end > start) {
      try {
        return JSON.parse(stdout.slice(start, end + 1)) as Record<string, unknown>;
      } catch {
        // fall through
      }
    }
    throw new Error('Failed to parse JSON output of "npx expo config".');
  }
}

/**
 * Derive the runtime version string from the resolved public config.
 * Returns null when it cannot be resolved (caller should require --runtime-version).
 */
export function resolveRuntimeVersion(
  config: Record<string, unknown>,
  platform: "ios" | "android"
): string | null {
  // A platform-level runtimeVersion (ios.runtimeVersion / android.runtimeVersion)
  // overrides the top-level one, exactly as expo-updates resolves it for builds.
  const platformConfig = config[platform];
  const platformRv =
    platformConfig && typeof platformConfig === "object"
      ? (platformConfig as { runtimeVersion?: unknown }).runtimeVersion
      : undefined;
  const rv = platformRv ?? config.runtimeVersion;
  if (typeof rv === "string" && rv.length > 0) return rv;
  if (rv && typeof rv === "object") {
    const policy = (rv as { policy?: unknown }).policy;
    if (policy === "appVersion") {
      const version = config.version;
      return typeof version === "string" && version.length > 0 ? version : null;
    }
    if (policy === "sdkVersion") {
      // expo-updates prefixes the SDK policy: builds request "exp@52.0.0".
      const sdk = config.sdkVersion;
      return typeof sdk === "string" && sdk.length > 0 ? `exp@${sdk}` : null;
    }
    return null; // nativeVersion, fingerprint, custom functions: not resolvable here
  }
  return null;
}

/** Run `npx expo export` into outputDir. Streams expo's output to the terminal. */
export function runExpoExport(
  cwd: string,
  outputDir: string,
  platform: "all" | "ios" | "android",
  sourceMaps = true
): void {
  const args = ["expo", "export", "--output-dir", outputDir];
  // Sourcemaps are uploaded with the update (stored privately on the server)
  // so device error stacks can be symbolicated.
  if (sourceMaps) {
    args.push("--source-maps");
  }
  if (platform !== "all") {
    args.push("--platform", platform);
  }
  const result = spawnSync("npx", args, {
    cwd,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (result.error) {
    throw new Error(`Failed to run "npx expo export": ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`"npx ${args.join(" ")}" exited with code ${result.status}.`);
  }
  if (!fs.existsSync(path.join(outputDir, "metadata.json"))) {
    throw new Error(
      `Export finished but ${outputDir}/metadata.json is missing; cannot build the archive.`
    );
  }
}

/** Zip the contents of dir (dir itself is the zip root, so metadata.json sits at /metadata.json). */
export async function zipDirectory(dir: string): Promise<Buffer> {
  const zip = new JSZip();
  const addDir = (abs: string, rel: string): void => {
    for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
      const absChild = path.join(abs, entry.name);
      const relChild = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        addDir(absChild, relChild);
      } else if (entry.isFile()) {
        zip.file(relChild, fs.readFileSync(absChild));
      }
    }
  };
  addDir(dir, "");
  return zip.generateAsync({
    type: "nodebuffer",
    compression: "DEFLATE",
    compressionOptions: { level: 6 },
  });
}

/** Best-effort git branch/commit for provenance metadata. */
export function gitInfo(cwd: string): { branch?: string; commit?: string } {
  const run = (args: string[]): string | undefined => {
    try {
      const result = spawnSync("git", args, { cwd, encoding: "utf8" });
      if (result.status === 0) {
        const out = (result.stdout ?? "").trim();
        if (out) return out;
      }
    } catch {
      // ignore: git missing or not a repo
    }
    return undefined;
  };
  return {
    branch: run(["rev-parse", "--abbrev-ref", "HEAD"]),
    commit: run(["rev-parse", "--short", "HEAD"]),
  };
}
