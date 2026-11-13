/**
 * Harness for the CLI end-to-end suite: a real `airlift serve` (plus the S3
 * stub it stores into), the real built CLI (`cli/dist/index.js`, run with
 * node like `npx airlift-cli` would), the real Expo project in
 * `e2e-device/app` (so `publish` runs a real `expo export`), and an
 * expo-updates client that checks what a device would actually be served.
 *
 * Nothing is mocked: every assertion goes over the wire to the same binary
 * that runs in production. `e2e-cli/run.sh` builds everything first.
 */
import { createHash, createVerify } from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

export const ROOT = path.resolve(import.meta.dir, "..");
export const APP_DIR = path.join(ROOT, "e2e-device", "app");
const CLI_JS = path.join(ROOT, "cli", "dist", "index.js");
const AIRLIFT_BIN = process.env.AIRLIFT_BIN ?? path.join(ROOT, "target", "debug", "airlift");
const S3_STUB_BIN =
  process.env.S3_STUB_BIN ?? path.join(ROOT, "target", "debug", "examples", "s3_stub");

export const ORG = "acme";
export const APP = "e2e";

/* ───────────────────────── processes ───────────────────────── */

async function freePort(): Promise<number> {
  const srv = net.createServer();
  await new Promise<void>((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const port = (srv.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => srv.close(() => resolve()));
  return port;
}

function requireFile(file: string, hint: string): void {
  if (!fs.existsSync(file)) throw new Error(`${file} is missing; ${hint}`);
}

/** A running airlift + S3 stub with an admin session, torn down by stop(). */
export class Instance {
  private procs: ReturnType<typeof Bun.spawn>[] = [];
  private cookie = "";
  appId = "";

  private constructor(
    readonly base: string,
    readonly work: string
  ) {}

  static async start(): Promise<Instance> {
    requireFile(AIRLIFT_BIN, "run e2e-cli/run.sh (or cargo build --bin airlift --example s3_stub)");
    requireFile(S3_STUB_BIN, "run e2e-cli/run.sh (or cargo build --example s3_stub)");
    requireFile(CLI_JS, "run e2e-cli/run.sh (or cd cli && bun run build)");

    const work = fs.mkdtempSync(path.join(os.tmpdir(), "airlift-cli-e2e-"));
    const [port, s3Port] = [await freePort(), await freePort()];
    const inst = new Instance(`http://127.0.0.1:${port}`, work);

    const log = (name: string) => Bun.file(path.join(work, name));
    inst.procs.push(
      Bun.spawn([S3_STUB_BIN, `127.0.0.1:${s3Port}`], { stdout: log("s3.log"), stderr: log("s3.log") })
    );
    inst.procs.push(
      Bun.spawn([AIRLIFT_BIN, "--config", path.join(work, "none.toml"), "serve"], {
        env: {
          ...process.env,
          RUST_LOG: process.env.RUST_LOG ?? "info",
          AIRLIFT_DATABASE__PATH: path.join(work, "airlift.db"),
          AIRLIFT_SERVER__HTTP_ADDR: `127.0.0.1:${port}`,
          AIRLIFT_SERVER__PUBLIC_URL: inst.base,
          AIRLIFT_TLS__ENABLED: "false",
          AIRLIFT_STORAGE__ENDPOINT: `http://127.0.0.1:${s3Port}`,
          AIRLIFT_STORAGE__BUCKET: "e2e",
          AIRLIFT_STORAGE__REGION: "us-east-1",
          AIRLIFT_STORAGE__ACCESS_KEY_ID: "e2e",
          AIRLIFT_STORAGE__SECRET_ACCESS_KEY: "e2e",
          AIRLIFT_STORAGE__FORCE_PATH_STYLE: "true",
        },
        stdout: log("airlift.log"),
        stderr: log("airlift.log"),
      })
    );

    const deadline = Date.now() + 30_000;
    for (;;) {
      try {
        if ((await fetch(`${inst.base}/healthz`)).ok) break;
      } catch {
        // not listening yet
      }
      if (Date.now() > deadline) throw new Error(`airlift did not become healthy; see ${work}/airlift.log`);
      await Bun.sleep(100);
    }

    // First-run setup: admin user + org, session cookie for admin calls.
    const res = await fetch(`${inst.base}/api/v1/setup`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "admin@example.test",
        username: "admin",
        password: "password123",
        org_slug: ORG,
        org_name: "Acme",
      }),
    });
    if (!res.ok) throw new Error(`setup failed: ${res.status} ${await res.text()}`);
    inst.cookie = res.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");

    const { app } = await inst.api<{ app: { id: string } }>("POST", `/api/v1/orgs/${ORG}/apps`, {
      slug: APP,
      name: "CLI e2e",
    });
    inst.appId = app.id;
    return inst;
  }

  /** Admin-session API call (setup and server-side assertions). */
  async api<T = any>(method: string, apiPath: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}${apiPath}`, {
      method,
      headers: { cookie: this.cookie, ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${apiPath}: ${res.status} ${text}`);
    return (text ? JSON.parse(text) : {}) as T;
  }

  /** Mint a personal access token for the org with the given cap. */
  async token(permission: "read" | "publish" | "admin"): Promise<string> {
    const r = await this.api<{ token: string }>("POST", "/api/v1/tokens", {
      name: `cli-e2e-${permission}`,
      org: ORG,
      permission,
    });
    return r.token;
  }

  async appDetail(): Promise<{
    channels: {
      name: string;
      branch: string;
      auto_release: boolean;
      releases: { runtime_version: string; group_id: string }[];
    }[];
  }> {
    return this.api("GET", `/api/v1/orgs/${ORG}/apps/${APP}`);
  }

  async updates(query = ""): Promise<
    { id: string; branch: string; runtime_version: string; message: string | null; platforms: string[]; group_type: string }[]
  > {
    return (await this.api("GET", `/api/v1/orgs/${ORG}/apps/${APP}/updates${query}`)).updates;
  }

  log(): string {
    try {
      return fs.readFileSync(path.join(this.work, "airlift.log"), "utf8").split("\n").slice(-60).join("\n");
    } catch {
      return "";
    }
  }

  async stop(): Promise<void> {
    for (const p of this.procs) p.kill();
    await Promise.all(this.procs.map((p) => p.exited));
  }
}

/* ───────────────────────── the CLI ───────────────────────── */

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
  /** stdout + stderr, for assertions that do not care which. */
  out: string;
}

/**
 * Run the built CLI with node, as `npx airlift-cli …` would. AIRLIFT_TOKEN
 * from the caller's environment is never inherited: pass `token` (or null
 * to run without one).
 */
export async function cli(
  args: string[],
  opts: { token: string | null; cwd?: string }
): Promise<CliResult> {
  const env: Record<string, string> = { ...(process.env as Record<string, string>), CI: "1", NO_COLOR: "1" };
  delete env.AIRLIFT_TOKEN;
  if (opts.token) env.AIRLIFT_TOKEN = opts.token;
  const proc = Bun.spawn(["node", CLI_JS, ...args], {
    cwd: opts.cwd ?? APP_DIR,
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr, out: `${stdout}\n${stderr}` };
}

/** `Published update group <id>` from publish output. */
export function publishedGroup(r: CliResult): string {
  const m = r.stdout.match(/Published update group ([0-9a-f-]{36})/);
  if (!m) throw new Error(`no group id in publish output:\n${r.out}`);
  return m[1];
}

/* ───────────────────────── the Expo project ───────────────────────── */

/**
 * The real Expo app in e2e-device/app, edited in place (as the device e2e
 * does) and put back afterwards: app.json, marker.js and the files `init`
 * writes (airlift.json, certs/).
 */
export class Fixture {
  private readonly saved = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "airlift-cli-fixture-")));
  private readonly tracked = ["app.json", "marker.js", "airlift.json", "certs"];

  backup(): void {
    for (const name of this.tracked) {
      const src = path.join(APP_DIR, name);
      if (fs.existsSync(src)) fs.cpSync(src, path.join(this.saved, name), { recursive: true });
    }
  }

  restore(): void {
    for (const name of this.tracked) {
      const dest = path.join(APP_DIR, name);
      const kept = path.join(this.saved, name);
      fs.rmSync(dest, { recursive: true, force: true });
      if (fs.existsSync(kept)) fs.cpSync(kept, dest, { recursive: true });
    }
  }

  appJson(): Record<string, any> {
    return JSON.parse(fs.readFileSync(path.join(APP_DIR, "app.json"), "utf8"));
  }

  writeAppJson(json: Record<string, any>): void {
    fs.writeFileSync(path.join(APP_DIR, "app.json"), JSON.stringify(json, null, 2) + "\n");
  }

  /** Change the bundle's content so the next publish is a new update. */
  setMarker(marker: string): void {
    const file = path.join(APP_DIR, "marker.js");
    const src = fs.readFileSync(file, "utf8").replace(/MARKER = '.*'/, `MARKER = '${marker}'`);
    fs.writeFileSync(file, src);
  }

  /**
   * Build the current code once and throw the output away, so Metro's
   * transform cache holds it. Expo/Metro do not produce byte-identical
   * Hermes bundles for a changed file transformed cold vs. from cache, so
   * a test that needs two identical publishes must warm the cache first.
   */
  async warmBuild(platform: "android" | "ios"): Promise<void> {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), "airlift-cli-warm-"));
    const proc = Bun.spawn(["npx", "expo", "export", "--output-dir", out, "--platform", platform], {
      cwd: APP_DIR,
      env: { ...process.env, CI: "1" },
      stdout: "ignore",
      stderr: "pipe",
    });
    const [stderr, code] = await Promise.all([new Response(proc.stderr).text(), proc.exited]);
    fs.rmSync(out, { recursive: true, force: true });
    if (code !== 0) throw new Error(`warm-up expo export failed:\n${stderr}`);
  }

  readText(rel: string): string {
    return fs.readFileSync(path.join(APP_DIR, rel), "utf8");
  }

  exists(rel: string): boolean {
    return fs.existsSync(path.join(APP_DIR, rel));
  }
}

/* ───────────────────────── an expo-updates client ───────────────────────── */

export type Served =
  | { kind: "update"; updateId: string; launchHash: string; launchUrl: string; signatureOk: boolean | null }
  | { kind: "noUpdateAvailable" }
  | { kind: "rollBackToEmbedded" };

interface ClientOpts {
  platform: "ios" | "android";
  runtime: string;
  channel: string;
  clientId?: string;
  /** Ask for a signature with this keyid and verify it with `certPem`. */
  keyid?: string;
  certPem?: string;
}

function clientHeaders(o: ClientOpts): Record<string, string> {
  return {
    "expo-platform": o.platform,
    "expo-runtime-version": o.runtime,
    "expo-channel-name": o.channel,
    "expo-protocol-version": "1",
    accept: "multipart/mixed",
    "eas-client-id": o.clientId ?? "00000000-0000-4000-8000-000000000001",
    ...(o.keyid ? { "expo-expect-signature": `sig, keyid="${o.keyid}", alg="rsa-v1_5-sha256"` } : {}),
  };
}

/** Do what expo-updates does on a check: request the manifest, verify it. */
export async function checkForUpdate(inst: Instance, o: ClientOpts): Promise<Served> {
  const res = await fetch(`${inst.base}/u/${inst.appId}/manifest`, { headers: clientHeaders(o) });
  if (!res.ok) throw new Error(`manifest: HTTP ${res.status} ${await res.text()}`);
  const ctype = res.headers.get("content-type") ?? "";
  const boundary = ctype.match(/boundary=("?)([^";]+)\1/)?.[2];
  if (!boundary) throw new Error(`manifest is not multipart: ${ctype}`);
  const body = Buffer.from(await res.arrayBuffer()).toString("latin1");

  for (const part of body.split(`--${boundary}`).slice(1, -1)) {
    const split = part.indexOf("\r\n\r\n");
    const head = part.slice(0, split);
    const raw = part.slice(split + 4).replace(/\r\n$/, "");
    const name = head.match(/name="([^"]+)"/)?.[1];
    const json = JSON.parse(Buffer.from(raw, "latin1").toString("utf8"));
    if (name === "directive") return { kind: json.type };
    if (name === "manifest") {
      let signatureOk: boolean | null = null;
      if (o.certPem) {
        const sig = head.match(/expo-signature:\s*sig="([^"]+)"/i)?.[1];
        signatureOk = !!sig &&
          createVerify("RSA-SHA256").update(Buffer.from(raw, "latin1")).verify(o.certPem, sig, "base64");
      }
      return {
        kind: "update",
        updateId: json.id,
        launchHash: json.launchAsset.hash,
        launchUrl: json.launchAsset.url,
        signatureOk,
      };
    }
  }
  throw new Error("manifest response had neither a manifest nor a directive part");
}

const bundleCache = new Map<string, string>();

/**
 * Download the served launch bundle (following the presigned redirect),
 * check it against the manifest hash, and return which of `markers` it was
 * built from. This is how the suite tells updates apart: every publish
 * writes a unique marker into marker.js.
 */
export async function servedMarker(
  inst: Instance,
  o: ClientOpts,
  markers: string[]
): Promise<string | "noUpdateAvailable" | "rollBackToEmbedded"> {
  const served = await checkForUpdate(inst, o);
  if (served.kind !== "update") return served.kind;
  let text = bundleCache.get(served.launchHash);
  if (text === undefined) {
    const res = await fetch(served.launchUrl, { headers: clientHeaders(o) });
    if (!res.ok) throw new Error(`launch asset: HTTP ${res.status}`);
    const bytes = Buffer.from(await res.arrayBuffer());
    const hash = createHash("sha256").update(bytes).digest("base64url");
    if (hash !== served.launchHash) throw new Error(`launch asset hash ${hash} != manifest ${served.launchHash}`);
    text = bytes.toString("latin1");
    bundleCache.set(served.launchHash, text);
  }
  const found = markers.filter((m) => text!.includes(m));
  if (found.length !== 1) throw new Error(`served bundle matches markers ${JSON.stringify(found)}`);
  return found[0];
}
