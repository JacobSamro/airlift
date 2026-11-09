import * as fs from "node:fs";
import * as path from "node:path";
import { AppDetail, getJson } from "../api";
import { CommonOptions, resolveContext } from "../config";
import { resolveExpoConfig, resolveRuntimeVersion } from "../expo";

type Level = "ok" | "warn" | "fail";

interface Check {
  level: Level;
  message: string;
}

/**
 * Check this project's Expo config against the airlift server: update URL,
 * code signing (certificate matches a server key, keyid, alg), channel,
 * runtime version and whether that channel has a release for it.
 * Exits non-zero if anything would stop devices from getting updates.
 */
export async function doctorCommand(opts: CommonOptions): Promise<void> {
  const checks: Check[] = [];
  const ok = (message: string) => checks.push({ level: "ok", message });
  const warn = (message: string) => checks.push({ level: "warn", message });
  const fail = (message: string) => checks.push({ level: "fail", message });

  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const appBase = `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}`;

  let detail: AppDetail | null = null;
  try {
    detail = await getJson<AppDetail>(client, appBase);
    ok(`Server reachable; app "${detail.app.name}" found (${detail.app.id}).`);
  } catch (err) {
    fail(`Cannot load app ${ctx.org}/${ctx.app} from ${ctx.server}: ${(err as Error).message}`);
  }

  let config: Record<string, any> | null = null;
  try {
    config = resolveExpoConfig(ctx.projectDir) as Record<string, any>;
    ok("Expo config resolved.");
  } catch (err) {
    const appJson = path.join(ctx.projectDir, "app.json");
    if (fs.existsSync(appJson)) {
      config = (JSON.parse(fs.readFileSync(appJson, "utf8")) as Record<string, any>).expo ?? {};
      warn(`npx expo config failed (${(err as Error).message.split("\n")[0]}); checked app.json instead.`);
    } else {
      fail(`Cannot resolve the Expo config: ${(err as Error).message.split("\n")[0]}`);
    }
  }

  if (config && detail) {
    const updates = { ...((config.updates ?? {}) as Record<string, any>) };
    // The public config strips the code-signing fields; read them from the
    // static app.json when it has them.
    const appJson = path.join(ctx.projectDir, "app.json");
    if (fs.existsSync(appJson)) {
      const raw = (JSON.parse(fs.readFileSync(appJson, "utf8")) as Record<string, any>).expo?.updates;
      updates.codeSigningCertificate ??= raw?.codeSigningCertificate;
      updates.codeSigningMetadata ??= raw?.codeSigningMetadata;
    }
    const expectedUrl = `${ctx.server}/u/${detail.app.id}/manifest`;
    if (updates.url === expectedUrl) ok(`updates.url points at this app.`);
    else fail(`updates.url is ${JSON.stringify(updates.url)}; expected ${expectedUrl}.`);

    if (updates.enabled === false) fail("updates.enabled is false: devices never check for updates.");

    // Code signing: the embedded certificate must be one of the app's keys,
    // and codeSigningMetadata.keyid must name that same key.
    type Key = { keyid: string; certificate_pem: string };
    let keys: Key[] = [];
    try {
      keys = (await getJson<{ keys: Key[] }>(client, `${appBase}/signing-keys`)).keys;
    } catch (err) {
      warn(`Could not list signing keys: ${(err as Error).message}`);
    }
    const certPath = updates.codeSigningCertificate as string | undefined;
    const meta = (updates.codeSigningMetadata ?? {}) as { keyid?: string; alg?: string };
    if (!certPath) {
      warn("No updates.codeSigningCertificate: updates are not signature-checked on device.");
    } else {
      const abs = path.resolve(ctx.projectDir, certPath);
      if (!fs.existsSync(abs)) {
        fail(`Certificate file ${certPath} does not exist.`);
      } else {
        const pem = fs.readFileSync(abs, "utf8").trim();
        const match = keys.find((k) => k.certificate_pem.trim() === pem);
        if (!match) fail(`${certPath} is not one of this app's signing certificates.`);
        else if ((meta.keyid ?? "main") !== match.keyid)
          fail(
            `codeSigningMetadata.keyid is "${meta.keyid ?? "main"}" but ${certPath} belongs to key "${match.keyid}".`
          );
        else ok(`Code signing uses key "${match.keyid}" (${certPath}).`);
      }
      if (meta.alg && meta.alg !== "rsa-v1_5-sha256")
        fail(`codeSigningMetadata.alg is "${meta.alg}"; airlift signs with rsa-v1_5-sha256.`);
    }

    const channel = (updates.requestHeaders ?? {})["expo-channel-name"] as string | undefined;
    const serverChannel = channel
      ? detail.channels.find((c) => c.name.toLowerCase() === channel.toLowerCase())
      : undefined;
    if (!channel) fail('No updates.requestHeaders["expo-channel-name"]: the server can\'t pick a channel.');
    else if (!serverChannel) fail(`Channel "${channel}" does not exist on the server.`);
    else ok(`Channel "${channel}" exists${serverChannel.branch ? ` (tracks ${serverChannel.branch})` : ""}.`);

    for (const platform of ["ios", "android"] as const) {
      const rv = resolveRuntimeVersion(config, platform);
      if (!rv) {
        warn(`${platform}: runtime version can't be resolved here (fingerprint/nativeVersion policy?).`);
        continue;
      }
      const released = serverChannel?.releases.some((r) => r.runtime_version === rv);
      if (serverChannel && !released)
        warn(`${platform}: runtime ${rv} has no release on "${channel}" yet; devices get no update.`);
      else if (serverChannel) ok(`${platform}: runtime ${rv} has a release on "${channel}".`);
    }
  }

  const pkgPath = path.join(ctx.projectDir, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as Record<string, any>;
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    if (deps["expo-updates"]) ok(`expo-updates ${deps["expo-updates"]} installed.`);
    else fail("expo-updates is not a dependency (npx expo install expo-updates).");
  }

  const icon: Record<Level, string> = { ok: "✓", warn: "!", fail: "✗" };
  for (const c of checks) console.log(`${icon[c.level]} ${c.message}`);
  const failures = checks.filter((c) => c.level === "fail").length;
  const warnings = checks.filter((c) => c.level === "warn").length;
  console.log(`\n${failures} problem(s), ${warnings} warning(s).`);
  if (failures > 0) process.exitCode = 1;
}
