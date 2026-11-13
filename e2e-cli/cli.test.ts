/**
 * Every airlift CLI command, end to end, against a real airlift instance.
 *
 * The tests run in order and share one server: they walk the life of an app
 * the way an operator would (link it, publish, gate, roll back, roll out,
 * split, republish, rotate keys, diagnose). Each step checks three things:
 * what the CLI printed and exited with, what the server recorded, and what
 * an expo-updates client is actually served (signature verified, bundle
 * hash checked, and the bundle's content identified by its marker).
 *
 * Run with e2e-cli/run.sh (builds the server, the S3 stub and the CLI).
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  APP,
  APP_DIR,
  ORG,
  Fixture,
  Instance,
  checkForUpdate,
  cli,
  publishedGroup,
  servedMarker,
} from "./harness";

const RUNTIME = "1.0.0";
const PUBLISH_TIMEOUT = 240_000;

let inst: Instance;
const fixture = new Fixture();
let publishToken = "";
let readToken = "";
let adminToken = "";

/** Every marker published so far; a served bundle must match exactly one. */
const markers: string[] = [];
let markerSeq = 0;
function nextMarker(): string {
  // Zero-padded and suffixed, so no marker is a substring of another.
  const m = `cli-e2e-${String(++markerSeq).padStart(2, "0")}-${Math.random().toString(36).slice(2, 8)}`;
  markers.push(m);
  fixture.setMarker(m);
  return m;
}

function cert(rel = "certs/certificate.pem"): string {
  return fixture.readText(rel);
}

/** What an Android device on `channel` is served (by marker). */
function android(channel: string, clientId?: string, runtime = RUNTIME) {
  return servedMarker(inst, { platform: "android", runtime, channel, clientId }, markers);
}

/** Stable, distinct device ids for rollout / split sampling. */
const DEVICES = Array.from({ length: 120 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`);

async function sample(channel: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const id of DEVICES) out.set(id, await android(channel, id));
  return out;
}

function count(served: Map<string, string>, marker: string): number {
  return [...served.values()].filter((m) => m === marker).length;
}

const group: Record<string, string> = {};
const marker: Record<string, string> = {};

beforeAll(async () => {
  fixture.backup();
  // Start from an unlinked project, and list web as a platform like many
  // real apps do: `publish` must still export iOS and Android only.
  for (const rel of ["airlift.json", "certs"]) {
    fs.rmSync(path.join(APP_DIR, rel), { recursive: true, force: true });
  }
  const appJson = fixture.appJson();
  appJson.expo.platforms = ["ios", "android", "web"];
  fixture.writeAppJson(appJson);

  inst = await Instance.start();
  publishToken = await inst.token("publish");
  readToken = await inst.token("read");
  adminToken = await inst.token("admin");
}, 60_000);

afterAll(async () => {
  fixture.restore();
  await inst?.stop();
});

function linkArgs(): string[] {
  return ["--server", inst.base, "--org", ORG, "--app", APP];
}

/** On failure, show the CLI output and the server log tail. */
function ok(r: { code: number; out: string }): void {
  if (r.code !== 0) console.error(`CLI failed:\n${r.out}\n---- airlift.log ----\n${inst.log()}`);
  expect(r.code).toBe(0);
}

describe("init", () => {
  test("refuses to run without a token", async () => {
    const r = await cli(["init", ...linkArgs()], { token: null });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("No access token");
    expect(fixture.exists("airlift.json")).toBe(false);
  });

  test("links the project: airlift.json, certificate, expo.updates", async () => {
    const r = await cli(["init", ...linkArgs()], { token: publishToken });
    ok(r);
    expect(r.stdout).toContain(`Found app "CLI e2e" (${inst.appId})`);

    expect(JSON.parse(fixture.readText("airlift.json"))).toEqual({
      server: inst.base,
      org: ORG,
      app: APP,
      appId: inst.appId,
    });

    const { keys } = await inst.api<{ keys: { keyid: string; certificate_pem: string }[] }>(
      "GET",
      `/api/v1/orgs/${ORG}/apps/${APP}/signing-keys`
    );
    const main = keys.find((k) => k.keyid === "main")!;
    expect(cert().trim()).toBe(main.certificate_pem.trim());

    const updates = fixture.appJson().expo.updates;
    expect(updates.url).toBe(`${inst.base}/u/${inst.appId}/manifest`);
    expect(updates.enabled).toBe(true);
    expect(updates.codeSigningCertificate).toBe("./certs/certificate.pem");
    expect(updates.codeSigningMetadata).toEqual({ keyid: "main", alg: "rsa-v1_5-sha256" });
    expect(updates.requestHeaders["expo-channel-name"]).toBe("production");
    // Existing settings and the runtime version survive.
    expect(updates.checkAutomatically).toBe("NEVER");
    expect(fixture.appJson().expo.runtimeVersion).toBe(RUNTIME);
  });

  test("re-running keeps a channel header the project already chose", async () => {
    const appJson = fixture.appJson();
    appJson.expo.updates.requestHeaders["expo-channel-name"] = "staging";
    fixture.writeAppJson(appJson);
    ok(await cli(["init", ...linkArgs()], { token: publishToken }));
    expect(fixture.appJson().expo.updates.requestHeaders["expo-channel-name"]).toBe("staging");

    appJson.expo.updates.requestHeaders["expo-channel-name"] = "production";
    fixture.writeAppJson(appJson);
  });
});

describe("doctor (before the first publish)", () => {
  test("flags the missing channel and exits non-zero", async () => {
    const r = await cli(["doctor"], { token: publishToken });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("✓ updates.url points at this app.");
    expect(r.stdout).toContain('✓ Code signing uses key "main"');
    expect(r.stdout).toContain('✗ Channel "production" does not exist on the server.');
  }, PUBLISH_TIMEOUT);
});

describe("publish", () => {
  test("--platform all (default) exports iOS and Android only, even with web configured", async () => {
    marker.first = nextMarker();
    const r = await cli(["publish", "--branch", "production", "--message", "first"], { token: publishToken });
    ok(r);
    group.first = publishedGroup(r);
    expect(r.stdout).toMatch(/platforms:\s+(android, ios|ios, android)/);
    expect(r.stdout).toMatch(/production\s+released/);

    const [head] = await inst.updates();
    expect(head.id).toBe(group.first);
    expect([...head.platforms].sort()).toEqual(["android", "ios"]);
    expect(head.message).toBe("first");
    expect(head.runtime_version).toBe(RUNTIME);

    // Both platforms are served the new bundle, signed with the build's key.
    for (const platform of ["android", "ios"] as const) {
      const served = await checkForUpdate(inst, {
        platform,
        runtime: RUNTIME,
        channel: "production",
        keyid: "main",
        certPem: cert(),
      });
      expect(served.kind).toBe("update");
      expect(served.kind === "update" && served.signatureOk).toBe(true);
      expect(await servedMarker(inst, { platform, runtime: RUNTIME, channel: "production" }, markers)).toBe(
        marker.first
      );
    }
  }, PUBLISH_TIMEOUT);

  test("refuses an identical re-publish with a clear message", async () => {
    const before = (await inst.updates()).length;
    const r = await cli(["publish", "--branch", "production"], { token: publishToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("Duplicate update");
    expect((await inst.updates()).length).toBe(before);
  }, PUBLISH_TIMEOUT);

  test("--platform android --runtime-version --no-source-maps", async () => {
    marker.rv2 = nextMarker();
    const r = await cli(
      [
        "publish",
        "--branch",
        "production",
        "--platform",
        "android",
        "--runtime-version",
        "2.0.0",
        "--no-source-maps",
        "--message",
        "runtime two",
      ],
      { token: publishToken }
    );
    ok(r);
    group.rv2 = publishedGroup(r);
    const [head] = await inst.updates();
    expect(head.id).toBe(group.rv2);
    expect(head.platforms).toEqual(["android"]);
    expect(head.runtime_version).toBe("2.0.0");

    expect(await android("production", undefined, "2.0.0")).toBe(marker.rv2);
    // Other runtimes and platforms are untouched.
    expect(await android("production")).toBe(marker.first);
    expect(
      await servedMarker(inst, { platform: "ios", runtime: "2.0.0", channel: "production" }, markers)
    ).toBe("noUpdateAvailable");
  }, PUBLISH_TIMEOUT);

  test("--channel on a channel that does not track the branch says so", async () => {
    marker.side = nextMarker();
    const r = await cli(
      ["publish", "--branch", "side", "--channel", "production", "--platform", "android"],
      { token: publishToken }
    );
    ok(r);
    group.side = publishedGroup(r);
    expect(r.stdout).toContain('channel "production" does not track branch "side"');
    expect(await android("production")).toBe(marker.first);
  }, PUBLISH_TIMEOUT);

  test("rejects an unknown --platform", async () => {
    const r = await cli(["publish", "--branch", "production", "--platform", "web"], { token: publishToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('Invalid --platform "web"');
  });
});

describe("list", () => {
  test("shows published update groups", async () => {
    const r = await cli(["list"], { token: readToken });
    ok(r);
    for (const id of [group.first, group.rv2, group.side]) expect(r.stdout).toContain(id.slice(0, 8));
    expect(r.stdout).toContain("runtime two");
  });

  test("--branch and --limit filter", async () => {
    const side = await cli(["list", "--branch", "side"], { token: readToken });
    ok(side);
    expect(side.stdout).toContain(group.side.slice(0, 8));
    expect(side.stdout).not.toContain(group.first.slice(0, 8));

    const one = await cli(["list", "--limit", "1"], { token: readToken });
    ok(one);
    expect(one.stdout.trim().split("\n")).toHaveLength(3); // header, rule, one row
  });

  test("bad --limit and unknown branch fail clearly", async () => {
    const bad = await cli(["list", "--limit", "0"], { token: readToken });
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain('Invalid --limit "0"');

    const missing = await cli(["list", "--branch", "no-such-branch"], { token: readToken });
    expect(missing.code).toBe(1);
  });
});

describe("rollback", () => {
  test("repoints the channel to its previous release", async () => {
    marker.second = nextMarker();
    const pub = await cli(["publish", "--branch", "production", "--platform", "android"], { token: publishToken });
    ok(pub);
    group.second = publishedGroup(pub);
    expect(await android("production")).toBe(marker.second);

    const r = await cli(["rollback", "--channel", "production", "--runtime-version", RUNTIME], {
      token: publishToken,
    });
    ok(r);
    // The server re-ships the previous release under a fresh identity, so
    // devices already running the newer update really switch back: the
    // printed group is a new copy whose bundle is the first publish.
    const m = r.stdout.match(/\(runtime 1\.0\.0\) to update group ([0-9a-f-]{36})\./);
    expect(m).not.toBeNull();
    expect([group.first, group.second]).not.toContain(m![1]);
    expect((await inst.updates())[0].id).toBe(m![1]);
    expect(await android("production")).toBe(marker.first);
  }, PUBLISH_TIMEOUT);
});

describe("gated channel + promote", () => {
  test("a publish waits as pending until promoted", async () => {
    await inst.api("POST", `/api/v1/orgs/${ORG}/apps/${APP}/channels`, {
      name: "store",
      branch: "store",
      auto_release: false,
    });

    marker.store = nextMarker();
    const r = await cli(
      ["publish", "--branch", "store", "--channel", "store", "--platform", "android"],
      { token: publishToken }
    );
    ok(r);
    group.store = publishedGroup(r);
    expect(r.stdout).toMatch(/store\s+pending/);
    expect(r.stdout).toContain(`airlift promote --channel store --group ${group.store}`);
    expect(await android("store")).toBe("noUpdateAvailable");

    const denied = await cli(["promote", "--channel", "store", "--group", group.store], { token: readToken });
    expect(denied.code).toBe(1);
    expect(denied.stderr).toContain("check your token");
    expect(await android("store")).toBe("noUpdateAvailable");

    const p = await cli(["promote", "--channel", "store", "--group", group.store], { token: publishToken });
    ok(p);
    expect(p.stdout).toContain(`Promoted update group ${group.store} to channel "store".`);
    expect(await android("store")).toBe(marker.store);
  }, PUBLISH_TIMEOUT);
});

describe("rollout", () => {
  test("publish --rollout starts at a share; rollout grows and completes it", async () => {
    marker.ramp = nextMarker();
    const r = await cli(
      ["publish", "--branch", "production", "--platform", "android", "--rollout", "25"],
      { token: publishToken }
    );
    ok(r);
    group.ramp = publishedGroup(r);
    expect(r.stdout).toMatch(/production\s+rolling out \(25%\)/);

    const at25 = await sample("production");
    const in25 = [...at25].filter(([, m]) => m === marker.ramp).map(([id]) => id);
    expect(in25.length).toBeGreaterThan(0);
    expect(in25.length).toBeLessThan(DEVICES.length);
    expect(count(at25, marker.ramp) + count(at25, marker.first)).toBe(DEVICES.length);

    const grow = await cli(
      ["rollout", "--channel", "production", "--runtime-version", RUNTIME, "--percent", "60"],
      { token: publishToken }
    );
    ok(grow);
    expect(grow.stdout).toContain(`(runtime ${RUNTIME}) now at 60%.`);
    const at60 = await sample("production");
    expect(count(at60, marker.ramp)).toBeGreaterThan(in25.length);
    // Devices already in the rollout stay in as it grows.
    for (const id of in25) expect(at60.get(id)).toBe(marker.ramp);

    const done = await cli(
      ["rollout", "--channel", "production", "--runtime-version", RUNTIME, "--percent", "100"],
      { token: publishToken }
    );
    ok(done);
    expect(done.stdout).toContain("completed: every device gets it.");
    expect(count(await sample("production"), marker.ramp)).toBe(DEVICES.length);
  }, PUBLISH_TIMEOUT);

  test("rollout --group starts a rollout of a pending update", async () => {
    marker.storeRamp = nextMarker();
    const pub = await cli(["publish", "--branch", "store", "--platform", "android"], { token: publishToken });
    ok(pub);
    group.storeRamp = publishedGroup(pub);
    expect(await android("store")).toBe(marker.store);

    const r = await cli(
      ["rollout", "--channel", "store", "--group", group.storeRamp, "--percent", "30"],
      { token: publishToken }
    );
    ok(r);
    expect(r.stdout).toContain(`Rolling out update group ${group.storeRamp} (runtime ${RUNTIME}) to 30%`);
    expect(r.stdout).toContain(`airlift rollout --channel store --runtime-version ${RUNTIME} --percent <n>`);
    const served = await sample("store");
    expect(count(served, marker.storeRamp)).toBeGreaterThan(0);
    expect(count(served, marker.store)).toBeGreaterThan(0);

    ok(
      await cli(["rollout", "--channel", "store", "--runtime-version", RUNTIME, "--percent", "100"], {
        token: publishToken,
      })
    );
    expect(count(await sample("store"), marker.storeRamp)).toBe(DEVICES.length);
  }, PUBLISH_TIMEOUT);

  test("invalid arguments fail clearly", async () => {
    const zero = await cli(["rollout", "--channel", "production", "--group", group.first, "--percent", "0"], {
      token: publishToken,
    });
    expect(zero.code).toBe(1);
    expect(zero.stderr).toContain("--percent must be a number in (0, 100]");

    const neither = await cli(["rollout", "--channel", "production", "--percent", "10"], { token: publishToken });
    expect(neither.code).toBe(1);
    expect(neither.stderr).toContain("Pass --group <id> to start a rollout");
  });
});

describe("split", () => {
  test("serves another branch to a share of devices, then ends", async () => {
    marker.exp = nextMarker();
    ok(await cli(["publish", "--branch", "exp", "--platform", "android"], { token: publishToken }));

    // Changing channels needs more than a publish token.
    const denied = await cli(["split", "--channel", "production", "--branch", "exp", "--percent", "50"], {
      token: publishToken,
    });
    expect(denied.code).toBe(1);
    expect(denied.stderr).toContain("check your token");

    const r = await cli(["split", "--channel", "production", "--branch", "exp", "--percent", "50"], {
      token: adminToken,
    });
    ok(r);
    expect(r.stdout).toContain('50% of devices on "production" now get branch "exp"');
    const split = await sample("production");
    expect(count(split, marker.exp)).toBeGreaterThan(0);
    expect(count(split, marker.ramp)).toBeGreaterThan(0);
    expect(count(split, marker.exp) + count(split, marker.ramp)).toBe(DEVICES.length);

    const off = await cli(["split", "--channel", "production", "--off"], { token: adminToken });
    ok(off);
    expect(off.stdout).toContain('Ended the A/B split on "production"');
    expect(count(await sample("production"), marker.ramp)).toBe(DEVICES.length);
  }, PUBLISH_TIMEOUT);

  test("missing arguments fail clearly", async () => {
    const r = await cli(["split", "--channel", "production"], { token: adminToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("Pass --branch <name> --percent <n> to split, or --off");
  });
});

describe("republish", () => {
  test("re-ships an old group as a new update on its branch", async () => {
    const r = await cli(["republish", "--group", group.first], { token: publishToken });
    ok(r);
    const m = r.stdout.match(/as update group ([0-9a-f-]{36}) on branch "production"/);
    expect(m).not.toBeNull();
    expect(m![1]).not.toBe(group.first);
    expect(r.stdout).toMatch(/production: released/);
    expect((await inst.updates())[0].id).toBe(m![1]);
    expect(count(await sample("production"), marker.first)).toBe(DEVICES.length);
  });

  test("--channel releases the copy to that channel", async () => {
    const r = await cli(["republish", "--group", group.store, "--channel", "store"], { token: publishToken });
    ok(r);
    expect(r.stdout).toMatch(/store: released/);
    expect(await android("store")).toBe(marker.store);
  });
});

describe("generate-certs (key rotation)", () => {
  test("needs a token that may manage keys", async () => {
    const r = await cli(["generate-certs", "--keyid", "k2"], { token: publishToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("check your token");
  });

  test("creates a server key, saves its certificate, points app.json at it", async () => {
    const r = await cli(["generate-certs", "--keyid", "k2"], { token: adminToken });
    ok(r);
    expect(r.stdout).toContain('New signing key "k2" created; wrote ./certs/certificate-k2.pem.');
    const updates = fixture.appJson().expo.updates;
    expect(updates.codeSigningCertificate).toBe("./certs/certificate-k2.pem");
    expect(updates.codeSigningMetadata).toEqual({ keyid: "k2", alg: "rsa-v1_5-sha256" });

    // New builds verify with k2; builds in the field still verify with main.
    for (const [keyid, pem] of [
      ["k2", cert("certs/certificate-k2.pem")],
      ["main", cert("certs/certificate.pem")],
    ] as const) {
      const served = await checkForUpdate(inst, {
        platform: "android",
        runtime: RUNTIME,
        channel: "production",
        keyid,
        certPem: pem,
      });
      expect(served.kind === "update" && served.signatureOk).toBe(true);
    }
  });
});

describe("doctor (linked and published)", () => {
  test("passes on a correctly configured project", async () => {
    const r = await cli(["doctor"], { token: publishToken });
    ok(r);
    expect(r.stdout).toContain('✓ Code signing uses key "k2" (./certs/certificate-k2.pem).');
    expect(r.stdout).toContain('✓ Channel "production" exists (tracks production).');
    expect(r.stdout).toContain(`✓ android: runtime ${RUNTIME} has a release on "production".`);
    expect(r.stdout).toContain("0 problem(s)");
  }, PUBLISH_TIMEOUT);

  test("catches a keyid that does not match the certificate", async () => {
    const appJson = fixture.appJson();
    appJson.expo.updates.codeSigningMetadata.keyid = "main";
    fixture.writeAppJson(appJson);
    const r = await cli(["doctor"], { token: publishToken });
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('belongs to key "k2"');
    appJson.expo.updates.codeSigningMetadata.keyid = "k2";
    fixture.writeAppJson(appJson);
  }, PUBLISH_TIMEOUT);
});

describe("init --keyid", () => {
  test("downloads that key's certificate", async () => {
    const r = await cli(["init", ...linkArgs(), "--keyid", "k2"], { token: publishToken });
    ok(r);
    expect(cert().trim()).toBe(cert("certs/certificate-k2.pem").trim());
    const updates = fixture.appJson().expo.updates;
    expect(updates.codeSigningCertificate).toBe("./certs/certificate.pem");
    expect(updates.codeSigningMetadata.keyid).toBe("k2");
  });
});

describe("flags, tokens and connection errors", () => {
  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "airlift-cli-nowhere-"));

  test("without airlift.json the flags are required", async () => {
    const r = await cli(["list"], { token: readToken, cwd: elsewhere });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("Missing --server, --org, --app");
  });

  test("--server/--org/--app/--token work without airlift.json", async () => {
    const r = await cli(["list", ...linkArgs(), "--token", readToken, "--limit", "1"], {
      token: null,
      cwd: elsewhere,
    });
    ok(r);
    const [newest] = await inst.updates();
    expect(r.stdout).toContain(newest.id.slice(0, 8));
  });

  test("a wrong token is reported as such", async () => {
    const r = await cli(["list"], { token: "alt_not_a_real_token" });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("check your token");
  });

  test("a read-only token cannot publish", async () => {
    nextMarker();
    const r = await cli(["publish", "--branch", "production", "--platform", "android"], { token: readToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("check your token");
  }, PUBLISH_TIMEOUT);

  test("an unreachable server is reported as such", async () => {
    const r = await cli(["list", "--server", "http://127.0.0.1:1"], { token: readToken });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("Could not reach server at http://127.0.0.1:1");
  });
});
