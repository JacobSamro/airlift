import * as fs from "node:fs";
import * as path from "node:path";
import { AppDetail, getJson, getText, normalizeServer } from "../api";
import { writeConfig } from "../config";

export interface InitOptions {
  server: string;
  org: string;
  app: string;
  token?: string;
}

interface ExpoUpdatesConfig {
  url: string;
  enabled: boolean;
  codeSigningCertificate: string;
  codeSigningMetadata: { keyid: string; alg: string };
  requestHeaders: Record<string, string>;
}

function desiredUpdates(updateUrl: string): ExpoUpdatesConfig {
  return {
    url: updateUrl,
    enabled: true,
    codeSigningCertificate: "./certs/certificate.pem",
    codeSigningMetadata: { keyid: "main", alg: "rsa-v1_5-sha256" },
    requestHeaders: { "expo-channel-name": "production" },
  };
}

export async function initCommand(opts: InitOptions): Promise<void> {
  const token = opts.token ?? process.env.AIRLIFT_TOKEN;
  if (!token) {
    throw new Error(
      "No access token. Set the AIRLIFT_TOKEN environment variable or pass --token <pat>."
    );
  }
  const server = normalizeServer(opts.server);
  const client = { server, token };

  // Verify the app exists and grab its id.
  const detail = await getJson<AppDetail>(
    client,
    `/api/v1/orgs/${encodeURIComponent(opts.org)}/apps/${encodeURIComponent(opts.app)}`
  );
  const appId = detail.app.id;
  console.log(`Found app "${detail.app.name}" (${appId}).`);

  const projectDir = process.cwd();

  // airlift.json
  const configFile = writeConfig(projectDir, {
    server,
    org: opts.org,
    app: opts.app,
    appId,
  });
  console.log(`Wrote ${path.relative(projectDir, configFile) || configFile}.`);

  // Certificate
  const pem = await getText(
    client,
    `/api/v1/orgs/${encodeURIComponent(opts.org)}/apps/${encodeURIComponent(opts.app)}/certificate`
  );
  const certDir = path.join(projectDir, "certs");
  fs.mkdirSync(certDir, { recursive: true });
  const certFile = path.join(certDir, "certificate.pem");
  fs.writeFileSync(certFile, pem);
  console.log("Wrote certs/certificate.pem.");

  // Expo config
  const updateUrl = `${server}/u/${appId}/manifest`;
  const appJsonPath = path.join(projectDir, "app.json");
  if (fs.existsSync(appJsonPath)) {
    patchAppJson(appJsonPath, updateUrl);
    console.log("Updated app.json (expo.updates and expo.runtimeVersion).");
  } else {
    const dynamicConfig = ["app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs"]
      .map((f) => path.join(projectDir, f))
      .find((f) => fs.existsSync(f));
    if (dynamicConfig) {
      console.log(
        `\nYou use a dynamic Expo config (${path.basename(dynamicConfig)}), which airlift will not edit.`
      );
      console.log("Merge the following into your exported config manually:\n");
      console.log(
        JSON.stringify(
          {
            updates: desiredUpdates(updateUrl),
            runtimeVersion: { policy: "appVersion" },
          },
          null,
          2
        )
      );
    } else {
      console.log(
        "\nNo app.json or app.config.js/ts found; add this to your Expo config manually:\n"
      );
      console.log(
        JSON.stringify(
          {
            updates: desiredUpdates(updateUrl),
            runtimeVersion: { policy: "appVersion" },
          },
          null,
          2
        )
      );
    }
  }

  console.log(
    "\nReminder: changing updates.url, code signing, or runtimeVersion requires a NEW NATIVE BUILD"
  );
  console.log("of your app before OTA updates from this server will be picked up.");
}

function patchAppJson(appJsonPath: string, updateUrl: string): void {
  let root: Record<string, unknown>;
  try {
    root = JSON.parse(fs.readFileSync(appJsonPath, "utf8")) as Record<string, unknown>;
  } catch {
    throw new Error(`${appJsonPath} is not valid JSON; fix it and re-run init.`);
  }

  // Standard shape is { "expo": { ... } }; create the key if missing.
  if (typeof root.expo !== "object" || root.expo === null) {
    root.expo = {};
  }
  const expo = root.expo as Record<string, unknown>;

  const existingUpdates =
    typeof expo.updates === "object" && expo.updates !== null
      ? (expo.updates as Record<string, unknown>)
      : {};
  const desired = desiredUpdates(updateUrl);
  const existingHeaders =
    typeof existingUpdates.requestHeaders === "object" && existingUpdates.requestHeaders !== null
      ? (existingUpdates.requestHeaders as Record<string, unknown>)
      : {};
  expo.updates = {
    ...existingUpdates,
    url: desired.url,
    enabled: desired.enabled,
    codeSigningCertificate: desired.codeSigningCertificate,
    codeSigningMetadata: desired.codeSigningMetadata,
    requestHeaders: { ...existingHeaders, ...desired.requestHeaders },
  };

  if (expo.runtimeVersion === undefined) {
    expo.runtimeVersion = { policy: "appVersion" };
  }

  fs.writeFileSync(appJsonPath, JSON.stringify(root, null, 2) + "\n");
}
