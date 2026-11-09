import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ApiError, AppDetail, PublishResult, getJson, postForm } from "../api";
import { CommonOptions, resolveContext } from "../config";
import {
  gitInfo,
  resolveExpoConfig,
  resolveRuntimeVersion,
  runExpoExport,
  zipDirectory,
} from "../expo";
import { renderTable } from "../util";

export interface PublishOptions extends CommonOptions {
  branch: string;
  channel?: string;
  message?: string;
  platform: string;
  runtimeVersion?: string;
  rollout?: string;
  /** commander sets false for --no-source-maps. */
  sourceMaps?: boolean;
}

export async function publishCommand(opts: PublishOptions): Promise<void> {
  const platform = opts.platform as "all" | "ios" | "android";
  if (!["all", "ios", "android"].includes(platform)) {
    throw new Error(`Invalid --platform "${opts.platform}"; expected all, ios, or android.`);
  }

  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };

  // Resolve the app id (cached in airlift.json unless flags overrode org/app/server).
  let appId = ctx.appId;
  if (!appId) {
    const detail = await getJson<AppDetail>(
      client,
      `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}`
    );
    appId = detail.app.id;
  }

  // Resolve the public Expo config.
  console.log("Resolving Expo config (npx expo config --json --type public)...");
  const expoConfig = resolveExpoConfig(ctx.projectDir);

  let runtimeVersion = opts.runtimeVersion ?? null;
  if (!runtimeVersion) {
    const platforms: ("ios" | "android")[] = platform === "all" ? ["ios", "android"] : [platform];
    const resolved = platforms.map((p) => resolveRuntimeVersion(expoConfig, p));
    if (resolved.length === 2 && resolved[0] && resolved[1] && resolved[0] !== resolved[1]) {
      throw new Error(
        `iOS and Android resolve to different runtime versions (${resolved[0]} vs ${resolved[1]}). ` +
          "Publish each platform separately with --platform ios / --platform android."
      );
    }
    runtimeVersion = resolved.every((r) => r === resolved[0]) ? (resolved[0] ?? null) : null;
  }
  if (!runtimeVersion) {
    throw new Error(
      "Could not resolve the runtime version from your Expo config " +
        "(unsupported or missing runtimeVersion policy). Pass --runtime-version <rv>."
    );
  }
  console.log(`Runtime version: ${runtimeVersion}`);

  // Export the bundle.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "airlift-export-"));
  try {
    console.log(`Exporting bundle (npx expo export --output-dir ${tmpDir})...`);
    runExpoExport(ctx.projectDir, tmpDir, platform, opts.sourceMaps !== false);

    console.log("Zipping export output...");
    const archive = await zipDirectory(tmpDir);
    console.log(`Archive size: ${(archive.length / 1024 / 1024).toFixed(2)} MB`);

    const git = gitInfo(ctx.projectDir);

    const form = new FormData();
    form.append("branch", opts.branch);
    form.append("runtime_version", runtimeVersion);
    if (opts.message) form.append("message", opts.message);
    if (git.branch) form.append("git_branch", git.branch);
    if (git.commit) form.append("git_commit", git.commit);
    if (opts.rollout) form.append("rollout_percent", opts.rollout);
    form.append("expo_config", JSON.stringify(expoConfig));
    form.append(
      "archive",
      new Blob([new Uint8Array(archive)], { type: "application/zip" }),
      "archive.zip"
    );

    console.log(`Uploading to ${ctx.server} (branch "${opts.branch}")...`);
    let result: PublishResult;
    try {
      result = await postForm<PublishResult>(client, `/api/v1/apps/${appId}/updates`, form);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        throw new Error(
          `Duplicate update: an update with identical contents is already at the head of branch "${opts.branch}". ` +
            "Nothing was published. Make a change to your app (or publish to a different branch) and try again."
        );
      }
      throw err;
    }

    console.log("");
    console.log(`Published update group ${result.group_id}`);
    console.log(`  branch:          ${result.branch}`);
    console.log(`  runtime version: ${result.runtime_version}`);
    console.log(`  platforms:       ${result.platforms.join(", ")}`);

    if (result.channels.length > 0) {
      console.log("");
      console.log(
        renderTable(
          ["CHANNEL", "STATUS"],
          result.channels.map((c) => [
            c.channel,
            c.status === "rolling_out" ? `rolling out (${c.percent}%)` : c.status,
          ])
        )
      );
    } else {
      console.log("\nNo channels track this branch yet.");
    }

    if (opts.channel) {
      const target = result.channels.find((c) => c.channel === opts.channel);
      if (!target) {
        console.log(
          `\nNote: channel "${opts.channel}" does not track branch "${opts.branch}", so this publish did not reach it.`
        );
      } else if (target.status === "pending") {
        console.log(
          `\nChannel "${opts.channel}" is pending manual release. To promote this update, run:\n` +
            `  airlift promote --channel ${opts.channel} --group ${result.group_id}`
        );
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
