import { postJson, sendJson } from "../api";
import { CommonOptions, resolveContext } from "../config";

function channelPath(org: string, app: string, channel: string): string {
  return (
    `/api/v1/orgs/${encodeURIComponent(org)}/apps/${encodeURIComponent(app)}` +
    `/channels/${encodeURIComponent(channel)}`
  );
}

function parsePercent(raw: string, max: number): number {
  const p = Number(raw);
  if (!Number.isFinite(p) || p <= 0 || p > max) {
    throw new Error(`--percent must be a number in (0, ${max}].`);
  }
  return p;
}

export interface RolloutOptions extends CommonOptions {
  channel: string;
  percent: string;
  group?: string;
  runtimeVersion?: string;
}

/**
 * Start a progressive rollout of --group, or move the running rollout for
 * --runtime-version to --percent (100 completes it).
 */
export async function rolloutCommand(opts: RolloutOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const percent = parsePercent(opts.percent, 100);
  const base = channelPath(ctx.org, ctx.app, opts.channel);

  if (opts.group) {
    const r = await postJson<{ group_id: string; runtime_version: string; percent: number }>(
      client,
      `${base}/rollout`,
      { group_id: opts.group, percent }
    );
    console.log(
      percent >= 100
        ? `Released update group ${r.group_id} to every device on "${opts.channel}".`
        : `Rolling out update group ${r.group_id} (runtime ${r.runtime_version}) to ${percent}% of ` +
            `devices on "${opts.channel}". Grow it with:\n` +
            `  airlift rollout --channel ${opts.channel} --runtime-version ${r.runtime_version} --percent <n>`
    );
    return;
  }
  if (!opts.runtimeVersion) {
    throw new Error("Pass --group <id> to start a rollout, or --runtime-version <rv> to adjust one.");
  }
  const r = await sendJson<{ complete: boolean }>(client, "PATCH", `${base}/rollout`, {
    runtime_version: opts.runtimeVersion,
    percent,
  });
  console.log(
    r.complete
      ? `Rollout on "${opts.channel}" (runtime ${opts.runtimeVersion}) completed: every device gets it.`
      : `Rollout on "${opts.channel}" (runtime ${opts.runtimeVersion}) now at ${percent}%.`
  );
}

export interface SplitOptions extends CommonOptions {
  channel: string;
  branch?: string;
  percent?: string;
  off?: boolean;
}

/** A/B split: serve --branch to --percent of the channel's devices, or --off. */
export async function splitCommand(opts: SplitOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const base = channelPath(ctx.org, ctx.app, opts.channel);
  if (opts.off) {
    await sendJson(client, "DELETE", `${base}/split`);
    console.log(`Ended the A/B split on "${opts.channel}": every device gets its own branch.`);
    return;
  }
  if (!opts.branch || !opts.percent) {
    throw new Error("Pass --branch <name> --percent <n> to split, or --off to end the split.");
  }
  const percent = parsePercent(opts.percent, 99.999);
  const r = await sendJson<{ split_channel: string }>(client, "PUT", `${base}/split`, {
    branch: opts.branch,
    percent,
  });
  console.log(
    `${percent}% of devices on "${opts.channel}" now get branch "${opts.branch}" ` +
      `(served via channel "${r.split_channel}").`
  );
}

export interface RepublishOptions extends CommonOptions {
  group: string;
  channel?: string;
}

/** Re-ship an existing update group as a brand-new update. */
export async function republishCommand(opts: RepublishOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const r = await postJson<{
    group_id: string;
    branch: string;
    channels: { channel: string; status: string }[];
  }>(
    client,
    `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}` +
      `/updates/${encodeURIComponent(opts.group)}/republish`,
    opts.channel ? { channel: opts.channel } : {}
  );
  console.log(`Republished ${opts.group} as update group ${r.group_id} on branch "${r.branch}".`);
  for (const c of r.channels) console.log(`  ${c.channel}: ${c.status}`);
}
