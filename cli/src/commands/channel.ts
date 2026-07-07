import { postJson } from "../api";
import { CommonOptions, resolveContext } from "../config";

export interface PromoteOptions extends CommonOptions {
  channel: string;
  group: string;
}

export async function promoteCommand(opts: PromoteOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  await postJson<{ ok: boolean }>(
    client,
    `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}` +
      `/channels/${encodeURIComponent(opts.channel)}/promote`,
    { group_id: opts.group }
  );
  console.log(`Promoted update group ${opts.group} to channel "${opts.channel}".`);
}

export interface RollbackOptions extends CommonOptions {
  channel: string;
  runtimeVersion: string;
}

export async function rollbackCommand(opts: RollbackOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const result = await postJson<{ ok: boolean; group_id: string }>(
    client,
    `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}` +
      `/channels/${encodeURIComponent(opts.channel)}/rollback`,
    { runtime_version: opts.runtimeVersion }
  );
  console.log(
    `Rolled back channel "${opts.channel}" (runtime ${opts.runtimeVersion}) ` +
      `to update group ${result.group_id}.`
  );
}
