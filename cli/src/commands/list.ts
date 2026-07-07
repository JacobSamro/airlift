import { UpdateInfo, getJson } from "../api";
import { CommonOptions, resolveContext } from "../config";
import { formatDate, renderTable, shortId, truncate } from "../util";

export interface ListOptions extends CommonOptions {
  branch?: string;
  limit?: string;
}

export async function listCommand(opts: ListOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };

  const params = new URLSearchParams();
  if (opts.branch) params.set("branch", opts.branch);
  if (opts.limit !== undefined) {
    const limit = Number.parseInt(opts.limit, 10);
    if (Number.isNaN(limit) || limit <= 0) {
      throw new Error(`Invalid --limit "${opts.limit}"; expected a positive integer.`);
    }
    params.set("limit", String(limit));
  }
  const query = params.toString();

  const { updates } = await getJson<{ updates: UpdateInfo[] }>(
    client,
    `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}/updates` +
      (query ? `?${query}` : "")
  );

  if (updates.length === 0) {
    console.log("No updates found.");
    return;
  }

  console.log(
    renderTable(
      ["ID", "BRANCH", "RUNTIME", "PLATFORMS", "TYPE", "MESSAGE", "CREATED"],
      updates.map((u) => [
        shortId(u.id),
        u.branch,
        u.runtime_version,
        (u.platforms ?? []).join(","),
        u.group_type,
        truncate(u.message ?? "", 40),
        formatDate(u.created_at),
      ])
    )
  );
}
