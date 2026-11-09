/** Thin wrapper around fetch for talking to an airlift server. */

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function normalizeServer(server: string): string {
  return server.replace(/\/+$/, "");
}

export interface ApiClient {
  server: string;
  token: string;
}

async function request(
  client: ApiClient,
  path: string,
  init: RequestInit = {}
): Promise<Response> {
  const url = normalizeServer(client.server) + path;
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        Authorization: `Bearer ${client.token}`,
        ...(init.headers ?? {}),
      },
    });
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new Error(`Could not reach server at ${url} (${cause})`);
  }

  if (!res.ok) {
    let message = `HTTP ${res.status} ${res.statusText}`;
    let code: string | undefined;
    try {
      const body = (await res.json()) as {
        error?: { code?: string; message?: string };
      };
      if (body && body.error) {
        if (body.error.message) message = body.error.message;
        code = body.error.code;
      }
    } catch {
      // Non-JSON error body; keep the generic message.
    }
    if (res.status === 401 || res.status === 403) {
      message += " (check your token: pass --token or set AIRLIFT_TOKEN)";
    }
    throw new ApiError(res.status, message, code);
  }
  return res;
}

export async function getJson<T>(client: ApiClient, path: string): Promise<T> {
  const res = await request(client, path);
  return (await res.json()) as T;
}

export async function getText(client: ApiClient, path: string): Promise<string> {
  const res = await request(client, path);
  return await res.text();
}

export async function postJson<T>(
  client: ApiClient,
  path: string,
  body: unknown
): Promise<T> {
  const res = await request(client, path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await res.json()) as T;
}

/** JSON request with any method (PUT/PATCH/DELETE…). */
export async function sendJson<T>(
  client: ApiClient,
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const res = await request(client, path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return (await res.json()) as T;
}

export async function postForm<T>(
  client: ApiClient,
  path: string,
  form: FormData
): Promise<T> {
  const res = await request(client, path, { method: "POST", body: form });
  return (await res.json()) as T;
}

/* ---- Server response shapes ---- */

export interface AppInfo {
  id: string;
  org_id: string;
  slug: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface ChannelRelease {
  runtime_version: string;
  group_id: string;
  released_at: string;
}

export interface ChannelInfo {
  id: string;
  name: string;
  branch: string;
  branch_id: string;
  auto_release: boolean;
  releases: ChannelRelease[];
}

export interface AppDetail {
  app: AppInfo;
  branches: { id: string; name: string }[];
  channels: ChannelInfo[];
}

export interface UpdateInfo {
  id: string;
  branch: string;
  runtime_version: string;
  message: string | null;
  git_branch: string | null;
  git_commit: string | null;
  group_type: string;
  platforms: string[];
  created_at: string;
}

export interface PublishResult {
  group_id: string;
  branch: string;
  runtime_version: string;
  platforms: string[];
  channels: { channel: string; status: "released" | "pending" | "rolling_out"; percent?: number }[];
}
