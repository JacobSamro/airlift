// Typed wrappers around the airlift dashboard API.

export type Role = "owner" | "admin" | "member";

export interface User {
  id: string;
  email: string;
  username: string;
  is_admin: boolean;
  created_at: string;
}
export interface OrgRef {
  id: string;
  slug: string;
  name: string;
  role: Role;
}
export interface Me {
  user: User;
  orgs: OrgRef[];
}
export interface OrgStats {
  apps: number;
  members: number;
  teams: number;
}
export interface Member {
  user_id: string;
  username: string;
  email: string;
  role: string;
}
export interface Team {
  id: string;
  slug: string;
  name: string;
}
export interface TeamPerm {
  app: string;
  permission: string;
}
export interface App {
  id: string;
  org_id: string;
  slug: string;
  name: string;
  created_at: string;
  updated_at: string;
}
export interface Branch {
  id: string;
  name: string;
  created_at: string;
}
export interface ChannelRelease {
  runtime_version: string;
  group_id: string;
  released_at: string;
}
export interface Channel {
  id: string;
  name: string;
  branch: string | null;
  branch_id: string | null;
  auto_release: boolean;
  releases: ChannelRelease[];
}
export interface UpdateGroup {
  id: string;
  branch: string;
  runtime_version: string;
  message: string | null;
  git_branch: string | null;
  git_commit: string | null;
  group_type: "normal" | "rollback_to_embedded";
  platforms: string[];
  created_at: string;
}
export interface Token {
  id: string;
  name: string;
  token_prefix: string;
  last_used_at: string | null;
  created_at: string;
  /** "all", "<org>", or "<org>/<app>". */
  scope: string;
  /** Permission cap: "read", "publish", or "admin". */
  max_perm: string;
}

export function useApi() {
  const call = <T>(method: string, path: string, body?: unknown) =>
    $fetch<T>(path, {
      method: method as any,
      body: body as any,
      credentials: "same-origin",
    });
  return {
    get: <T>(p: string) => call<T>("GET", p),
    post: <T>(p: string, b?: unknown) => call<T>("POST", p, b),
    put: <T>(p: string, b?: unknown) => call<T>("PUT", p, b),
    patch: <T>(p: string, b?: unknown) => call<T>("PATCH", p, b),
    del: <T>(p: string) => call<T>("DELETE", p),
  };
}

/** Reactive current-user state, shared across the app. */
export function useMe() {
  return useState<Me | null>("me", () => null);
}

export function apiErrorMessage(e: any): string {
  return (
    e?.data?.error?.message ||
    e?.data?.errors?.[0]?.message ||
    e?.message ||
    "Request failed"
  );
}
