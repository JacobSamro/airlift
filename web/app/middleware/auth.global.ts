// Client-side auth gate. Loads the current user once, then redirects between
// the app, the login page, and the first-run setup wizard as appropriate.
// A signed-out visit to a deep link (e.g. the OAuth consent page an MCP
// client opened) is remembered and resumed after sign-in — in
// sessionStorage, so it survives an SSO round-trip.
const NEXT_KEY = "airlift_next";

export default defineNuxtRouteMiddleware(async (to) => {
  const me = useMe();
  const api = useApi();

  if (!me.value) {
    try {
      me.value = await api.get<Me>("/api/v1/auth/me");
    } catch {
      me.value = null;
    }
  }

  const authed = !!me.value;
  const publicPage = to.path === "/login" || to.path === "/setup";

  if (!authed && !publicPage) {
    if (import.meta.client && to.fullPath !== "/") {
      sessionStorage.setItem(NEXT_KEY, to.fullPath);
    }
    const status = await api
      .get<{ needs_setup: boolean }>("/api/v1/setup/status")
      .catch(() => ({ needs_setup: false }));
    return navigateTo(status.needs_setup ? "/setup" : "/login");
  }

  if (authed && import.meta.client) {
    const next = sessionStorage.getItem(NEXT_KEY);
    // Same-site paths only (no //host or scheme-relative tricks).
    if (next && next.startsWith("/") && !next.startsWith("//") && next !== to.fullPath) {
      sessionStorage.removeItem(NEXT_KEY);
      return navigateTo(next);
    }
  }

  if (authed && publicPage) {
    return navigateTo("/");
  }
});
