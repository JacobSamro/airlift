<script setup lang="ts">
// OAuth consent for MCP clients (agents): who is asking, what it may do
// (a cap on your own access + optional org/app confinement), approve/deny.
const route = useRoute();
const api = useApi();
const me = useMe();

const q = computed(() => ({
  client_id: (route.query.client_id as string) ?? "",
  redirect_uri: (route.query.redirect_uri as string) ?? "",
  code_challenge: (route.query.code_challenge as string) ?? "",
  state: (route.query.state as string) ?? "",
}));
const client = ref<{ name: string; redirect_host: string } | null>(null);
const error = ref("");
const busy = ref(false);
const permission = ref<"read" | "publish" | "admin">("publish");
const org = ref("");

onMounted(async () => {
  try {
    client.value = await api.get(
      `/api/v1/oauth/client?client_id=${encodeURIComponent(q.value.client_id)}&redirect_uri=${encodeURIComponent(q.value.redirect_uri)}`,
    );
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
});

async function decide(approve: boolean) {
  busy.value = true;
  error.value = "";
  try {
    const r = await api.post<{ redirect: string }>("/api/v1/oauth/consent", {
      ...q.value,
      approve,
      permission: permission.value,
      org: org.value || undefined,
    });
    window.location.href = r.redirect;
  } catch (e) {
    error.value = apiErrorMessage(e);
    busy.value = false;
  }
}
</script>

<template>
  <div class="mx-auto max-w-lg py-10">
    <UiCard v-if="error && !client" title="Can't authorize this client">
      <p class="text-sm text-red-400">{{ error }}</p>
    </UiCard>
    <UiCard v-else-if="client" :title="`Allow ${client.name} to use airlift?`">
      <div class="flex flex-col gap-4 text-sm">
        <p class="text-muted-foreground">
          <span class="font-medium text-foreground">{{ client.name }}</span> (redirects to
          <span class="font-mono">{{ client.redirect_host }}</span>) wants to act as
          <span class="font-medium text-foreground">{{ me?.user.username }}</span> through airlift's MCP server: list
          apps and updates, and — depending on what you allow — publish, roll out and roll back. It never gets more
          than you have.
        </p>
        <label class="flex flex-col gap-1">
          <span class="font-medium">Permission</span>
          <select v-model="permission" class="h-9 rounded-md border border-border bg-background px-2" data-testid="consent-perm">
            <option value="read">Read only</option>
            <option value="publish">Read, publish, release (promote / roll out / roll back)</option>
            <option value="admin">Everything you can do</option>
          </select>
        </label>
        <label class="flex flex-col gap-1">
          <span class="font-medium">Organizations</span>
          <select v-model="org" class="h-9 rounded-md border border-border bg-background px-2" data-testid="consent-org">
            <option value="">All my organizations</option>
            <option v-for="o in me?.orgs ?? []" :key="o.slug" :value="o.slug">Only {{ o.name }}</option>
          </select>
        </label>
        <p class="text-xs text-muted-foreground">
          Access lasts until you revoke it under Access Tokens (it appears as "MCP: {{ client.name }}").
        </p>
        <p v-if="error" class="text-red-400">{{ error }}</p>
        <div class="flex justify-end gap-2">
          <UiButton variant="outline" :disabled="busy" data-testid="consent-deny" @click="decide(false)">Deny</UiButton>
          <UiButton :disabled="busy" data-testid="consent-approve" @click="decide(true)">Allow</UiButton>
        </div>
      </div>
    </UiCard>
  </div>
</template>
