<script setup lang="ts">
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const api = useApi();
const me = useMe();
const { confirm } = useConfirm();

const tokens = ref<Token[]>([]);
const loading = ref(true);
const showCreate = ref(false);
const newName = ref("");
const created = ref<string | null>(null);
const copied = ref(false);

// Scope selection for a new token.
const orgs = computed(() => me.value?.orgs ?? []);
const scopeType = ref<"all" | "org" | "app">("all");
const scopeOrg = ref("");
const scopeApp = ref("");
const scopePerm = ref<"admin" | "publish" | "read">("admin");

const PERM_LABEL: Record<string, string> = {
  admin: "full",
  publish: "read & publish",
  read: "read-only",
};

watch([scopeType, scopeOrg], () => {
  if ((scopeType.value === "org" || scopeType.value === "app") && !scopeOrg.value) {
    scopeOrg.value = orgs.value[0]?.slug ?? "";
  }
});

// Apps for the selected org, so the app scope is a picker instead of free text.
const orgApps = ref<App[]>([]);
const orgAppsLoading = ref(false);
watch(
  [scopeType, scopeOrg],
  async () => {
    if (scopeType.value !== "app" || !scopeOrg.value) return;
    orgAppsLoading.value = true;
    scopeApp.value = "";
    try {
      orgApps.value = (
        await api.get<{ apps: App[] }>(`/api/v1/orgs/${scopeOrg.value}/apps`)
      ).apps;
    } catch {
      orgApps.value = [];
    } finally {
      orgAppsLoading.value = false;
    }
  },
  { immediate: false },
);

async function load() {
  loading.value = true;
  try {
    tokens.value = (await api.get<{ tokens: Token[] }>("/api/v1/tokens")).tokens;
  } finally {
    loading.value = false;
  }
}
onMounted(load);

async function create() {
  // Always send the scope kind explicitly: the server rejects a narrow scope
  // with missing org/app instead of minting an all-scope token.
  const body: Record<string, string> = {
    name: newName.value,
    permission: scopePerm.value,
    scope: scopeType.value,
  };
  if (scopeType.value !== "all" && scopeOrg.value) body.org = scopeOrg.value;
  if (scopeType.value === "app" && scopeApp.value.trim()) body.app = scopeApp.value.trim();
  const res = await api.post<{ token: string }>("/api/v1/tokens", body);
  created.value = res.token;
  newName.value = "";
  await load();
}

async function remove(t: Token) {
  if (
    !(await confirm({
      title: "Revoke token",
      message: `Revoke token "${t.name}"? Any client using it will stop working.`,
      confirmText: "Revoke",
      destructive: true,
    }))
  )
    return;
  await api.del(`/api/v1/tokens/${t.id}`);
  await load();
}

function copyToken() {
  if (created.value) navigator.clipboard?.writeText(created.value);
  copied.value = true;
  setTimeout(() => (copied.value = false), 1500);
}

function closeCreate() {
  showCreate.value = false;
  created.value = null;
  scopeType.value = "all";
  scopeOrg.value = "";
  scopeApp.value = "";
  scopePerm.value = "admin";
}
</script>

<template>
  <div>
    <div class="mb-6 flex items-end justify-between">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Access Tokens</h1>
        <p class="text-sm text-muted-foreground">
          Use a token to authenticate CLI and CI publishes.
          Scope a token to one org or app to limit its reach.
        </p>
      </div>
      <UiButton size="sm" @click="showCreate = true">
        <UiIcon name="plus" :size="14" /> New token
      </UiButton>
    </div>

    <UiCard>
      <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
      <div v-else-if="!tokens.length" class="py-8 text-center text-sm text-muted-foreground">No tokens yet.</div>
      <table v-else class="w-full text-sm">
        <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
          <tr class="border-b border-border">
            <th class="px-3 py-2 font-medium">Name</th>
            <th class="px-3 py-2 font-medium">Scope</th>
            <th class="px-3 py-2 font-medium">Permission</th>
            <th class="px-3 py-2 font-medium">Token</th>
            <th class="px-3 py-2 font-medium">Last used</th>
            <th class="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tokens" :key="t.id" class="border-b border-border last:border-0">
            <td class="px-3 py-3 font-medium">{{ t.name }}</td>
            <td class="px-3 py-3">
              <UiBadge :variant="t.scope === 'all' ? 'default' : 'outline'">
                {{ t.scope === "all" ? "all access" : t.scope }}
              </UiBadge>
            </td>
            <td class="px-3 py-3 text-muted-foreground">{{ PERM_LABEL[t.max_perm] || t.max_perm }}</td>
            <td class="px-3 py-3 font-mono text-xs text-muted-foreground">{{ t.token_prefix }}…</td>
            <td class="px-3 py-3 text-muted-foreground">{{ t.last_used_at ? timeAgo(t.last_used_at) : "never" }}</td>
            <td class="px-3 py-3 text-right">
              <UiButton variant="ghost" size="sm" @click="remove(t)"><UiIcon name="trash" :size="14" /></UiButton>
            </td>
          </tr>
        </tbody>
      </table>
    </UiCard>

    <UiModal :open="showCreate" :title="created ? 'Token created' : 'New access token'" @close="closeCreate">
      <div v-if="created" class="flex flex-col gap-4">
        <p class="text-sm text-muted-foreground">Copy it now — you won't be able to see it again.</p>
        <div class="flex items-center gap-2 rounded-[var(--radius)] border border-border bg-background px-3 py-2 font-mono text-xs">
          <span class="flex-1 break-all">{{ created }}</span>
          <UiButton variant="ghost" size="sm" @click="copyToken">
            <UiIcon :name="copied ? 'check' : 'copy'" :size="14" />
          </UiButton>
        </div>
        <p class="text-xs text-muted-foreground">
          Send it as a <span class="font-mono">Bearer</span> token in the
          <span class="font-mono">Authorization</span> header when publishing updates.
        </p>
        <div class="flex justify-end">
          <UiButton @click="closeCreate">Done</UiButton>
        </div>
      </div>
      <form v-else class="flex flex-col gap-4" @submit.prevent="create">
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Name</label>
          <UiInput v-model="newName" placeholder="laptop" required />
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Scope</label>
          <Select v-model="scopeType">
            <SelectTrigger class="w-full" data-testid="token-scope"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All my access</SelectItem>
              <SelectItem value="org">A single organization</SelectItem>
              <SelectItem value="app">A single app</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Permission</label>
          <Select v-model="scopePerm">
            <SelectTrigger class="w-full" data-testid="token-perm"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="admin">Full (read, publish, manage)</SelectItem>
              <SelectItem value="publish">Read &amp; publish</SelectItem>
              <SelectItem value="read">Read-only</SelectItem>
            </SelectContent>
          </Select>
          <p class="text-xs text-muted-foreground">Caps the token below your own access; never grants more.</p>
        </div>

        <div v-if="scopeType !== 'all'" class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Organization</label>
          <Select v-model="scopeOrg">
            <SelectTrigger class="w-full" data-testid="token-org"><SelectValue placeholder="Select an organization…" /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="o in orgs" :key="o.slug" :value="o.slug">{{ o.name }}</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div v-if="scopeType === 'app'" class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">App</label>
          <Select v-model="scopeApp" :disabled="orgAppsLoading || !orgApps.length">
            <SelectTrigger class="w-full" data-testid="token-app">
              <SelectValue :placeholder="orgAppsLoading ? 'Loading apps…' : 'Select an app…'" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="a in orgApps" :key="a.id" :value="a.slug">{{ a.name }}</SelectItem>
            </SelectContent>
          </Select>
          <p v-if="!orgAppsLoading && !orgApps.length" class="text-xs text-muted-foreground">
            This organization has no apps yet.
          </p>
          <p v-else class="text-xs text-muted-foreground">The app this token is limited to.</p>
        </div>

        <div class="flex justify-end gap-2">
          <UiButton variant="outline" type="button" @click="closeCreate">Cancel</UiButton>
          <UiButton type="submit">Create</UiButton>
        </div>
      </form>
    </UiModal>
  </div>
</template>
