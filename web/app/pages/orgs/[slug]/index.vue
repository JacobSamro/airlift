<script setup lang="ts">
// Org overview: headline stats plus the org's apps.
const route = useRoute();
const api = useApi();
const me = useMe();
const slug = computed(() => route.params.slug as string);

const stats = ref<OrgStats | null>(null);
const orgName = ref("");
const apps = ref<App[]>([]);
const loading = ref(true);
const error = ref("");

const canAdmin = computed(() => {
  const role = me.value?.orgs.find((o) => o.slug === slug.value)?.role;
  return role === "owner" || role === "admin";
});

const showCreate = ref(false);
const newApp = reactive({ name: "", slug: "" });

watch(
  () => newApp.name,
  (v) => {
    newApp.slug = v
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40);
  },
);

async function load() {
  loading.value = true;
  try {
    const [org, list] = await Promise.all([
      api.get<{ org?: { name?: string }; name?: string; role: string; stats: OrgStats }>(
        `/api/v1/orgs/${slug.value}`,
      ),
      api.get<{ apps: App[] }>(`/api/v1/orgs/${slug.value}/apps`),
    ]);
    stats.value = org.stats;
    orgName.value = org.org?.name || org.name || slug.value;
    apps.value = list.apps;
  } finally {
    loading.value = false;
  }
}
onMounted(load);
watch(slug, load);

async function create() {
  error.value = "";
  try {
    await api.post(`/api/v1/orgs/${slug.value}/apps`, { slug: newApp.slug, name: newApp.name });
    closeCreate();
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

function closeCreate() {
  showCreate.value = false;
  newApp.name = "";
  newApp.slug = "";
  error.value = "";
}
</script>

<template>
  <div>
    <div class="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">{{ orgName || slug }}</h1>
        <p class="text-sm text-muted-foreground">Over-the-air updates for this organization.</p>
      </div>
      <UiButton v-if="canAdmin" size="sm" data-testid="new-app" @click="showCreate = true">
        <UiIcon name="plus" :size="14" /> New app
      </UiButton>
    </div>

    <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
    <template v-else>
      <div class="mb-6 grid grid-cols-3 gap-4">
        <UiCard>
          <p class="text-xs uppercase tracking-wide text-muted-foreground">Apps</p>
          <p class="mt-1 text-2xl font-semibold">{{ stats?.apps ?? 0 }}</p>
        </UiCard>
        <UiCard>
          <p class="text-xs uppercase tracking-wide text-muted-foreground">Members</p>
          <p class="mt-1 text-2xl font-semibold">{{ stats?.members ?? 0 }}</p>
        </UiCard>
        <UiCard>
          <p class="text-xs uppercase tracking-wide text-muted-foreground">Teams</p>
          <p class="mt-1 text-2xl font-semibold">{{ stats?.teams ?? 0 }}</p>
        </UiCard>
      </div>

      <UiCard v-if="!apps.length">
        <div class="flex flex-col items-center gap-3 py-12 text-center">
          <UiIcon name="package" :size="32" class="text-muted-foreground" />
          <div>
            <p class="font-medium">No apps yet</p>
            <p class="mt-1 text-sm text-muted-foreground">
              Create an app here, then wire up your Expo project with the CLI:
            </p>
            <p class="mt-2 font-mono text-xs text-muted-foreground">
              npx airlift-cli init --org {{ slug }} --app &lt;app-slug&gt;
            </p>
          </div>
          <UiButton v-if="canAdmin" size="sm" class="mt-2" @click="showCreate = true">
            <UiIcon name="plus" :size="14" /> New app
          </UiButton>
        </div>
      </UiCard>

      <UiCard v-else title="Apps">
        <table class="w-full text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr class="border-b border-border">
              <th class="px-3 py-2 font-medium">Name</th>
              <th class="px-3 py-2 font-medium">Slug</th>
              <th class="px-3 py-2 font-medium">Created</th>
              <th class="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in apps" :key="a.id" class="border-b border-border last:border-0">
              <td class="px-3 py-3">
                <NuxtLink
                  :to="`/orgs/${slug}/apps/${a.slug}`"
                  class="flex items-center gap-2 font-medium hover:underline"
                >
                  <UiIcon name="package" :size="16" class="text-muted-foreground" />
                  {{ a.name }}
                </NuxtLink>
              </td>
              <td class="px-3 py-3 font-mono text-xs text-muted-foreground">{{ a.slug }}</td>
              <td class="px-3 py-3 text-muted-foreground">{{ timeAgo(a.created_at) }}</td>
              <td class="px-3 py-3 text-right">
                <NuxtLink :to="`/orgs/${slug}/apps/${a.slug}`">
                  <UiButton variant="ghost" size="sm">Open</UiButton>
                </NuxtLink>
              </td>
            </tr>
          </tbody>
        </table>
      </UiCard>
    </template>

    <UiModal :open="showCreate" title="New app" @close="closeCreate">
      <form class="flex flex-col gap-4" @submit.prevent="create">
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Name</label>
          <UiInput v-model="newApp.name" placeholder="My App" required data-testid="app-name" />
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Slug</label>
          <UiInput v-model="newApp.slug" placeholder="my-app" required data-testid="app-slug" />
          <p class="text-xs text-muted-foreground">Used in URLs and the CLI. Lowercase, dashes only.</p>
        </div>
        <p v-if="error" class="text-sm text-red-400">{{ error }}</p>
        <div class="flex justify-end gap-2">
          <UiButton variant="outline" type="button" @click="closeCreate">Cancel</UiButton>
          <UiButton type="submit">Create</UiButton>
        </div>
      </form>
    </UiModal>
  </div>
</template>
