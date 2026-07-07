<script setup lang="ts">
// Org overview: headline stats plus a placeholder until app management lands.
const route = useRoute();
const api = useApi();
const slug = computed(() => route.params.slug as string);

const stats = ref<OrgStats | null>(null);
const orgName = ref("");
const loading = ref(true);

async function load() {
  loading.value = true;
  try {
    const org = await api.get<{ org?: { name?: string }; name?: string; role: string; stats: OrgStats }>(
      `/api/v1/orgs/${slug.value}`,
    );
    stats.value = org.stats;
    orgName.value = org.org?.name || org.name || slug.value;
  } finally {
    loading.value = false;
  }
}
onMounted(load);
watch(slug, load);
</script>

<template>
  <div>
    <div class="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">{{ orgName || slug }}</h1>
        <p class="text-sm text-muted-foreground">Over-the-air updates for this organization.</p>
      </div>
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

      <UiCard>
        <div class="flex flex-col items-center gap-3 py-12 text-center">
          <UiIcon name="package" :size="32" class="text-muted-foreground" />
          <div>
            <p class="font-medium">Apps coming soon</p>
            <p class="mt-1 text-sm text-muted-foreground">
              App management and update publishing will appear here.
            </p>
          </div>
        </div>
      </UiCard>
    </template>
  </div>
</template>
