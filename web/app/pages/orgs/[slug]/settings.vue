<script setup lang="ts">
// Organization-scoped settings. Instance-wide configuration (storage, TLS,
// Google sign-in, users) lives on the admin-only /settings page.
const route = useRoute();
const api = useApi();
const me = useMe();
const slug = computed(() => route.params.slug as string);
const host = computed(() => window.location.host);

const canAdmin = computed(() => {
  const role = me.value?.orgs.find((o) => o.slug === slug.value)?.role;
  return role === "owner" || role === "admin";
});

interface AuditEntry {
  id: number;
  ts: string;
  actor_user_id: string | null;
  action: string;
  target: string | null;
  detail: string | null;
}
const audit = ref<AuditEntry[]>([]);
async function loadAudit() {
  if (!canAdmin.value) return;
  audit.value = (
    await api.get<{ entries: AuditEntry[] }>(`/api/v1/orgs/${slug.value}/audit`)
  ).entries;
}
onMounted(loadAudit);
watch([slug, canAdmin], loadAudit);
const exportUrl = (format: string) => `/api/v1/orgs/${slug.value}/audit/export?format=${format}`;
</script>

<template>
  <div>
    <h1 class="mb-6 text-2xl font-semibold tracking-tight">Settings</h1>

    <div class="flex flex-col gap-6">
      <UiCard title="Organization" description="Namespace for your apps and updates.">
        <dl class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <dt class="text-muted-foreground">Slug</dt>
            <dd class="font-mono">{{ slug }}</dd>
          </div>
          <div>
            <dt class="text-muted-foreground">Update server host</dt>
            <dd class="font-mono">{{ host }}</dd>
          </div>
        </dl>
      </UiCard>

      <UiCard
        v-if="canAdmin"
        title="Audit log"
        description="Who published, released, rolled back and changed access. Newest first."
      >
        <template #header>
          <div class="flex gap-2">
            <a :href="exportUrl('csv')" download data-testid="audit-export-csv">
              <UiButton variant="outline" size="sm"><UiIcon name="download" :size="14" /> CSV</UiButton>
            </a>
            <a :href="exportUrl('jsonl')" download data-testid="audit-export-jsonl">
              <UiButton variant="outline" size="sm"><UiIcon name="download" :size="14" /> JSON Lines</UiButton>
            </a>
          </div>
        </template>
        <div v-if="!audit.length" class="py-4 text-sm text-muted-foreground">No entries yet.</div>
        <table v-else class="w-full text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr class="border-b border-border">
              <th class="px-2 py-2 font-medium">When</th>
              <th class="px-2 py-2 font-medium">Action</th>
              <th class="px-2 py-2 font-medium">Target</th>
              <th class="px-2 py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in audit.slice(0, 50)" :key="e.id" class="border-b border-border last:border-0">
              <td class="whitespace-nowrap px-2 py-2 text-muted-foreground" :title="e.ts">{{ timeAgo(e.ts) }}</td>
              <td class="px-2 py-2 font-mono text-xs">{{ e.action }}</td>
              <td class="px-2 py-2 font-mono text-xs">{{ e.target ?? "—" }}</td>
              <td class="max-w-64 truncate px-2 py-2 text-xs text-muted-foreground" :title="e.detail ?? ''">
                {{ e.detail ?? "" }}
              </td>
            </tr>
          </tbody>
        </table>
        <p class="mt-2 text-xs text-muted-foreground">
          For scheduled pulls into a SIEM, call
          <span class="font-mono">GET /api/v1/orgs/{{ slug }}/audit/export?format=jsonl&amp;after_id=…</span>
          with an org-scoped admin token; continue from the <span class="font-mono">x-audit-next-after-id</span> header.
        </p>
      </UiCard>

      <UiCard
        v-if="me?.user.is_admin"
        title="Instance settings"
        description="Storage, TLS &amp; domains, Google sign-in, and user accounts are configured instance-wide."
      >
        <NuxtLink to="/settings">
          <UiButton variant="outline"><UiIcon name="settings" :size="14" /> Open instance settings</UiButton>
        </NuxtLink>
      </UiCard>
    </div>
  </div>
</template>
