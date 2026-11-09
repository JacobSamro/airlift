<script setup lang="ts">
// Logs: OTLP log records from devices, newest first, with severity / text /
// update / device filters and "load older" paging.
const route = useRoute();
const api = useApi();
const slug = computed(() => route.params.slug as string);
const appSlug = computed(() => route.params.app as string);
const base = computed(() => `/api/v1/orgs/${slug.value}/apps/${appSlug.value}`);

interface LogRow {
  id: number;
  ts: string;
  severity: number;
  severity_text: string | null;
  body: string;
  attributes: string | null;
  update_id: string | null;
  platform: string | null;
  client_id: string | null;
  trace_id: string | null;
}

const windowSel = ref("24h");
const severity = ref("0");
const text = ref("");
const update = ref("");
const client = ref("");
const logs = ref<LogRow[]>([]);
const loading = ref(false);
const exhausted = ref(false);
const expanded = ref<number | null>(null);
const PAGE = 200;

async function fetchPage(beforeId?: number) {
  const q = new URLSearchParams({ window: windowSel.value, severity: severity.value, limit: String(PAGE) });
  if (text.value.trim()) q.set("q", text.value.trim());
  if (update.value.trim()) q.set("update", update.value.trim());
  if (client.value.trim()) q.set("client", client.value.trim());
  if (beforeId) q.set("before_id", String(beforeId));
  return (await api.get<{ logs: LogRow[] }>(`${base.value}/logs?${q}`)).logs;
}

async function load() {
  loading.value = true;
  try {
    logs.value = await fetchPage();
    exhausted.value = logs.value.length < PAGE;
  } finally {
    loading.value = false;
  }
}
async function older() {
  const last = logs.value[logs.value.length - 1];
  if (!last) return;
  const page = await fetchPage(last.id);
  logs.value.push(...page);
  exhausted.value = page.length < PAGE;
}
onMounted(load);
watch([slug, appSlug, windowSel, severity], load);

// OTLP severityNumber ranges: 1-4 TRACE, 5-8 DEBUG, 9-12 INFO, 13-16 WARN,
// 17-20 ERROR, 21-24 FATAL.
function level(n: number): { label: string; cls: string } {
  if (n >= 21) return { label: "FATAL", cls: "text-red-500" };
  if (n >= 17) return { label: "ERROR", cls: "text-red-500" };
  if (n >= 13) return { label: "WARN", cls: "text-amber-500" };
  if (n >= 9) return { label: "INFO", cls: "text-sky-500" };
  if (n >= 5) return { label: "DEBUG", cls: "text-muted-foreground" };
  if (n >= 1) return { label: "TRACE", cls: "text-muted-foreground" };
  return { label: "—", cls: "text-muted-foreground" };
}
const pretty = (attrs: string | null) => {
  try {
    return attrs ? JSON.stringify(JSON.parse(attrs), null, 2) : "";
  } catch {
    return attrs ?? "";
  }
};
</script>

<template>
  <div>
    <AppTabs :slug="slug" :app="appSlug" />

    <div class="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h2 class="text-lg font-semibold tracking-tight">Logs</h2>
      <form class="flex flex-wrap items-center gap-2" @submit.prevent="load">
        <div class="w-44"><UiInput v-model="text" placeholder="search text" class="h-8" data-testid="logs-search" /></div>
        <div class="w-36"><UiInput v-model="update" placeholder="update id" class="h-8" /></div>
        <div class="w-36"><UiInput v-model="client" placeholder="device id" class="h-8" /></div>
        <select v-model="severity" class="h-8 rounded-md border border-border bg-background px-2 text-sm">
          <option value="0">All levels</option>
          <option value="9">Info+</option>
          <option value="13">Warn+</option>
          <option value="17">Error+</option>
        </select>
        <select v-model="windowSel" class="h-8 rounded-md border border-border bg-background px-2 text-sm">
          <option value="1h">1h</option>
          <option value="24h">24h</option>
          <option value="7d">7d</option>
          <option value="14d">14d</option>
        </select>
        <UiButton size="sm" type="submit">Search</UiButton>
      </form>
    </div>

    <UiCard>
      <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
      <div v-else-if="!logs.length" class="py-10 text-center text-sm text-muted-foreground">
        No log records. Point an OTLP/HTTP JSON log exporter at
        <span class="font-mono">/u/&lt;app-id&gt;/otlp/v1/logs</span>.
      </div>
      <ul v-else class="flex flex-col divide-y divide-border font-mono text-xs">
        <li v-for="l in logs" :key="l.id" class="py-1.5">
          <button class="flex w-full items-start gap-3 text-left" @click="expanded = expanded === l.id ? null : l.id">
            <span class="w-44 shrink-0 whitespace-nowrap text-muted-foreground">{{ l.ts.replace("T", " ").slice(0, 23) }}</span>
            <span class="w-12 shrink-0 font-semibold" :class="level(l.severity).cls">
              {{ l.severity_text ?? level(l.severity).label }}
            </span>
            <span class="w-14 shrink-0 text-muted-foreground">{{ l.platform ?? "" }}</span>
            <span class="flex-1 whitespace-pre-wrap break-all">{{ l.body }}</span>
          </button>
          <pre
            v-if="expanded === l.id"
            class="ml-44 mt-1 overflow-x-auto rounded-md bg-muted px-3 py-2"
          >update {{ l.update_id ?? "—" }} · device {{ l.client_id ?? "—" }}{{ l.trace_id ? ` · trace ${l.trace_id}` : "" }}
{{ pretty(l.attributes) }}</pre>
        </li>
      </ul>
      <div v-if="logs.length && !exhausted" class="flex justify-center pt-3">
        <UiButton variant="outline" size="sm" @click="older">Load older</UiButton>
      </div>
    </UiCard>
  </div>
</template>
