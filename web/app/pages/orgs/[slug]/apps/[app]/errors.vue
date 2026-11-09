<script setup lang="ts">
// Errors: JS crash groups from devices (airlift-reporter or OTLP exception
// logs), symbolicated with each update's sourcemap; drill into a group for
// its stack (original sources) and recent events.
const route = useRoute();
const api = useApi();
const slug = computed(() => route.params.slug as string);
const appSlug = computed(() => route.params.app as string);
const base = computed(() => `/api/v1/orgs/${slug.value}/apps/${appSlug.value}`);

interface Group {
  id: string;
  name: string;
  message: string;
  culprit: string | null;
  fatal: boolean;
  events: number;
  recent_events: number;
  recent_devices: number;
  updates: number;
  first_seen: string;
  last_seen: string;
}
interface Frame {
  function: string | null;
  file: string | null;
  line: number | null;
  column: number | null;
  source: string | null;
  source_line: number | null;
  source_column: number | null;
  in_app: boolean;
  symbolicated: boolean;
}
interface ErrorEvent {
  id: number;
  ts: string;
  update_id: string | null;
  platform: string | null;
  runtime_version: string | null;
  client_id: string | null;
  fatal: boolean;
  message: string;
  raw_stack: string | null;
  frames: Frame[] | null;
  source: string;
}

const windowSel = ref("24h");
const updateFilter = ref((route.query.update as string) ?? "");
const groups = ref<Group[]>([]);
const loading = ref(true);
const selected = ref<{ group: Group; events: ErrorEvent[] } | null>(null);
const showRaw = ref(false);

async function load() {
  loading.value = true;
  try {
    const q = new URLSearchParams({ window: windowSel.value });
    if (updateFilter.value.trim()) q.set("update", updateFilter.value.trim());
    groups.value = (await api.get<{ groups: Group[] }>(`${base.value}/errors?${q}`)).groups;
  } finally {
    loading.value = false;
  }
}
onMounted(load);
watch([slug, appSlug, windowSel], load);

async function open(g: Group) {
  selected.value = await api.get(`${base.value}/errors/${g.id}`);
  showRaw.value = false;
}

const latest = computed(() => selected.value?.events[0] ?? null);
const where = (f: Frame) =>
  f.symbolicated
    ? `${f.source}:${f.source_line}:${f.source_column}`
    : f.file
      ? `${f.file}${f.line ? `:${f.line}:${f.column}` : ""}`
      : "";
</script>

<template>
  <div>
    <AppTabs :slug="slug" :app="appSlug" />

    <div class="mb-4 flex items-center justify-between gap-2">
      <h2 class="text-lg font-semibold tracking-tight">Errors</h2>
      <div class="flex items-center gap-2">
        <div class="w-56"><UiInput v-model="updateFilter" placeholder="update id" class="h-8" @keyup.enter="load" /></div>
        <select v-model="windowSel" class="h-8 rounded-md border border-border bg-background px-2 text-sm">
          <option value="1h">Last hour</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="14d">Last 14 days</option>
        </select>
      </div>
    </div>

    <UiCard>
      <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
      <div v-else-if="!groups.length" class="flex flex-col items-center gap-2 py-10 text-center">
        <UiIcon name="check" :size="28" class="text-muted-foreground" />
        <p class="font-medium">No errors in this window</p>
        <p class="max-w-md text-sm text-muted-foreground">
          Report JS errors with <span class="font-mono">airlift-reporter</span>
          (<span class="font-mono">initAirlift({ url })</span>) or an OTLP log exporter pointed at
          <span class="font-mono">/u/&lt;app-id&gt;/otlp/v1/logs</span>. Stacks are symbolicated with the sourcemap
          <span class="font-mono">airlift publish</span> uploads.
        </p>
      </div>
      <table v-else class="w-full text-sm">
        <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
          <tr class="border-b border-border">
            <th class="px-2 py-2 font-medium">Error</th>
            <th class="px-2 py-2 font-medium">Events</th>
            <th class="px-2 py-2 font-medium">Devices</th>
            <th class="px-2 py-2 font-medium">Updates</th>
            <th class="px-2 py-2 font-medium">Last seen</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="g in groups"
            :key="g.id"
            class="cursor-pointer border-b border-border last:border-0 hover:bg-muted/40"
            data-testid="error-group"
            @click="open(g)"
          >
            <td class="max-w-[28rem] px-2 py-2">
              <div class="flex items-center gap-2">
                <UiBadge v-if="g.fatal" variant="outline"><span class="text-destructive">fatal</span></UiBadge>
                <span class="font-medium">{{ g.name }}</span>
                <span class="truncate text-muted-foreground">{{ g.message }}</span>
              </div>
              <p v-if="g.culprit" class="truncate font-mono text-xs text-muted-foreground">{{ g.culprit }}</p>
            </td>
            <td class="px-2 py-2 font-mono">{{ g.recent_events }}</td>
            <td class="px-2 py-2 font-mono">{{ g.recent_devices }}</td>
            <td class="px-2 py-2 font-mono">{{ g.updates }}</td>
            <td class="whitespace-nowrap px-2 py-2 text-muted-foreground">{{ timeAgo(g.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
    </UiCard>

    <UiModal
      :open="!!selected"
      :title="selected ? `${selected.group.name}: ${selected.group.message}` : ''"
      @close="selected = null"
    >
      <div v-if="selected" class="flex max-h-[70vh] flex-col gap-4 overflow-y-auto text-sm">
        <div class="flex flex-wrap gap-3 text-xs text-muted-foreground">
          <span>{{ selected.group.events }} events total</span>
          <span>first {{ timeAgo(selected.group.first_seen) }}</span>
          <span>last {{ timeAgo(selected.group.last_seen) }}</span>
        </div>
        <div v-if="latest">
          <div class="mb-1 flex items-center justify-between">
            <p class="text-xs uppercase tracking-wide text-muted-foreground">
              Latest stack · {{ latest.platform ?? "?" }} · update
              <span class="font-mono">{{ latest.update_id?.slice(0, 8) ?? "embedded" }}</span>
            </p>
            <button class="text-xs underline" @click="showRaw = !showRaw">
              {{ showRaw ? "symbolicated" : "raw" }}
            </button>
          </div>
          <pre
            v-if="showRaw || !latest.frames?.length"
            class="overflow-x-auto rounded-md bg-muted px-3 py-2 font-mono text-xs"
          >{{ latest.raw_stack ?? latest.message }}</pre>
          <ol v-else class="flex flex-col gap-1 rounded-md bg-muted px-3 py-2 font-mono text-xs">
            <li v-for="(f, i) in latest.frames" :key="i" :class="f.in_app ? '' : 'opacity-50'">
              <span class="text-foreground">{{ f.function ?? "<anonymous>" }}</span>
              <span class="text-muted-foreground"> {{ where(f) }}</span>
              <UiBadge v-if="f.symbolicated && f.in_app" variant="outline" class="ml-1">app</UiBadge>
            </li>
          </ol>
        </div>
        <div>
          <p class="mb-1 text-xs uppercase tracking-wide text-muted-foreground">Recent events</p>
          <ul class="flex flex-col divide-y divide-border">
            <li v-for="e in selected.events" :key="e.id" class="flex justify-between gap-2 py-1.5 text-xs">
              <span class="truncate">{{ e.message }}</span>
              <span class="whitespace-nowrap text-muted-foreground">
                {{ e.platform }} · <span class="font-mono">{{ e.update_id?.slice(0, 8) ?? "embedded" }}</span>
                · {{ e.client_id?.slice(0, 10) ?? "?" }} · {{ timeAgo(e.ts) }}
              </span>
            </li>
          </ul>
        </div>
      </div>
    </UiModal>
  </div>
</template>
