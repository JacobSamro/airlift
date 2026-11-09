<script setup lang="ts">
// Metrics: OTLP metrics from devices, rolled up per minute on the server;
// pick a metric and an aggregation to chart it.
const route = useRoute();
const api = useApi();
const slug = computed(() => route.params.slug as string);
const appSlug = computed(() => route.params.app as string);
const base = computed(() => `/api/v1/orgs/${slug.value}/apps/${appSlug.value}`);

interface MetricName {
  name: string;
  kind: "sum" | "gauge" | "histogram";
  unit: string | null;
  last_minute: string;
}
interface Bucket {
  bucket: string;
  count: number;
  sum: number;
  min: number | null;
  max: number | null;
}

const names = ref<MetricName[]>([]);
const selected = ref<MetricName | null>(null);
const windowSel = ref("24h");
const agg = ref<"sum" | "avg" | "max" | "min" | "count">("sum");
const series = ref<Bucket[]>([]);

async function loadNames() {
  names.value = (await api.get<{ metrics: MetricName[] }>(`${base.value}/metrics`)).metrics;
  if (!selected.value && names.value.length) pick(names.value[0]);
}
async function loadSeries() {
  if (!selected.value) return;
  const q = new URLSearchParams({ name: selected.value.name, window: windowSel.value });
  series.value = (await api.get<{ series: Bucket[] }>(`${base.value}/metrics/series?${q}`)).series;
}
function pick(m: MetricName) {
  selected.value = m;
  // Counters are summed; gauges/histograms are more useful averaged.
  agg.value = m.kind === "sum" ? "sum" : "avg";
  loadSeries();
}
onMounted(loadNames);
watch([slug, appSlug], () => {
  selected.value = null;
  loadNames();
});
watch(windowSel, loadSeries);

const points = computed(() =>
  series.value.map((b) => ({
    label: b.bucket,
    value:
      agg.value === "sum"
        ? b.sum
        : agg.value === "count"
          ? b.count
          : agg.value === "max"
            ? (b.max ?? 0)
            : agg.value === "min"
              ? (b.min ?? 0)
              : b.count
                ? b.sum / b.count
                : 0,
  })),
);
</script>

<template>
  <div>
    <AppTabs :slug="slug" :app="appSlug" />
    <h2 class="mb-4 text-lg font-semibold tracking-tight">Metrics</h2>

    <UiCard v-if="!names.length">
      <div class="py-10 text-center text-sm text-muted-foreground">
        No metrics in the last 7 days. Point an OTLP/HTTP JSON metric exporter at
        <span class="font-mono">/u/&lt;app-id&gt;/otlp/v1/metrics</span> (delta temporality preferred).
      </div>
    </UiCard>

    <div v-else class="grid grid-cols-4 gap-6">
      <UiCard class="col-span-1">
        <ul class="flex flex-col gap-1">
          <li v-for="m in names" :key="m.name">
            <button
              class="flex w-full flex-col rounded-lg px-3 py-2 text-left text-sm transition-colors"
              :class="selected?.name === m.name ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted/50'"
              @click="pick(m)"
            >
              <span class="font-mono">{{ m.name }}</span>
              <span class="text-xs">{{ m.kind }}{{ m.unit ? ` · ${m.unit}` : "" }}</span>
            </button>
          </li>
        </ul>
      </UiCard>
      <UiCard v-if="selected" class="col-span-3" :title="selected.name">
        <template #header>
          <div class="flex gap-2">
            <select v-model="agg" class="h-8 rounded-md border border-border bg-background px-2 text-sm">
              <option value="sum">sum</option>
              <option value="avg">avg</option>
              <option value="max">max</option>
              <option value="min">min</option>
              <option value="count">count</option>
            </select>
            <select v-model="windowSel" class="h-8 rounded-md border border-border bg-background px-2 text-sm">
              <option value="1h">1h (per minute)</option>
              <option value="24h">24h (per hour)</option>
              <option value="7d">7d (per day)</option>
              <option value="14d">14d (per day)</option>
            </select>
          </div>
        </template>
        <p v-if="!points.length" class="py-8 text-center text-sm text-muted-foreground">No data in this window.</p>
        <SeriesChart v-else :points="points" :unit="selected.unit" />
      </UiCard>
    </div>
  </div>
</template>
