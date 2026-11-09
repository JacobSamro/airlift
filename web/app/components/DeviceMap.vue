<script setup lang="ts">
// World choropleth of active devices per country (ISO 3166-1 alpha-2 counts
// from /geo). Shapes: world-atlas 110m (keyed by ISO numeric), projected
// with d3-geo's Natural Earth projection into an SVG; no tiles, no network.
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import countries110m from "world-atlas/countries-110m.json";
import iso from "i18n-iso-countries";

const props = defineProps<{ counts: { country: string | null; devices: number }[] }>();

const WIDTH = 960;
const HEIGHT = 480;

// ISO numeric (world-atlas feature id, zero-padded) → device count.
const byNumeric = computed(() => {
  const m = new Map<string, { alpha2: string; devices: number }>();
  for (const c of props.counts) {
    if (!c.country) continue;
    const num = iso.alpha2ToNumeric(c.country);
    if (num) m.set(String(num).padStart(3, "0"), { alpha2: c.country, devices: c.devices });
  }
  return m;
});
const max = computed(() => Math.max(1, ...props.counts.map((c) => c.devices)));

const shapes = computed(() => {
  const topo = countries110m as any;
  const fc = feature(topo, topo.objects.countries) as any;
  const projection = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], fc);
  const path = geoPath(projection);
  return fc.features.map((f: any) => {
    const hit = byNumeric.value.get(String(f.id).padStart(3, "0"));
    return {
      id: f.id as string,
      d: path(f) ?? "",
      name: f.properties?.name as string,
      devices: hit?.devices ?? 0,
    };
  });
});

// Log-ish scale so one big country doesn't wash out the rest.
function fill(devices: number): string {
  if (!devices) return "var(--muted)";
  const t = Math.log1p(devices) / Math.log1p(max.value);
  return `color-mix(in oklab, var(--primary) ${Math.round(20 + 80 * t)}%, var(--muted))`;
}

const hover = ref<{ name: string; devices: number } | null>(null);
</script>

<template>
  <div class="relative">
    <svg :viewBox="`0 0 ${WIDTH} ${HEIGHT}`" class="h-auto w-full" data-testid="device-map">
      <path
        v-for="s in shapes"
        :key="s.id"
        :d="s.d"
        :fill="fill(s.devices)"
        stroke="var(--border)"
        stroke-width="0.5"
        class="transition-opacity hover:opacity-80"
        @mouseenter="hover = { name: s.name, devices: s.devices }"
        @mouseleave="hover = null"
      >
        <title>{{ s.name }}: {{ s.devices }} device{{ s.devices === 1 ? "" : "s" }}</title>
      </path>
    </svg>
    <div
      v-if="hover"
      class="pointer-events-none absolute left-3 top-3 rounded-md border border-border bg-card px-2 py-1 text-xs"
    >
      {{ hover.name }} · <span class="font-mono">{{ hover.devices }}</span> devices
    </div>
  </div>
</template>
