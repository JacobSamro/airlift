<script setup lang="ts">
// Minimal SVG line chart for a metric series (one value per bucket).
const props = defineProps<{ points: { label: string; value: number }[]; unit?: string | null }>();

const W = 800;
const H = 220;
const PAD = { l: 48, r: 12, t: 12, b: 28 };

const max = computed(() => Math.max(0, ...props.points.map((p) => p.value)));
const min = computed(() => Math.min(0, ...props.points.map((p) => p.value)));
const x = (i: number) =>
  PAD.l + (props.points.length <= 1 ? 0.5 : i / (props.points.length - 1)) * (W - PAD.l - PAD.r);
const y = (v: number) => {
  const span = max.value - min.value || 1;
  return PAD.t + (1 - (v - min.value) / span) * (H - PAD.t - PAD.b);
};
const path = computed(() =>
  props.points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(" "),
);
const fmt = (v: number) =>
  Math.abs(v) >= 1000 ? `${(v / 1000).toFixed(1)}k` : Number.isInteger(v) ? `${v}` : v.toFixed(2);
const ticks = computed(() => [max.value, (max.value + min.value) / 2, min.value]);
const labelEvery = computed(() => Math.max(1, Math.ceil(props.points.length / 8)));
const hover = ref<number | null>(null);
</script>

<template>
  <svg :viewBox="`0 0 ${W} ${H}`" class="h-auto w-full" data-testid="series-chart" @mouseleave="hover = null">
    <g v-for="t in ticks" :key="t">
      <line :x1="PAD.l" :x2="W - PAD.r" :y1="y(t)" :y2="y(t)" stroke="var(--border)" stroke-dasharray="3 3" />
      <text :x="PAD.l - 6" :y="y(t) + 4" text-anchor="end" font-size="11" fill="var(--muted-foreground)">
        {{ fmt(t) }}
      </text>
    </g>
    <path :d="path" fill="none" stroke="var(--primary)" stroke-width="2" />
    <g v-for="(p, i) in points" :key="p.label">
      <circle :cx="x(i)" :cy="y(p.value)" r="6" fill="transparent" @mouseenter="hover = i" />
      <circle v-if="hover === i" :cx="x(i)" :cy="y(p.value)" r="3.5" fill="var(--primary)" />
      <text
        v-if="i % labelEvery === 0"
        :x="x(i)"
        :y="H - 8"
        text-anchor="middle"
        font-size="10"
        fill="var(--muted-foreground)"
      >
        {{ p.label.slice(5).replace("T", " ") }}
      </text>
    </g>
    <text
      v-if="hover !== null && points[hover]"
      :x="Math.min(x(hover) + 8, W - 160)"
      :y="PAD.t + 12"
      font-size="12"
      fill="var(--foreground)"
    >
      {{ points[hover].label.replace("T", " ") }}: {{ fmt(points[hover].value) }}{{ unit ? ` ${unit}` : "" }}
    </text>
  </svg>
</template>
