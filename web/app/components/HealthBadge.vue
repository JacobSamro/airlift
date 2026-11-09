<script setup lang="ts">
// Health badge for an update group: share of devices that crashed launching
// it (reported via Expo-Recent-Failed-Update-IDs) out of those that tried it.
const props = defineProps<{ health: Health | null | undefined }>();

const tone = computed(
  () =>
    ({
      healthy: "border-emerald-500/40 text-emerald-500",
      degraded: "border-amber-500/40 text-amber-500",
      unhealthy: "border-red-500/50 text-red-500",
      insufficient: "border-border text-muted-foreground",
    })[props.health?.status ?? "insufficient"],
);

const label = computed(() => {
  const h = props.health;
  if (!h || h.devices === 0) return "no data";
  const pct = (h.failure_rate * 100).toFixed(h.failure_rate < 0.1 ? 1 : 0);
  return `${pct}% crash`;
});

const title = computed(() => {
  const h = props.health;
  if (!h || h.devices === 0) return "No device has reported launching this update yet.";
  const base = `${h.failed} of ${h.devices} devices failed to launch it`;
  return h.status === "insufficient" ? `${base} (too few devices to judge)` : `${base} — ${h.status}`;
});
</script>

<template>
  <span
    :title="title"
    class="inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium"
    :class="tone"
    data-testid="health-badge"
  >
    <span class="size-1.5 rounded-full bg-current" />
    {{ label }}
  </span>
</template>
