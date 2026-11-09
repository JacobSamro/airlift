<script setup lang="ts">
// Tabs across an app's pages: overview (channels/updates), devices (map,
// adoption), errors (symbolicated crash groups), logs and metrics (OTLP).
const props = defineProps<{ slug: string; app: string }>();
const route = useRoute();

const base = computed(() => `/orgs/${props.slug}/apps/${props.app}`);
const tabs = computed(() => [
  { to: base.value, label: "Overview", icon: "rocket" },
  { to: `${base.value}/devices`, label: "Devices", icon: "globe" },
  { to: `${base.value}/errors`, label: "Errors", icon: "alert" },
  { to: `${base.value}/logs`, label: "Logs", icon: "terminal" },
  { to: `${base.value}/metrics`, label: "Metrics", icon: "grid" },
]);
</script>

<template>
  <div class="mb-6">
    <NuxtLink
      :to="`/orgs/${slug}`"
      class="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
    >
      ← {{ slug }}
    </NuxtLink>
    <nav class="flex gap-1 border-b border-border">
      <NuxtLink
        v-for="t in tabs"
        :key="t.to"
        :to="t.to"
        class="-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition-colors"
        :class="
          route.path === t.to
            ? 'border-primary font-medium text-foreground'
            : 'border-transparent text-muted-foreground hover:text-foreground'
        "
        :data-testid="`app-tab-${t.label.toLowerCase()}`"
      >
        <UiIcon :name="t.icon" :size="14" /> {{ t.label }}
      </NuxtLink>
    </nav>
  </div>
</template>
