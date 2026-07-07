<script setup lang="ts">
// Organization-scoped settings. Instance-wide configuration (storage, TLS,
// Google sign-in, users) lives on the admin-only /settings page.
const route = useRoute();
const me = useMe();
const slug = computed(() => route.params.slug as string);
const host = computed(() => window.location.host);
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
