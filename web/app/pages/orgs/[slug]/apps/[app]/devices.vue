<script setup lang="ts">
// Devices: where the fleet is (map + countries/cities, 14-day active),
// which update each device runs (adoption), and recently seen devices.
import iso from "i18n-iso-countries";
import en from "i18n-iso-countries/langs/en.json";

iso.registerLocale(en);

const route = useRoute();
const api = useApi();
const slug = computed(() => route.params.slug as string);
const appSlug = computed(() => route.params.app as string);
const base = computed(() => `/api/v1/orgs/${slug.value}/apps/${appSlug.value}`);

interface GeoCount {
  country: string | null;
  city: string | null;
  devices: number;
}
interface Adoption {
  current_update_id: string | null;
  platform: string | null;
  runtime_version: string | null;
  devices: number;
}
interface Client {
  client_id: string;
  platform: string | null;
  runtime_version: string | null;
  channel: string | null;
  current_update_id: string | null;
  country: string | null;
  city: string | null;
  last_seen: string;
}

const countries = ref<GeoCount[]>([]);
const cities = ref<GeoCount[]>([]);
const adoption = ref<Adoption[]>([]);
const totalDevices = ref(0);
const clients = ref<Client[]>([]);
const loading = ref(true);

async function load() {
  loading.value = true;
  try {
    const [g, s, c] = await Promise.all([
      api.get<{ countries: GeoCount[]; cities: GeoCount[] }>(`${base.value}/geo`),
      api.get<{ adoption: Adoption[]; total_devices: number }>(`${base.value}/stats`),
      api.get<{ clients: Client[] }>(`${base.value}/clients`),
    ]);
    countries.value = g.countries;
    cities.value = g.cities;
    adoption.value = s.adoption;
    totalDevices.value = s.total_devices;
    clients.value = c.clients;
  } finally {
    loading.value = false;
  }
}
onMounted(load);
watch([slug, appSlug], load);

const countryName = (c: string | null) => (c ? iso.getName(c, "en") ?? c : "Unknown");
const pct = (n: number) => (totalDevices.value ? `${Math.round((100 * n) / totalDevices.value)}%` : "");
const shortId = (id: string | null) => (id ? id.slice(0, 8) : "embedded");
</script>

<template>
  <div>
    <AppTabs :slug="slug" :app="appSlug" />
    <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
    <div v-else class="flex flex-col gap-6">
      <UiCard
        title="Where devices are"
        :description="`${totalDevices} device${totalDevices === 1 ? '' : 's'} active in the last 14 days`"
      >
        <DeviceMap :counts="countries" />
        <div class="mt-4 grid grid-cols-2 gap-6">
          <div>
            <p class="mb-1 text-xs uppercase tracking-wide text-muted-foreground">Countries</p>
            <ul class="flex flex-col divide-y divide-border text-sm">
              <li v-for="c in countries.slice(0, 15)" :key="c.country ?? '?'" class="flex justify-between py-1.5">
                <span>{{ countryName(c.country) }}</span>
                <span class="font-mono text-xs text-muted-foreground">{{ c.devices }} · {{ pct(c.devices) }}</span>
              </li>
            </ul>
          </div>
          <div>
            <p class="mb-1 text-xs uppercase tracking-wide text-muted-foreground">Top cities</p>
            <p v-if="!cities.length" class="text-xs text-muted-foreground">
              City data needs a GeoIP City database (<span class="font-mono">observability.geoip_mmdb</span>)
              or a CDN that sends city headers.
            </p>
            <ul v-else class="flex flex-col divide-y divide-border text-sm">
              <li v-for="c in cities.slice(0, 15)" :key="`${c.country}-${c.city}`" class="flex justify-between py-1.5">
                <span>{{ c.city }} <span class="text-muted-foreground">· {{ c.country }}</span></span>
                <span class="font-mono text-xs text-muted-foreground">{{ c.devices }}</span>
              </li>
            </ul>
          </div>
        </div>
      </UiCard>

      <UiCard title="Adoption" description="Which update each recently active device runs.">
        <table class="w-full text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr class="border-b border-border">
              <th class="px-2 py-2 font-medium">Update</th>
              <th class="px-2 py-2 font-medium">Platform</th>
              <th class="px-2 py-2 font-medium">Runtime</th>
              <th class="px-2 py-2 font-medium">Devices</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in adoption" :key="`${a.current_update_id}-${a.platform}-${a.runtime_version}`" class="border-b border-border last:border-0">
              <td class="px-2 py-2 font-mono text-xs">{{ shortId(a.current_update_id) }}</td>
              <td class="px-2 py-2">{{ a.platform }}</td>
              <td class="px-2 py-2 font-mono text-xs text-muted-foreground">{{ a.runtime_version }}</td>
              <td class="px-2 py-2">
                <div class="flex items-center gap-2">
                  <div class="h-1.5 w-24 overflow-hidden rounded bg-muted">
                    <div class="h-full bg-primary" :style="{ width: pct(a.devices) }" />
                  </div>
                  <span class="font-mono text-xs">{{ a.devices }}</span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </UiCard>

      <UiCard title="Recently seen devices">
        <table class="w-full text-sm">
          <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
            <tr class="border-b border-border">
              <th class="px-2 py-2 font-medium">Device</th>
              <th class="px-2 py-2 font-medium">Platform</th>
              <th class="px-2 py-2 font-medium">Channel</th>
              <th class="px-2 py-2 font-medium">Update</th>
              <th class="px-2 py-2 font-medium">Location</th>
              <th class="px-2 py-2 font-medium">Seen</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in clients.slice(0, 100)" :key="c.client_id" class="border-b border-border last:border-0">
              <td class="px-2 py-2 font-mono text-xs">{{ c.client_id.length > 20 ? `${c.client_id.slice(0, 20)}…` : c.client_id }}</td>
              <td class="px-2 py-2">{{ c.platform }}</td>
              <td class="px-2 py-2">{{ c.channel }}</td>
              <td class="px-2 py-2 font-mono text-xs">{{ shortId(c.current_update_id) }}</td>
              <td class="px-2 py-2 text-xs">{{ c.city ? `${c.city}, ` : "" }}{{ c.country ?? "—" }}</td>
              <td class="whitespace-nowrap px-2 py-2 text-muted-foreground">{{ timeAgo(c.last_seen) }}</td>
            </tr>
          </tbody>
        </table>
      </UiCard>
    </div>
  </div>
</template>
