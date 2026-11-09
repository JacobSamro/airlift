<script setup lang="ts">
// App detail: update URL & certificate, channels (branch pointer, auto/gated,
// releases, rollback), the update-group timeline with promote, and CLI help.
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";

const route = useRoute();
const router = useRouter();
const api = useApi();
const me = useMe();
const { confirm } = useConfirm();

const slug = computed(() => route.params.slug as string);
const appSlug = computed(() => route.params.app as string);

const app = ref<App | null>(null);
const branches = ref<Branch[]>([]);
const channels = ref<Channel[]>([]);
const updates = ref<UpdateGroup[]>([]);
const loading = ref(true);
const updatesLoading = ref(false);
const error = ref("");

const role = computed(() => me.value?.orgs.find((o) => o.slug === slug.value)?.role);
const isOwner = computed(() => role.value === "owner");

const origin = ref("");
onMounted(() => {
  origin.value = window.location.origin;
});
const updateUrl = computed(() => (app.value ? `${origin.value}/u/${app.value.id}/manifest` : ""));
const certUrl = computed(() => `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/certificate`);

const copied = ref(false);
function copyUrl() {
  if (updateUrl.value) navigator.clipboard?.writeText(updateUrl.value);
  copied.value = true;
  setTimeout(() => (copied.value = false), 1500);
}

// ── Loading ────────────────────────────────────────────────────────────────

async function load() {
  loading.value = true;
  try {
    const res = await api.get<{ app: App; branches: Branch[]; channels: Channel[] }>(
      `/api/v1/orgs/${slug.value}/apps/${appSlug.value}`,
    );
    app.value = res.app;
    branches.value = res.branches;
    channels.value = res.channels;
  } finally {
    loading.value = false;
  }
}

const branchFilter = ref("all");
async function loadUpdates() {
  updatesLoading.value = true;
  try {
    const q = branchFilter.value !== "all" ? `?branch=${encodeURIComponent(branchFilter.value)}` : "";
    updates.value = (
      await api.get<{ updates: UpdateGroup[] }>(
        `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/updates${q}`,
      )
    ).updates;
  } finally {
    updatesLoading.value = false;
  }
}

onMounted(() => {
  load();
  loadUpdates();
});
watch([slug, appSlug], () => {
  load();
  loadUpdates();
});
watch(branchFilter, loadUpdates);

// ── App-level actions ──────────────────────────────────────────────────────

async function deleteApp() {
  if (!app.value) return;
  if (
    !(await confirm({
      title: "Delete app",
      message: `Delete "${app.value.name}" and all of its branches, channels and updates? Devices will stop receiving updates. This cannot be undone.`,
      confirmText: "Delete app",
      destructive: true,
    }))
  )
    return;
  try {
    await api.del(`/api/v1/orgs/${slug.value}/apps/${appSlug.value}`);
    await router.push(`/orgs/${slug.value}`);
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// ── Channels ───────────────────────────────────────────────────────────────

const showNewChannel = ref(false);
const newChannel = reactive({ name: "", branch: "", auto_release: true });

async function createChannel() {
  error.value = "";
  try {
    const body: Record<string, unknown> = {
      name: newChannel.name,
      auto_release: newChannel.auto_release,
    };
    if (newChannel.branch) body.branch = newChannel.branch;
    await api.post(`/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels`, body);
    showNewChannel.value = false;
    newChannel.name = "";
    newChannel.branch = "";
    newChannel.auto_release = true;
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function setChannelBranch(ch: Channel, branch: unknown) {
  if (!branch || branch === ch.branch) return;
  error.value = "";
  try {
    await api.patch(`/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${ch.name}`, {
      branch: String(branch),
    });
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function setAutoRelease(ch: Channel, value: boolean) {
  error.value = "";
  try {
    await api.patch(`/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${ch.name}`, {
      auto_release: value,
    });
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function deleteChannel(ch: Channel) {
  if (
    !(await confirm({
      title: "Delete channel",
      message: `Delete channel "${ch.name}"? Builds pointing at it will stop receiving updates.`,
      confirmText: "Delete",
      destructive: true,
    }))
  )
    return;
  try {
    await api.del(`/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${ch.name}`);
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// Channel rollback: pick a runtime from the channel's releases, confirm, POST.
const rollbackChannel = ref<Channel | null>(null);
const rollbackRuntime = ref("");

function openRollback(ch: Channel) {
  rollbackChannel.value = ch;
  rollbackRuntime.value = ch.releases[0]?.runtime_version ?? "";
}

async function submitRollback() {
  const ch = rollbackChannel.value;
  if (!ch || !rollbackRuntime.value) return;
  if (
    !(await confirm({
      title: "Roll back channel",
      message: `Roll back "${ch.name}" for runtime ${rollbackRuntime.value}? Devices on that runtime will receive the previous update.`,
      confirmText: "Roll back",
      destructive: true,
    }))
  )
    return;
  error.value = "";
  try {
    await api.post(
      `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${ch.name}/rollback`,
      { runtime_version: rollbackRuntime.value },
    );
    rollbackChannel.value = null;
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// ── Promote ────────────────────────────────────────────────────────────────

const promoteUpdate = ref<UpdateGroup | null>(null);
const promoteChannelName = ref("");
// Below 100 the promote becomes a progressive rollout.
const promotePercent = ref(100);

function openPromote(u: UpdateGroup) {
  promoteUpdate.value = u;
  promoteChannelName.value = channels.value[0]?.name ?? "";
  promotePercent.value = 100;
}

async function submitPromote() {
  const u = promoteUpdate.value;
  if (!u || !promoteChannelName.value) return;
  error.value = "";
  const base = `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${promoteChannelName.value}`;
  try {
    if (promotePercent.value < 100) {
      await api.post(`${base}/rollout`, { group_id: u.id, percent: Number(promotePercent.value) });
    } else {
      await api.post(`${base}/promote`, { group_id: u.id });
    }
    promoteUpdate.value = null;
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// ── Rollouts ───────────────────────────────────────────────────────────────

const rolloutTarget = ref<{ ch: Channel; r: ChannelRelease } | null>(null);
const rolloutPercent = ref(0);

function openRollout(ch: Channel, r: ChannelRelease) {
  rolloutTarget.value = { ch, r };
  rolloutPercent.value = r.rollout_percent ?? 100;
}

async function submitRollout(percent: number) {
  const t = rolloutTarget.value;
  if (!t) return;
  error.value = "";
  try {
    await api.patch(
      `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/channels/${t.ch.name}/rollout`,
      { runtime_version: t.r.runtime_version, percent: Number(percent) },
    );
    rolloutTarget.value = null;
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// ── Rollback to embedded ───────────────────────────────────────────────────

const showEmbedded = ref(false);
const embBranch = ref("");
const embRuntime = ref("");

async function submitEmbedded() {
  if (!embBranch.value || !embRuntime.value) return;
  if (
    !(await confirm({
      title: "Roll back to embedded",
      message: `Publish a rollback-to-embedded update on "${embBranch.value}" for runtime ${embRuntime.value}? Devices will revert to the update embedded in their binary.`,
      confirmText: "Roll back to embedded",
      destructive: true,
    }))
  )
    return;
  error.value = "";
  try {
    await api.post(
      `/api/v1/orgs/${slug.value}/apps/${appSlug.value}/branches/${embBranch.value}/rollback-to-embedded`,
      { runtime_version: embRuntime.value },
    );
    showEmbedded.value = false;
    embBranch.value = "";
    embRuntime.value = "";
    await Promise.all([load(), loadUpdates()]);
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

const showHelp = ref(false);
const shortId = (id: string) => id.slice(0, 8);
const gitRef = (u: UpdateGroup) =>
  u.git_branch || u.git_commit
    ? `${u.git_branch ?? "?"}@${(u.git_commit ?? "").slice(0, 7) || "?"}`
    : null;
</script>

<template>
  <div>
    <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
    <template v-else-if="app">
      <!-- Header -->
      <div class="mb-6">
        <NuxtLink
          :to="`/orgs/${slug}`"
          class="mb-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          ← {{ slug }}
        </NuxtLink>
        <div class="flex items-start justify-between gap-4">
          <div>
            <div class="flex items-center gap-3">
              <h1 class="text-2xl font-semibold tracking-tight">{{ app.name }}</h1>
              <UiBadge variant="outline"><span class="font-mono">{{ app.slug }}</span></UiBadge>
            </div>
            <div class="mt-2 flex items-center gap-2 text-sm text-muted-foreground">
              <span class="font-mono text-xs">{{ updateUrl || `/u/${app.id}/manifest` }}</span>
              <button
                class="inline-flex items-center text-muted-foreground transition-colors hover:text-foreground"
                title="Copy update URL"
                @click="copyUrl"
              >
                <UiIcon :name="copied ? 'check' : 'copy'" :size="14" />
              </button>
            </div>
          </div>
          <div class="flex shrink-0 items-center gap-2">
            <a :href="certUrl" download>
              <UiButton variant="outline" size="sm">
                <UiIcon name="download" :size="14" /> Certificate
              </UiButton>
            </a>
            <UiButton
              v-if="isOwner"
              variant="destructive"
              size="sm"
              data-testid="delete-app"
              @click="deleteApp"
            >
              <UiIcon name="trash" :size="14" /> Delete
            </UiButton>
          </div>
        </div>
      </div>

      <p v-if="error" class="mb-4 text-sm text-red-400">{{ error }}</p>

      <!-- Channels -->
      <div class="mb-6">
        <div class="mb-3 flex items-center justify-between">
          <h2 class="text-lg font-semibold tracking-tight">Channels</h2>
          <UiButton size="sm" data-testid="new-channel" @click="showNewChannel = true">
            <UiIcon name="plus" :size="14" /> New channel
          </UiButton>
        </div>

        <UiCard v-if="!channels.length">
          <div class="flex flex-col items-center gap-2 py-8 text-center">
            <UiIcon name="radio" :size="28" class="text-muted-foreground" />
            <p class="font-medium">No channels yet</p>
            <p class="text-sm text-muted-foreground">
              Channels are what device builds point at. Create one and map it to a branch.
            </p>
          </div>
        </UiCard>

        <div v-else class="grid grid-cols-2 gap-4">
          <UiCard v-for="ch in channels" :key="ch.id">
            <div class="flex items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <UiIcon name="radio" :size="16" class="text-muted-foreground" />
                <span class="font-medium">{{ ch.name }}</span>
                <UiBadge :variant="ch.auto_release ? 'primary' : 'outline'">
                  {{ ch.auto_release ? "auto" : "gated" }}
                </UiBadge>
              </div>
              <UiButton variant="ghost" size="sm" title="Delete channel" @click="deleteChannel(ch)">
                <UiIcon name="trash" :size="14" />
              </UiButton>
            </div>

            <div class="mt-4 flex flex-col gap-3">
              <div class="flex items-center justify-between gap-2">
                <span class="text-sm text-muted-foreground">Branch</span>
                <Select
                  :model-value="ch.branch ?? undefined"
                  @update:model-value="(v) => setChannelBranch(ch, v)"
                >
                  <SelectTrigger class="h-8 w-44" :data-testid="`channel-branch-${ch.name}`">
                    <SelectValue placeholder="No branch" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="b in branches" :key="b.id" :value="b.name">{{ b.name }}</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div class="flex items-center justify-between gap-2">
                <div>
                  <span class="text-sm text-muted-foreground">Auto release</span>
                  <p class="text-xs text-muted-foreground/70">
                    {{ ch.auto_release ? "New publishes go live immediately." : "Publishes wait for a promote." }}
                  </p>
                </div>
                <Switch
                  :model-value="ch.auto_release"
                  :data-testid="`channel-auto-${ch.name}`"
                  @update:model-value="(v: boolean) => setAutoRelease(ch, v)"
                />
              </div>

              <div v-if="!ch.branch" class="rounded-[var(--radius)] border border-dashed border-border px-3 py-2 text-xs text-muted-foreground">
                Not pointing at a branch — devices on this channel receive nothing. Pick a branch above.
              </div>

              <div v-else>
                <p class="mb-1 text-xs uppercase tracking-wide text-muted-foreground">Releases</p>
                <p v-if="!ch.releases.length" class="text-xs text-muted-foreground">
                  Nothing released yet.
                </p>
                <ul v-else class="flex flex-col divide-y divide-border text-sm">
                  <li
                    v-for="r in ch.releases"
                    :key="r.runtime_version"
                    class="flex items-center justify-between py-1.5"
                  >
                    <span class="font-mono text-xs">{{ r.runtime_version }}</span>
                    <span class="flex items-center gap-2 text-xs text-muted-foreground">
                      <button
                        v-if="r.rollout_percent !== null"
                        :title="`Rolling out to ${r.rollout_percent}% of devices — adjust`"
                        :data-testid="`rollout-${ch.name}-${r.runtime_version}`"
                        @click="openRollout(ch, r)"
                      >
                        <UiBadge variant="primary">{{ r.rollout_percent }}%</UiBadge>
                      </button>
                      <span class="font-mono">{{ shortId(r.group_id) }}</span>
                      · {{ timeAgo(r.released_at) }}
                    </span>
                  </li>
                </ul>
              </div>

              <div class="flex justify-end border-t border-border pt-3">
                <UiButton
                  variant="outline"
                  size="sm"
                  :disabled="!ch.releases.length"
                  :data-testid="`channel-rollback-${ch.name}`"
                  @click="openRollback(ch)"
                >
                  <UiIcon name="rotate" :size="14" /> Roll back
                </UiButton>
              </div>
            </div>
          </UiCard>
        </div>
      </div>

      <!-- Updates timeline -->
      <div class="mb-6">
        <div class="mb-3 flex items-center justify-between gap-2">
          <h2 class="text-lg font-semibold tracking-tight">Updates</h2>
          <div class="flex items-center gap-2">
            <Select v-model="branchFilter">
              <SelectTrigger class="h-8 w-44" data-testid="updates-branch-filter">
                <SelectValue placeholder="All branches" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All branches</SelectItem>
                <SelectItem v-for="b in branches" :key="b.id" :value="b.name">{{ b.name }}</SelectItem>
              </SelectContent>
            </Select>
            <UiButton
              variant="outline"
              size="sm"
              class="text-destructive hover:text-destructive"
              :disabled="!branches.length"
              data-testid="rollback-embedded"
              @click="showEmbedded = true"
            >
              <UiIcon name="alert" :size="14" /> Roll back to embedded…
            </UiButton>
          </div>
        </div>

        <UiCard>
          <div v-if="updatesLoading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
          <div v-else-if="!updates.length" class="flex flex-col items-center gap-2 py-10 text-center">
            <UiIcon name="rocket" :size="28" class="text-muted-foreground" />
            <p class="font-medium">No updates {{ branchFilter !== "all" ? `on ${branchFilter}` : "yet" }}</p>
            <p class="text-sm text-muted-foreground">Publish your first update from your Expo project:</p>
            <p class="font-mono text-xs text-muted-foreground">npx airlift-cli publish --branch production</p>
          </div>
          <table v-else class="w-full text-sm">
            <thead class="text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr class="border-b border-border">
                <th class="px-3 py-2 font-medium">Update</th>
                <th class="px-3 py-2 font-medium">Branch</th>
                <th class="px-3 py-2 font-medium">Runtime</th>
                <th class="px-3 py-2 font-medium">Platforms</th>
                <th class="px-3 py-2 font-medium">Message</th>
                <th class="px-3 py-2 font-medium">Published</th>
                <th class="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in updates" :key="u.id" class="border-b border-border last:border-0">
                <td class="px-3 py-3">
                  <div class="flex items-center gap-2">
                    <span class="font-mono text-xs">{{ shortId(u.id) }}</span>
                    <UiBadge v-if="u.group_type === 'rollback_to_embedded'" variant="outline">
                      <span class="text-destructive">rollback</span>
                    </UiBadge>
                  </div>
                </td>
                <td class="px-3 py-3">
                  <UiBadge variant="outline"><span class="font-mono">{{ u.branch }}</span></UiBadge>
                </td>
                <td class="px-3 py-3 font-mono text-xs text-muted-foreground">{{ u.runtime_version }}</td>
                <td class="px-3 py-3">
                  <div class="flex gap-1">
                    <UiBadge v-for="p in u.platforms" :key="p">{{ p }}</UiBadge>
                  </div>
                </td>
                <td class="max-w-56 px-3 py-3">
                  <p class="truncate" :title="u.message ?? ''">{{ u.message || "—" }}</p>
                  <p v-if="gitRef(u)" class="truncate font-mono text-xs text-muted-foreground">
                    {{ gitRef(u) }}
                  </p>
                </td>
                <td class="whitespace-nowrap px-3 py-3 text-muted-foreground">{{ timeAgo(u.created_at) }}</td>
                <td class="px-3 py-3 text-right">
                  <UiButton
                    variant="ghost"
                    size="sm"
                    :disabled="!channels.length"
                    :title="channels.length ? 'Promote to channel…' : 'Create a channel first'"
                    @click="openPromote(u)"
                  >
                    <UiIcon name="upload" :size="14" /> Promote
                  </UiButton>
                </td>
              </tr>
            </tbody>
          </table>
        </UiCard>
      </div>

      <!-- Publish help -->
      <div class="rounded-xl border border-border bg-card text-card-foreground">
        <button
          class="flex w-full items-center justify-between px-6 py-4 text-left text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
          @click="showHelp = !showHelp"
        >
          <span class="flex items-center gap-2"><UiIcon name="terminal" :size="16" /> Publishing from the CLI</span>
          <UiIcon name="chevron-down" :size="16" :class="showHelp ? 'rotate-180' : ''" class="transition-transform" />
        </button>
        <div v-if="showHelp" class="flex flex-col gap-3 border-t border-border px-6 py-4 text-sm">
          <div>
            <p class="mb-1 text-xs text-muted-foreground">Wire up your Expo project once:</p>
            <pre class="overflow-x-auto rounded-[var(--radius)] bg-muted px-3 py-2 font-mono text-xs">npx airlift-cli init --server {{ origin }} --org {{ slug }} --app {{ app.slug }}</pre>
          </div>
          <div>
            <p class="mb-1 text-xs text-muted-foreground">Then publish an update to a branch:</p>
            <pre class="overflow-x-auto rounded-[var(--radius)] bg-muted px-3 py-2 font-mono text-xs">npx airlift-cli publish --branch production</pre>
          </div>
          <p class="text-xs text-muted-foreground">
            Authenticate with an access token: set <span class="font-mono">AIRLIFT_TOKEN</span> in your
            environment (create one under
            <NuxtLink to="/tokens" class="underline">Access Tokens</NuxtLink>).
          </p>
        </div>
      </div>

      <!-- New channel dialog -->
      <UiModal :open="showNewChannel" title="New channel" @close="showNewChannel = false">
        <form class="flex flex-col gap-4" @submit.prevent="createChannel">
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Name</label>
            <UiInput v-model="newChannel.name" placeholder="production" required data-testid="channel-name" />
            <p class="text-xs text-muted-foreground">The channel name baked into your device builds.</p>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Branch</label>
            <Select v-model="newChannel.branch">
              <SelectTrigger class="w-full" data-testid="channel-branch">
                <SelectValue placeholder="None (set later)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="b in branches" :key="b.id" :value="b.name">{{ b.name }}</SelectItem>
              </SelectContent>
            </Select>
            <p v-if="!branches.length" class="text-xs text-muted-foreground">
              No branches yet — they appear after the first publish.
            </p>
          </div>
          <div class="flex items-center justify-between gap-2">
            <div>
              <label class="text-sm font-medium">Auto release</label>
              <p class="text-xs text-muted-foreground">Serve new publishes immediately.</p>
            </div>
            <Switch v-model="newChannel.auto_release" data-testid="channel-auto" />
          </div>
          <div class="flex justify-end gap-2">
            <UiButton variant="outline" type="button" @click="showNewChannel = false">Cancel</UiButton>
            <UiButton type="submit">Create</UiButton>
          </div>
        </form>
      </UiModal>

      <!-- Rollback channel dialog -->
      <UiModal
        :open="!!rollbackChannel"
        :title="`Roll back ${rollbackChannel?.name ?? ''}`"
        @close="rollbackChannel = null"
      >
        <form class="flex flex-col gap-4" @submit.prevent="submitRollback">
          <p class="text-sm text-muted-foreground">
            Moves the channel's pointer back to the previous update for one runtime version.
          </p>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Runtime version</label>
            <Select v-model="rollbackRuntime">
              <SelectTrigger class="w-full" data-testid="rollback-runtime">
                <SelectValue placeholder="Select a runtime…" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="r in rollbackChannel?.releases ?? []"
                  :key="r.runtime_version"
                  :value="r.runtime_version"
                >
                  {{ r.runtime_version }} · currently {{ shortId(r.group_id) }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="flex justify-end gap-2">
            <UiButton variant="outline" type="button" @click="rollbackChannel = null">Cancel</UiButton>
            <UiButton variant="destructive" type="submit" :disabled="!rollbackRuntime">Roll back</UiButton>
          </div>
        </form>
      </UiModal>

      <!-- Promote dialog -->
      <UiModal
        :open="!!promoteUpdate"
        title="Promote to channel"
        @close="promoteUpdate = null"
      >
        <form class="flex flex-col gap-4" @submit.prevent="submitPromote">
          <p class="text-sm text-muted-foreground">
            Release update
            <span class="font-mono text-xs">{{ promoteUpdate ? shortId(promoteUpdate.id) : "" }}</span>
            (runtime <span class="font-mono text-xs">{{ promoteUpdate?.runtime_version }}</span>) to a channel.
          </p>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Channel</label>
            <Select v-model="promoteChannelName">
              <SelectTrigger class="w-full" data-testid="promote-channel">
                <SelectValue placeholder="Select a channel…" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="ch in channels" :key="ch.id" :value="ch.name">
                  {{ ch.name }}{{ ch.branch ? ` · ${ch.branch}` : "" }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Rollout</label>
            <div class="flex items-center gap-3">
              <input
                v-model.number="promotePercent"
                type="range"
                min="1"
                max="100"
                class="flex-1"
                data-testid="promote-percent"
              />
              <span class="w-12 text-right font-mono text-sm">{{ promotePercent }}%</span>
            </div>
            <p class="text-xs text-muted-foreground">
              {{
                promotePercent < 100
                  ? "Only this share of devices gets it; the rest keep the current release. Devices stay in as you grow it."
                  : "Every device on the channel gets it."
              }}
            </p>
          </div>
          <div class="flex justify-end gap-2">
            <UiButton variant="outline" type="button" @click="promoteUpdate = null">Cancel</UiButton>
            <UiButton type="submit" :disabled="!promoteChannelName">
              {{ promotePercent < 100 ? `Roll out to ${promotePercent}%` : "Promote" }}
            </UiButton>
          </div>
        </form>
      </UiModal>

      <!-- Adjust rollout dialog -->
      <UiModal
        :open="!!rolloutTarget"
        :title="`Rollout on ${rolloutTarget?.ch.name ?? ''}`"
        @close="rolloutTarget = null"
      >
        <form class="flex flex-col gap-4" @submit.prevent="submitRollout(rolloutPercent)">
          <p class="text-sm text-muted-foreground">
            Update <span class="font-mono text-xs">{{ rolloutTarget ? shortId(rolloutTarget.r.group_id) : "" }}</span>
            (runtime <span class="font-mono text-xs">{{ rolloutTarget?.r.runtime_version }}</span>) is
            reaching {{ rolloutTarget?.r.rollout_percent }}% of devices. Devices already in stay in when
            you grow it; to pull it from devices, roll the channel back.
          </p>
          <div class="flex items-center gap-3">
            <input
              v-model.number="rolloutPercent"
              type="range"
              min="1"
              max="100"
              class="flex-1"
              data-testid="rollout-percent"
            />
            <span class="w-12 text-right font-mono text-sm">{{ rolloutPercent }}%</span>
          </div>
          <div class="flex justify-end gap-2">
            <UiButton variant="outline" type="button" @click="rolloutTarget = null">Cancel</UiButton>
            <UiButton variant="outline" type="button" @click="submitRollout(100)">Complete (100%)</UiButton>
            <UiButton type="submit">Set {{ rolloutPercent }}%</UiButton>
          </div>
        </form>
      </UiModal>

      <!-- Rollback to embedded dialog -->
      <UiModal :open="showEmbedded" title="Roll back to embedded" @close="showEmbedded = false">
        <form class="flex flex-col gap-4" @submit.prevent="submitEmbedded">
          <p class="text-sm text-muted-foreground">
            Publishes a special update on a branch that tells devices to revert to the update
            embedded in their binary. Channels pointing at the branch pick it up like any publish.
          </p>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Branch</label>
            <Select v-model="embBranch">
              <SelectTrigger class="w-full" data-testid="embedded-branch">
                <SelectValue placeholder="Select a branch…" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="b in branches" :key="b.id" :value="b.name">{{ b.name }}</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-sm font-medium">Runtime version</label>
            <UiInput v-model="embRuntime" placeholder="1.0.0" required data-testid="embedded-runtime" />
            <p class="text-xs text-muted-foreground">Only devices on this runtime version revert.</p>
          </div>
          <div class="flex justify-end gap-2">
            <UiButton variant="outline" type="button" @click="showEmbedded = false">Cancel</UiButton>
            <UiButton variant="destructive" type="submit" :disabled="!embBranch || !embRuntime">
              Roll back to embedded
            </UiButton>
          </div>
        </form>
      </UiModal>
    </template>
  </div>
</template>
