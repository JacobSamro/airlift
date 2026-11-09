<script setup lang="ts">
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const route = useRoute();
const api = useApi();
const me = useMe();
const slug = computed(() => route.params.slug as string);

const teams = ref<Team[]>([]);
const selected = ref<Team | null>(null);
const teamMembers = ref<Member[]>([]);
const teamPerms = ref<TeamPerm[]>([]);
const error = ref("");

const showCreate = ref(false);
const newTeam = reactive({ name: "", slug: "" });
const addMemberLogin = ref("");
const permApp = ref("");
const permLevel = ref("read");

// Custom roles: named capability sets usable as grants ("role:<name>").
interface CustomRole {
  name: string;
  capabilities: string[];
}
const roles = ref<CustomRole[]>([]);
const allCaps = ref<string[]>([]);
const showRole = ref(false);
const roleForm = reactive<{ name: string; caps: string[] }>({ name: "", caps: [] });
const capHelp: Record<string, string> = {
  read: "see the app, updates, stats",
  publish: "publish / republish updates",
  release: "promote, roll out, roll back",
  channels: "configure channels and A/B splits",
  keys: "manage code-signing keys",
  protected: "act on protected branches",
};

async function loadRoles() {
  const r = await api.get<{ roles: CustomRole[]; capabilities: string[] }>(
    `/api/v1/orgs/${slug.value}/roles`,
  );
  roles.value = r.roles;
  allCaps.value = r.capabilities;
}

function editRole(r?: CustomRole) {
  roleForm.name = r?.name ?? "";
  roleForm.caps = r ? [...r.capabilities] : ["read"];
  showRole.value = true;
}

async function saveRole() {
  error.value = "";
  try {
    await api.put(`/api/v1/orgs/${slug.value}/roles/${roleForm.name}`, {
      capabilities: roleForm.caps,
    });
    showRole.value = false;
    await loadRoles();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function deleteRole(r: CustomRole) {
  error.value = "";
  try {
    await api.del(`/api/v1/orgs/${slug.value}/roles/${r.name}`);
    await loadRoles();
    if (selected.value) await select(selected.value);
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

const canAdmin = computed(() => {
  const role = me.value?.orgs.find((o) => o.slug === slug.value)?.role;
  return role === "owner" || role === "admin";
});

watch(() => newTeam.name, (v) => {
  newTeam.slug = v.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
});

async function loadTeams() {
  teams.value = (await api.get<{ teams: Team[] }>(`/api/v1/orgs/${slug.value}/teams`)).teams;
  if (!selected.value && teams.value.length) select(teams.value[0]);
}
onMounted(() => {
  loadTeams();
  loadRoles();
});
watch(slug, () => {
  selected.value = null;
  loadTeams();
  loadRoles();
});

async function select(t: Team) {
  selected.value = t;
  const [m, p] = await Promise.all([
    api.get<{ members: Member[] }>(`/api/v1/orgs/${slug.value}/teams/${t.slug}/members`),
    api.get<{ permissions: TeamPerm[] }>(`/api/v1/orgs/${slug.value}/teams/${t.slug}/perms`),
  ]);
  teamMembers.value = m.members;
  teamPerms.value = p.permissions;
}

async function create() {
  error.value = "";
  try {
    await api.post(`/api/v1/orgs/${slug.value}/teams`, { name: newTeam.name, slug: newTeam.slug });
    showCreate.value = false;
    newTeam.name = "";
    await loadTeams();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function addMember() {
  if (!selected.value) return;
  try {
    await api.post(`/api/v1/orgs/${slug.value}/teams/${selected.value.slug}/members`, { login: addMemberLogin.value });
    addMemberLogin.value = "";
    await select(selected.value);
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function removeMember(m: Member) {
  if (!selected.value) return;
  await api.del(`/api/v1/orgs/${slug.value}/teams/${selected.value.slug}/members/${m.user_id}`);
  await select(selected.value);
}

async function setPerm() {
  if (!selected.value) return;
  try {
    await api.post(`/api/v1/orgs/${slug.value}/teams/${selected.value.slug}/perms`, {
      app: permApp.value,
      permission: permLevel.value,
    });
    permApp.value = "";
    await select(selected.value);
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}
</script>

<template>
  <div>
    <div class="mb-6 flex items-end justify-between">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">Teams</h1>
        <p class="text-sm text-muted-foreground">Group members and grant per-app access.</p>
      </div>
      <UiButton v-if="canAdmin" size="sm" @click="showCreate = true">
        <UiIcon name="plus" :size="14" /> New team
      </UiButton>
    </div>

    <div class="grid grid-cols-3 gap-6">
      <UiCard class="col-span-1">
        <div v-if="!teams.length" class="py-6 text-center text-sm text-muted-foreground">No teams yet.</div>
        <ul class="flex flex-col gap-1">
          <li v-for="t in teams" :key="t.id">
            <button
              class="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition-colors"
              :class="selected?.id === t.id ? 'bg-accent font-medium text-accent-foreground' : 'text-muted-foreground hover:bg-muted/50'"
              @click="select(t)"
            >
              <UiIcon name="team" :size="16" /> {{ t.name }}
            </button>
          </li>
        </ul>
      </UiCard>

      <div class="col-span-2 flex flex-col gap-6">
        <UiCard v-if="selected" :title="`${selected.name} · members`">
          <template #header>
            <div v-if="canAdmin" class="flex gap-2">
              <UiInput v-model="addMemberLogin" placeholder="username" class="h-8 w-40" />
              <UiButton size="sm" @click="addMember">Add</UiButton>
            </div>
          </template>
          <div v-if="!teamMembers.length" class="py-4 text-sm text-muted-foreground">No members.</div>
          <ul v-else class="flex flex-col divide-y divide-border">
            <li v-for="m in teamMembers" :key="m.user_id" class="flex items-center justify-between py-2 text-sm">
              <span>{{ m.username }} <span class="text-muted-foreground">· {{ m.role }}</span></span>
              <UiButton v-if="canAdmin" variant="ghost" size="sm" @click="removeMember(m)">
                <UiIcon name="trash" :size="14" />
              </UiButton>
            </li>
          </ul>
        </UiCard>

        <UiCard v-if="selected" :title="`${selected.name} · app access`">
          <template #header>
            <div v-if="canAdmin" class="flex gap-2">
              <UiInput v-model="permApp" placeholder="app name" class="h-8 w-32" />
              <Select v-model="permLevel">
                <SelectTrigger class="h-8 w-36"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="read">read</SelectItem>
                  <SelectItem value="publish">publish</SelectItem>
                  <SelectItem value="admin">admin</SelectItem>
                  <SelectItem v-for="r in roles" :key="r.name" :value="`role:${r.name}`">
                    role: {{ r.name }}
                  </SelectItem>
                </SelectContent>
              </Select>
              <UiButton size="sm" @click="setPerm">Grant</UiButton>
            </div>
          </template>
          <div v-if="!teamPerms.length" class="py-4 text-sm text-muted-foreground">No grants.</div>
          <ul v-else class="flex flex-col divide-y divide-border">
            <li v-for="p in teamPerms" :key="p.app" class="flex items-center justify-between py-2 text-sm">
              <span class="font-mono">{{ p.app }}</span>
              <UiBadge variant="outline">{{ p.permission }}</UiBadge>
            </li>
          </ul>
        </UiCard>

        <UiCard title="Custom roles">
          <template #header>
            <UiButton v-if="canAdmin" size="sm" data-testid="new-role" @click="editRole()">
              <UiIcon name="plus" :size="14" /> New role
            </UiButton>
          </template>
          <p class="mb-2 text-xs text-muted-foreground">
            Named sets of app capabilities. Grant them to a team as
            <span class="font-mono">role:&lt;name&gt;</span> instead of read / publish / admin.
          </p>
          <div v-if="!roles.length" class="py-2 text-sm text-muted-foreground">No custom roles.</div>
          <ul v-else class="flex flex-col divide-y divide-border">
            <li v-for="r in roles" :key="r.name" class="flex items-center justify-between gap-2 py-2 text-sm">
              <span class="font-mono">{{ r.name }}</span>
              <span class="flex flex-1 flex-wrap justify-end gap-1">
                <UiBadge v-for="c in r.capabilities" :key="c" variant="outline">{{ c }}</UiBadge>
              </span>
              <span v-if="canAdmin" class="flex">
                <UiButton variant="ghost" size="sm" @click="editRole(r)">Edit</UiButton>
                <UiButton variant="ghost" size="sm" @click="deleteRole(r)"><UiIcon name="trash" :size="14" /></UiButton>
              </span>
            </li>
          </ul>
        </UiCard>

        <p v-if="error" class="text-sm text-red-400">{{ error }}</p>
      </div>
    </div>

    <UiModal :open="showRole" :title="roleForm.name ? `Role ${roleForm.name}` : 'New role'" @close="showRole = false">
      <form class="flex flex-col gap-4" @submit.prevent="saveRole">
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Name</label>
          <UiInput v-model="roleForm.name" placeholder="releaser" required data-testid="role-name" />
        </div>
        <div class="flex flex-col gap-2">
          <label class="text-sm font-medium">Capabilities</label>
          <label v-for="c in allCaps" :key="c" class="flex items-center gap-2 text-sm">
            <input v-model="roleForm.caps" type="checkbox" :value="c" />
            <span class="font-mono">{{ c }}</span>
            <span class="text-xs text-muted-foreground">{{ capHelp[c] }}</span>
          </label>
        </div>
        <div class="flex justify-end gap-2">
          <UiButton variant="outline" type="button" @click="showRole = false">Cancel</UiButton>
          <UiButton type="submit" :disabled="!roleForm.name || !roleForm.caps.length">Save</UiButton>
        </div>
      </form>
    </UiModal>

    <UiModal :open="showCreate" title="New team" @close="showCreate = false">
      <form class="flex flex-col gap-4" @submit.prevent="create">
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Name</label>
          <UiInput v-model="newTeam.name" placeholder="Backend" required />
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-sm font-medium">Slug</label>
          <UiInput v-model="newTeam.slug" placeholder="backend" required />
        </div>
        <div class="flex justify-end gap-2">
          <UiButton variant="outline" type="button" @click="showCreate = false">Cancel</UiButton>
          <UiButton type="submit">Create</UiButton>
        </div>
      </form>
    </UiModal>
  </div>
</template>
