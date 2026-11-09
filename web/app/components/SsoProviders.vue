<script setup lang="ts">
// SSO identity providers (OIDC / SAML) for the instance (org omitted) or one
// org. Shows the URLs to register at the IdP; secrets are write-only.
const props = defineProps<{ org?: string }>();
const api = useApi();

interface Provider {
  id: string;
  kind: "oidc" | "saml";
  name: string;
  enabled: boolean;
  domains: string[];
  auto_provision: boolean;
  default_role: string;
  config: Record<string, any>;
  has_client_secret: boolean;
  login_url: string;
  oidc_redirect_uri: string;
  saml_acs_url: string;
  saml_entity_id: string;
}

const listUrl = computed(() => (props.org ? `/api/v1/orgs/${props.org}/sso` : "/api/v1/sso/providers"));
const providers = ref<Provider[]>([]);
const error = ref("");
const editing = ref<Partial<Provider> | null>(null);
const form = reactive({
  kind: "oidc" as "oidc" | "saml",
  name: "",
  enabled: true,
  domains: "",
  auto_provision: false,
  default_role: "member",
  issuer: "",
  client_id: "",
  client_secret: "",
  scopes: "openid email profile",
  allow_unverified_email: false,
  idp_sso_url: "",
  idp_entity_id: "",
  idp_cert_pem: "",
});

async function load() {
  providers.value = (await api.get<{ providers: Provider[] }>(listUrl.value)).providers;
}
onMounted(load);
watch(listUrl, load);

function edit(p?: Provider) {
  error.value = "";
  editing.value = p ?? {};
  Object.assign(form, {
    kind: p?.kind ?? "oidc",
    name: p?.name ?? "",
    enabled: p?.enabled ?? true,
    domains: (p?.domains ?? []).join(", "),
    auto_provision: p?.auto_provision ?? false,
    default_role: p?.default_role ?? "member",
    issuer: p?.config.issuer ?? "",
    client_id: p?.config.client_id ?? "",
    client_secret: "",
    scopes: p?.config.scopes ?? "openid email profile",
    allow_unverified_email: p?.config.allow_unverified_email ?? false,
    idp_sso_url: p?.config.idp_sso_url ?? "",
    idp_entity_id: p?.config.idp_entity_id ?? "",
    idp_cert_pem: p?.config.idp_cert_pem ?? "",
  });
}

async function save() {
  error.value = "";
  const config =
    form.kind === "oidc"
      ? {
          issuer: form.issuer,
          client_id: form.client_id,
          client_secret: form.client_secret,
          scopes: form.scopes,
          allow_unverified_email: form.allow_unverified_email,
        }
      : { idp_sso_url: form.idp_sso_url, idp_entity_id: form.idp_entity_id, idp_cert_pem: form.idp_cert_pem };
  const body = {
    kind: form.kind,
    name: form.name,
    enabled: form.enabled,
    domains: form.domains.split(/[\s,]+/).filter(Boolean),
    auto_provision: form.auto_provision,
    default_role: form.default_role,
    config,
  };
  try {
    if (editing.value?.id) await api.patch(`/api/v1/sso/providers/${editing.value.id}`, body);
    else await api.post(listUrl.value, body);
    editing.value = null;
    await load();
  } catch (e) {
    error.value = apiErrorMessage(e);
  }
}

async function remove(p: Provider) {
  await api.del(`/api/v1/sso/providers/${p.id}`);
  await load();
}

const copy = (s: string) => navigator.clipboard?.writeText(s);
</script>

<template>
  <div>
    <div class="mb-2 flex justify-end">
      <UiButton size="sm" data-testid="sso-new" @click="edit()"><UiIcon name="plus" :size="14" /> Add provider</UiButton>
    </div>
    <p v-if="!providers.length" class="py-2 text-sm text-muted-foreground">
      No SSO providers. Add an OIDC (Okta, Entra ID, Google Workspace, Keycloak…) or SAML 2.0 IdP; users then
      sign in with "Sign in with SSO" using their work email.
    </p>
    <ul class="flex flex-col divide-y divide-border">
      <li v-for="p in providers" :key="p.id" class="flex flex-col gap-1 py-3 text-sm">
        <div class="flex items-center justify-between gap-2">
          <span class="flex items-center gap-2">
            <span class="font-medium">{{ p.name }}</span>
            <UiBadge variant="outline">{{ p.kind.toUpperCase() }}</UiBadge>
            <UiBadge v-if="!p.enabled" variant="outline">disabled</UiBadge>
            <span class="text-xs text-muted-foreground">{{ p.domains.join(", ") || "any domain" }}</span>
          </span>
          <span class="flex">
            <UiButton variant="ghost" size="sm" @click="edit(p)">Edit</UiButton>
            <UiButton variant="ghost" size="sm" @click="remove(p)"><UiIcon name="trash" :size="14" /></UiButton>
          </span>
        </div>
        <div class="flex flex-col gap-0.5 font-mono text-xs text-muted-foreground">
          <template v-if="p.kind === 'oidc'">
            <span>Redirect URI: {{ p.oidc_redirect_uri }} <button class="underline" @click="copy(p.oidc_redirect_uri)">copy</button></span>
          </template>
          <template v-else>
            <span>ACS URL: {{ p.saml_acs_url }} <button class="underline" @click="copy(p.saml_acs_url)">copy</button></span>
            <span>Entity ID / metadata: {{ p.saml_entity_id }} <button class="underline" @click="copy(p.saml_entity_id)">copy</button></span>
          </template>
        </div>
      </li>
    </ul>

    <UiModal :open="!!editing" :title="editing?.id ? `Edit ${form.name}` : 'Add SSO provider'" @close="editing = null">
      <form class="flex max-h-[70vh] flex-col gap-3 overflow-y-auto" @submit.prevent="save">
        <div v-if="!editing?.id" class="flex gap-2">
          <UiButton type="button" :variant="form.kind === 'oidc' ? 'primary' : 'outline'" size="sm" @click="form.kind = 'oidc'">OIDC</UiButton>
          <UiButton type="button" :variant="form.kind === 'saml' ? 'primary' : 'outline'" size="sm" @click="form.kind = 'saml'">SAML 2.0</UiButton>
        </div>
        <label class="flex flex-col gap-1 text-sm">Name <UiInput v-model="form.name" placeholder="Okta" required /></label>
        <label class="flex flex-col gap-1 text-sm">
          Email domains <UiInput v-model="form.domains" placeholder="company.com, company.io" />
          <span class="text-xs text-muted-foreground">
            Users with these domains are sent here, and only these domains are accepted{{ org ? " (required for org providers)" : "" }}.
          </span>
        </label>
        <template v-if="form.kind === 'oidc'">
          <label class="flex flex-col gap-1 text-sm">Issuer URL <UiInput v-model="form.issuer" placeholder="https://company.okta.com" required /></label>
          <label class="flex flex-col gap-1 text-sm">Client ID <UiInput v-model="form.client_id" required /></label>
          <label class="flex flex-col gap-1 text-sm">
            Client secret
            <UiInput v-model="form.client_secret" type="password" :placeholder="editing?.has_client_secret ? 'unchanged' : ''" />
          </label>
          <label class="flex flex-col gap-1 text-sm">Scopes <UiInput v-model="form.scopes" /></label>
          <label class="flex items-center gap-2 text-sm">
            <input v-model="form.allow_unverified_email" type="checkbox" />
            Accept emails the IdP doesn't mark verified (e.g. Entra ID without <span class="font-mono">email_verified</span>)
          </label>
        </template>
        <template v-else>
          <label class="flex flex-col gap-1 text-sm">IdP SSO URL (HTTP-Redirect) <UiInput v-model="form.idp_sso_url" required /></label>
          <label class="flex flex-col gap-1 text-sm">IdP entity ID (Issuer) <UiInput v-model="form.idp_entity_id" /></label>
          <label class="flex flex-col gap-1 text-sm">
            IdP signing certificate (PEM)
            <textarea v-model="form.idp_cert_pem" rows="5" class="rounded-md border border-border bg-background p-2 font-mono text-xs" required />
          </label>
          <p class="text-xs text-muted-foreground">Assertions must be signed (RSA-SHA256) and not encrypted.</p>
        </template>
        <label class="flex items-center gap-2 text-sm">
          <input v-model="form.auto_provision" type="checkbox" /> Create accounts on first sign-in{{ org ? ` (as org ${form.default_role})` : "" }}
        </label>
        <label v-if="org" class="flex items-center gap-2 text-sm">
          Role for new members
          <select v-model="form.default_role" class="h-8 rounded-md border border-border bg-background px-2">
            <option value="member">member</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label class="flex items-center gap-2 text-sm"><input v-model="form.enabled" type="checkbox" /> Enabled</label>
        <p v-if="error" class="text-sm text-red-400">{{ error }}</p>
        <div class="flex justify-end gap-2">
          <UiButton variant="outline" type="button" @click="editing = null">Cancel</UiButton>
          <UiButton type="submit">Save</UiButton>
        </div>
      </form>
    </UiModal>
  </div>
</template>
