import * as fs from "node:fs";
import * as path from "node:path";
import { postJson } from "../api";
import { CommonOptions, resolveContext } from "../config";

export interface GenerateCertsOptions extends CommonOptions {
  keyid?: string;
}

/**
 * Rotate the app's code-signing key: the server generates a new key (the
 * private key never leaves it), this writes its certificate to
 * certs/certificate-<keyid>.pem and points app.json at it. Existing builds
 * keep verifying with their old key; the new key applies to new builds.
 */
export async function generateCertsCommand(opts: GenerateCertsOptions): Promise<void> {
  const ctx = resolveContext(opts);
  const client = { server: ctx.server, token: ctx.token };
  const r = await postJson<{ keyid: string; certificate_pem: string }>(
    client,
    `/api/v1/orgs/${encodeURIComponent(ctx.org)}/apps/${encodeURIComponent(ctx.app)}/signing-keys`,
    opts.keyid ? { keyid: opts.keyid } : {}
  );

  const certDir = path.join(ctx.projectDir, "certs");
  fs.mkdirSync(certDir, { recursive: true });
  const rel = `./certs/certificate-${r.keyid}.pem`;
  fs.writeFileSync(path.join(ctx.projectDir, rel), r.certificate_pem);
  console.log(`New signing key "${r.keyid}" created; wrote ${rel}.`);

  const appJsonPath = path.join(ctx.projectDir, "app.json");
  if (fs.existsSync(appJsonPath)) {
    const root = JSON.parse(fs.readFileSync(appJsonPath, "utf8")) as Record<string, any>;
    root.expo ??= {};
    root.expo.updates ??= {};
    root.expo.updates.codeSigningCertificate = rel;
    root.expo.updates.codeSigningMetadata = { keyid: r.keyid, alg: "rsa-v1_5-sha256" };
    fs.writeFileSync(appJsonPath, JSON.stringify(root, null, 2) + "\n");
    console.log("Updated app.json (updates.codeSigningCertificate and codeSigningMetadata.keyid).");
  } else {
    console.log("\nSet these in your Expo config:");
    console.log(
      JSON.stringify(
        {
          updates: {
            codeSigningCertificate: rel,
            codeSigningMetadata: { keyid: r.keyid, alg: "rsa-v1_5-sha256" },
          },
        },
        null,
        2
      )
    );
  }
  console.log(
    "\nBuilds already in the field keep working with their old key. Make a NEW NATIVE BUILD to\n" +
      "embed this certificate; from then on those builds verify updates with the new key."
  );
}
