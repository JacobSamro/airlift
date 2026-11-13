#!/usr/bin/env node
import { Command } from "commander";
import { generateCertsCommand } from "./commands/certs";
import { promoteCommand, rollbackCommand } from "./commands/channel";
import { doctorCommand } from "./commands/doctor";
import { initCommand } from "./commands/init";
import { republishCommand, rolloutCommand, splitCommand } from "./commands/rollout";
import { listCommand } from "./commands/list";
import { publishCommand } from "./commands/publish";

const program = new Command();

program
  .name("airlift")
  .description("Publish Expo OTA updates to a self-hosted airlift server")
  .version("0.1.2");

function fail(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`Error: ${message}`);
  process.exit(1);
}

/** Add the flags shared by every command that talks to the server. */
function withCommonOptions(cmd: Command): Command {
  return cmd
    .option("--server <url>", "airlift server URL (falls back to airlift.json)")
    .option("--org <slug>", "organization slug (falls back to airlift.json)")
    .option("--app <slug>", "app slug (falls back to airlift.json)")
    .option("--token <pat>", "personal access token (falls back to AIRLIFT_TOKEN)");
}

program
  .command("init")
  .description(
    "Link this project to an airlift app: writes airlift.json, downloads the signing certificate, and configures expo.updates"
  )
  .requiredOption("--server <url>", "airlift server URL")
  .requiredOption("--org <slug>", "organization slug")
  .requiredOption("--app <slug>", "app slug")
  .option("--token <pat>", "personal access token (falls back to AIRLIFT_TOKEN)")
  .option(
    "--keyid <id>",
    "code-signing key this build verifies with (a rotated key from the app's signing keys)",
    "main"
  )
  .action(async (opts) => {
    try {
      await initCommand(opts);
    } catch (err) {
      fail(err);
    }
  });

withCommonOptions(
  program
    .command("publish")
    .description("Export the Expo app and publish it as an update to a branch")
    .requiredOption("--branch <name>", "branch to publish to")
    .option("--channel <name>", "channel to check after publishing (prints promote instructions if pending)")
    .option("--message <msg>", "human-readable message for this update")
    .option("--platform <platform>", "platforms to export: all, ios, or android", "all")
    .option(
      "--runtime-version <rv>",
      "override the runtime version (required if it cannot be derived from your Expo config)"
    )
    .option("--rollout <percent>", "auto-release channels start a progressive rollout at this share")
    .option("--no-source-maps", "don't upload sourcemaps (used to symbolicate device error stacks)")
).action(async (opts) => {
  try {
    await publishCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("promote")
    .description("Release a published update group to a channel")
    .requiredOption("--channel <name>", "channel to promote to")
    .requiredOption("--group <group_id>", "update group id to promote")
).action(async (opts) => {
  try {
    await promoteCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("rollback")
    .description("Roll a channel back to its previous release for a runtime version")
    .requiredOption("--channel <name>", "channel to roll back")
    .requiredOption("--runtime-version <rv>", "runtime version to roll back")
).action(async (opts) => {
  try {
    await rollbackCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("list")
    .description("List published updates for the app")
    .option("--branch <name>", "only show updates on this branch")
    .option("--limit <n>", "maximum number of updates to show")
).action(async (opts) => {
  try {
    await listCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("rollout")
    .description(
      "Progressive rollout: start one for --group, or move the running one for --runtime-version (100 completes it)"
    )
    .requiredOption("--channel <name>", "channel to roll out on")
    .requiredOption("--percent <n>", "share of devices (0-100]")
    .option("--group <group_id>", "update group to start rolling out")
    .option("--runtime-version <rv>", "runtime of the running rollout to adjust")
).action(async (opts) => {
  try {
    await rolloutCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("split")
    .description("A/B split: serve another branch to a share of a channel's devices")
    .requiredOption("--channel <name>", "channel to split")
    .option("--branch <name>", "branch the split share gets")
    .option("--percent <n>", "share of devices (0-100)")
    .option("--off", "end the split")
).action(async (opts) => {
  try {
    await splitCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("republish")
    .description("Re-ship an existing update group as a brand-new update")
    .requiredOption("--group <group_id>", "update group to republish")
    .option("--channel <name>", "release the copy to this channel (default: like a publish to its branch)")
).action(async (opts) => {
  try {
    await republishCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("doctor")
    .description("Check this project's Expo config against the airlift server")
).action(async (opts) => {
  try {
    await doctorCommand(opts);
  } catch (err) {
    fail(err);
  }
});

withCommonOptions(
  program
    .command("generate-certs")
    .description(
      "Rotate the code-signing key: create a new server key, save its certificate, point app.json at it"
    )
    .option("--keyid <id>", "name for the new key (default k<YYYYMMDD>)")
).action(async (opts) => {
  try {
    await generateCertsCommand(opts);
  } catch (err) {
    fail(err);
  }
});

program.parseAsync(process.argv).catch(fail);
