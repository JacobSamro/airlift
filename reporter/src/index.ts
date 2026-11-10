/**
 * airlift-reporter — send JS errors from an Expo app to an airlift server.
 *
 *   import { initAirlift, captureException } from "airlift-reporter";
 *   initAirlift({ url: "https://updates.example.com/u/<app-id>" });
 *
 * Uncaught errors (fatal) and unhandled promise rejections are reported
 * automatically; `captureException` reports handled ones. Each report carries
 * the running update id, runtime version, channel and platform, so the server
 * can symbolicate the stack with that update's sourcemap and group it per
 * update. No dependencies: expo-updates and react-native are read if present.
 */

declare const global: any;
declare function require(name: string): any;
declare function setTimeout(cb: () => void, ms: number): unknown;
declare function fetch(
  url: string,
  init: { method: string; headers: Record<string, string>; body: string }
): Promise<{ ok: boolean; status: number }>;

export interface AirliftOptions {
  /** `https://<server>/u/<app-id>` — the update URL without `/manifest`. */
  url: string;
  /** Stable device id to count affected devices (e.g. EAS client id). */
  clientId?: string;
  /** Also report unhandled promise rejections (default true). */
  captureRejections?: boolean;
  /** Drop a report by returning false. */
  beforeSend?: (report: ErrorReport) => boolean;
}

export interface ErrorReport {
  name: string;
  message: string;
  stack?: string;
  fatal: boolean;
  update_id?: string;
  runtime_version?: string;
  channel?: string;
  platform?: string;
  client_id?: string;
  timestamp: string;
}

let options: AirliftOptions | null = null;
let queue: ErrorReport[] = [];
let flushing = false;
let scheduled = false;
const MAX_QUEUE = 50;
const MAX_BATCH = 20;

// Literal requires inside try: Metro bundles them as optional dependencies.
// A computed `require(name)` can't be bundled at all (Metro turns it into a
// throw), which silently dropped the update id every report needs.
function expoUpdates(): any {
  try {
    return require("expo-updates");
  } catch {
    return undefined;
  }
}

function reactNative(): any {
  try {
    return require("react-native");
  } catch {
    return undefined;
  }
}

/** Context from expo-updates / react-native, read lazily. */
function context(): Partial<ErrorReport> {
  const Updates = expoUpdates();
  const RN = reactNative();
  return {
    update_id: Updates?.updateId ?? undefined,
    runtime_version: Updates?.runtimeVersion ?? undefined,
    channel: Updates?.channel ?? undefined,
    platform: RN?.Platform?.OS,
  };
}

function toReport(err: unknown, fatal: boolean): ErrorReport {
  const e = err instanceof Error ? err : new Error(typeof err === "string" ? err : JSON.stringify(err));
  return {
    name: e.name || "Error",
    message: e.message || String(err),
    stack: e.stack,
    fatal,
    client_id: options?.clientId,
    timestamp: new Date().toISOString(),
    ...context(),
  };
}

async function flush(): Promise<void> {
  if (!options || flushing || queue.length === 0) return;
  flushing = true;
  const batch = queue.slice(0, MAX_BATCH);
  try {
    const res = await fetch(`${options.url.replace(/\/+$/, "")}/errors`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batch),
    });
    // Drop the batch on success or on a client error (it won't get better);
    // keep it for a retry on network/server errors.
    if (res.ok || (res.status >= 400 && res.status < 500)) queue = queue.slice(batch.length);
  } catch {
    // offline: keep for the next flush
  } finally {
    flushing = false;
  }
  if (queue.length > 0) schedule(10_000);
}

function schedule(ms = 1000): void {
  if (scheduled) return;
  scheduled = true;
  setTimeout(() => {
    scheduled = false;
    void flush();
  }, ms);
}

function enqueue(report: ErrorReport, immediate: boolean): void {
  if (!options) return;
  if (options.beforeSend && !options.beforeSend(report)) return;
  queue.push(report);
  if (queue.length > MAX_QUEUE) queue = queue.slice(-MAX_QUEUE);
  if (immediate) void flush();
  else schedule();
}

/** Report a handled error. */
export function captureException(err: unknown, opts: { fatal?: boolean } = {}): void {
  enqueue(toReport(err, opts.fatal ?? false), opts.fatal ?? false);
}

/** Install the global handlers. Call once, as early as possible. */
export function initAirlift(opts: AirliftOptions): void {
  if (options) return;
  options = opts;

  // Uncaught JS errors (React Native's ErrorUtils); chain the previous
  // handler so the red box / crash behaviour is unchanged.
  const ErrorUtils = global.ErrorUtils;
  if (ErrorUtils?.getGlobalHandler && ErrorUtils?.setGlobalHandler) {
    const previous = ErrorUtils.getGlobalHandler();
    ErrorUtils.setGlobalHandler((error: unknown, isFatal?: boolean) => {
      // Fatal errors may kill the JS context: send right away.
      enqueue(toReport(error, !!isFatal), !!isFatal);
      previous?.(error, isFatal);
    });
  }

  // Unhandled promise rejections (Hermes).
  if (opts.captureRejections !== false) {
    const hermes = global.HermesInternal;
    if (hermes?.enablePromiseRejectionTracker) {
      hermes.enablePromiseRejectionTracker({
        allRejections: true,
        onUnhandled: (_id: number, rejection: unknown) => enqueue(toReport(rejection, false), false),
      });
    }
  }
}
