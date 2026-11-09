# airlift-reporter

Report JS errors from an Expo app to your [airlift](../README.md) server. Stacks are
symbolicated on the server with the sourcemap uploaded by `airlift publish` for the
exact update the device runs, grouped, and shown per update (Errors tab).

```sh
npm install airlift-reporter
```

```ts
// App entry, as early as possible
import { initAirlift, captureException } from "airlift-reporter";

initAirlift({
  url: "https://updates.example.com/u/<app-id>", // your updates.url without /manifest
});

try {
  risky();
} catch (e) {
  captureException(e); // handled errors
}
```

- Uncaught errors (reported as fatal, sent immediately) and unhandled promise
  rejections (Hermes) are captured automatically; the previous global handler still runs.
- Each report includes the update id, runtime version, channel (from `expo-updates`)
  and platform. Pass `clientId` to count affected devices.
- Reports are batched, retried while offline, and capped in memory.
- `beforeSend(report)` can drop or scrub reports.

Prefer OpenTelemetry? Point the OTLP/HTTP JSON log exporter at
`https://<server>/u/<app-id>/otlp/v1/logs`; log records with `exception.*` attributes
are symbolicated and grouped the same way. Set `airlift.update_id` as a resource
attribute to tie them to an update.
