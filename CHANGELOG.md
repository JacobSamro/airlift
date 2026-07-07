# Changelog

## [Unreleased]

Initial development.

- Expo Updates protocol v0 + v1: multipart manifests, `noUpdateAvailable` /
  `rollBackToEmbedded` directives, RSA-SHA256 manifest signing with per-app
  generated certificates.
- EAS-style branches + channels with per-channel auto-release/gated releases,
  promote, rollback, channel→branch repointing.
- Publish API: zipped `expo export` upload, content-addressed per-org asset
  dedup in S3/Tigris, duplicate-head refusal (409), auto-created same-named
  channel on first publish.
- Assets served as 307 redirects to presigned storage/CDN URLs.
- Multi-tenancy: orgs, members, teams (per-app read/publish/admin grants),
  PATs (`alt_` prefix; all/org/app scope × read/publish/admin cap), Google
  sign-in, first-run setup.
- Client monitoring: device check-ins, adoption per update, daily series;
  Prometheus `/metrics`.
- Embedded Nuxt 4 dashboard (apps, channels, updates timeline, promote/
  rollback, tokens, instance settings, domains + automatic Let's Encrypt TLS).
- `airlift-cli` npm package: init / publish / promote / rollback / list.
- Asset garbage collection with grace window (`airlift gc` + background loop).
- bsdiff incremental launch-bundle patches (SDK 55+ `A-IM: bsdiff` → `226 IM
  Used`, classic BSDIFF40): lazy background generation, integrity-gated
  inputs, not-beneficial cutoff, automatic full-bundle fallback.
