// Rewritten by e2e-device/run.sh before each publish; the build embeds
// "embedded", no EXTRA image, no error reporting and no crash.
export const MARKER = 'embedded';
export const EXTRA = null;
// `https://<server>/u/<app-id>`: report a handled error there on launch.
export const REPORT = null;
export const CRASH = false;
