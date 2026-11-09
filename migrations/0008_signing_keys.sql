-- Additional code-signing keys per app, for rotation without breaking
-- builds in the field. The original key stays on `apps` as keyid "main".
-- A build names its key in `updates.codeSigningMetadata.keyid`, the client
-- echoes it in `expo-expect-signature`, and the server signs with that key —
-- so old binaries keep verifying against their embedded certificate while new
-- builds use the new one.
CREATE TABLE app_signing_keys (
    app_id          TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    keyid           TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (app_id, keyid)
);
