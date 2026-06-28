# Infinity Guard

In-process Java agent (`-javaagent`) for the Infinity MC launcher.

- **Pack monitor** — deletes unauthorized resource packs and reports them to
  `/api/launcher/report-violation`.
- **Attestation heartbeat** — proves liveness to the server with a rolling
  HMAC (`init` → `beat` → `end`). If the heartbeat stops, the server kicks the
  player, making the lock fail-closed.

## Build
```
./build.sh
```
Produces `infinity-guard-1.2.0.jar` (Premain-Class: `infinity.GuardAgent`).

## JVM properties
- `infinity.server_url` — auth/sync server base URL
- `infinity.token` — player session token (Bearer)
- `infinity.whitelist` — comma-separated allowed pack SHA-1 hashes
