# HWID Licenser

Pure Node.js/Express service for issuing and validating RS256 JWT license tokens that bind to an HWID. Designed for VPS deployment with file-based storage, strong admin auth, and audit logging.

## Features
- RS256 JWT license issuance with `hwid`, `plan`, `exp`, and `jti`
- Online verification endpoint with HWID matching and revocation checks
- File-backed revocation list with atomic writes
- Audit logs for issued and revoked licenses (JSONL)
- Admin-only endpoints secured by HTTP Basic Auth + bcrypt
- Global rate limiting and request slowdown to mitigate brute-force abuse
- Optional offline verification helper (`verify-offline.js`)
- Optional Discord bot with slash commands, modals, and secure token reveal

## Prerequisites
- Node.js 18 or newer
- npm (bundled with Node)
- OpenSSL (for generating RSA key pair)

## Initial Setup
```sh
mkdir -p keys data/logs
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Copy the example environment file, then adjust values for your deployment:
```sh
cp .env.example .env
```

Install dependencies and start the server:
```sh
npm install
npm start
```

The service listens on the port defined by `PORT` (defaults to 4000).

## Environment Variables
See `.env.example` for all options. Key entries:
- `ADMIN_USER` / `ADMIN_PASS`: Admin credentials for issuance/revocation. `ADMIN_PASS` accepts plaintext or a bcrypt hash (`$2a$...`). Plaintext is hashed on boot and never logged.
- `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_KID`: Embedded in each token and enforced during verification.
- `PRIVATE_KEY_PATH`, `PUBLIC_KEY_PATH`: Locations of the RSA key pair.
- `RATE_MAX_PER_MIN`, `SLOW_AFTER_PER_MIN`, `SLOW_DELAY_MS`: Global rate limiter and slowdown settings.
- `TRUST_PROXY`: Express trust proxy mode. Default `loopback`. Set to `false` for single-host setups or configure to match your reverse proxy hops.
- `CORS_ORIGINS`: Comma-separated allowlist or `*` for open access.
- Discord bot (optional): `INCLUDE_DISCORD_BOT`, `DISCORD_TOKEN`, `DISCORD_CLIENT_ID`, `DISCORD_GUILD_ID`, `ISSUER_BASE_URL`, `ISSUER_BASIC_USER`, `ISSUER_BASIC_PASS`.

## Endpoints
All endpoints accept/return JSON unless noted.

### `GET /healthz`
Simple health probe.
```json
{ "status": "ok" }
```

### `POST /issue`
Requires admin Basic Auth. Body:
```json
{
  "hwid": "DESKTOP-ABC123",
  "ttlSeconds": 3600,
  "plan": "pro",
  "note": "trial"
}
```
Response:
```json
{ "token": "<JWT>", "jti": "...", "exp": 1700000000 }
```
Audit log appended to `data/logs/issued.jsonl`.

Example:
```sh
curl -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"hwid":"DESKTOP-ABC123","ttlSeconds":3600,"plan":"pro","note":"trial"}' \
  http://localhost:4000/issue
```

### `POST /verify`
Public endpoint. Body:
```json
{ "token": "<JWT>", "hwid": "DESKTOP-ABC123" }
```
Successful verification:
```json
{ "ok": true, "plan": "pro", "exp": 1700000000 }
```
Failure reasons: `invalid_or_expired`, `hwid_mismatch`, `revoked`.

Example:
```sh
curl -H "Content-Type: application/json" \
  -d '{"token":"<JWT>","hwid":"DESKTOP-ABC123"}' \
  http://localhost:4000/verify
```

### `POST /revoke`
Requires admin Basic Auth. Body:
```json
{ "jti": "<license-id>" }
```
Adds the `jti` to `data/revoked.json` atomically and logs to `data/logs/revoked.jsonl`.

Example:
```sh
curl -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"jti":"<license-id>"}' \
  http://localhost:4000/revoke
```

### `GET /status/:jti`
Public endpoint returning revocation status:
```json
{ "revoked": false }
```

Example:
```sh
curl http://localhost:4000/status/<license-id>
```

## Token Payload
Issued tokens contain:
```json
{
  "sub": "license",
  "iss": "<JWT_ISSUER>",
  "aud": "<JWT_AUDIENCE>",
  "hwid": "<HWID>",
  "plan": "<PLAN>",
  "jti": "<ID>",
  "iat": 1700000000,
  "exp": 1700003600
}
```
The header includes the configured `kid` for key rotation support. Distribute `keys/public.pem` to clients so they can verify signatures offline.

## Offline Verification Helper
`verify-offline.js` provides a minimal Node-based verifier using `PUBLIC_KEY_PATH`:
```sh
node verify-offline.js "<TOKEN>" "<HWID>"
```
Outputs JSON describing the validation result.

## Discord Bot (Optional)
Set up the bot if you want to manage licenses from Discord:
1. Fill the Discord-related variables in `.env` and set `INCLUDE_DISCORD_BOT=true`.
2. `DISCORD_TOKEN`: Bot token from the Discord Developer Portal.
3. `DISCORD_CLIENT_ID`: Application ID. Optional `DISCORD_GUILD_ID` registers commands instantly in a single guild.
4. `ISSUER_BASE_URL`: Base URL to reach this API (for example `http://localhost:4000`).
5. `ISSUER_BASIC_USER` / `ISSUER_BASIC_PASS`: Credentials the bot will send to `/issue` and `/revoke` (can match the admin account).
6. Run the bot alongside the API: `npm run bot`.

Commands are slash based with modals for input:
- `/issue`: Opens a modal requesting HWID, TTL, plan, and note. The bot replies ephemerally with the license metadata and a button to reveal the full token (cached for five minutes).
- `/revoke`: Modal for the license JTI, then revokes and logs.
- `/status`: Modal for JTI to display whether the license is active or revoked.

## Logs & Persistence
- Revoked IDs: `data/revoked.json` (sorted array, updated atomically)
- Issuance log: `data/logs/issued.jsonl`
- Revocation log: `data/logs/revoked.jsonl`

Logs are append-only JSON lines suitable for log ingestion. Protect the `keys/` and `data/` directories with appropriate filesystem permissions.

## Production Notes
- Run behind HTTPS (use a reverse proxy such as Nginx or Caddy). Match `TRUST_PROXY` to your proxy hop count or CIDR.
- Forward real client IPs via `X-Forwarded-For` and configure your proxy options accordingly.
- Rotate the RSA key pair periodically and update `JWT_KID` to signal new keys.
- Monitor audit logs and revocation file for tampering; consider off-box backups.

## Optional Discord Bot Source
Run `npm run bot` to start the bot, or leave `INCLUDE_DISCORD_BOT=false` to skip loading `discord.js` entirely.
