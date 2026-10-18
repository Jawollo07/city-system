# CC:Tweaked Crypto Server / KMS

## Security configuration

The service refuses to start unless **two different** random secrets of at least 32 characters are configured:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

- `DEVICE_API_TOKEN`: used by `crypto.lua` for network-key retrieval only.
- `ADMIN_API_TOKEN`: used only by `admin.lua` for device enrollment, revocation, listing, and manual key rotation.
- `NETWORK_CONFIG_JSON`: maps network labels (the CC computer label is used as the network name) to allowed computer IDs.
- `DB_PATH`: persistent SQLite state, e.g. `/data/keys.db`.
- `ROTATION_INTERVAL_HOURS`: key rotation interval (1–8760 hours).

Copy `.env.example` to a private `.env`, replace both placeholders with independently generated secrets, and never commit the private file. Configure the device token in `crypto.lua` and the admin token only in `admin.lua` on the admin computer. Configure `API_URL` in `crypto.lua` to the HTTPS URL of the KMS reverse proxy, ending in `/v1/`. The code deliberately refuses the placeholder URL and plain HTTP.

## Device enrollment and privileges

The admin API can list, authorize, and revoke network membership under `/v1/networks/{network}/devices`. Those routes and `/v1/rotate/{network}` require `ADMIN_API_TOKEN`. Key retrieval under `/v1/keys/{network}` requires `DEVICE_API_TOKEN` and checks the supplied `User-Agent` computer ID against the network membership table.

**Important limitation:** the `User-Agent` computer ID is not proof of identity. All CC clients configured with the same device token can spoof another ID. For stronger isolation, implement per-device credentials before relying on enrollment as a security boundary. Separating the tokens prevents a compromised ordinary client from directly invoking administrative API routes, but does not provide device-unique authentication.

## Deployment

Install dependencies with `python -m pip install -r crypto-server/requirements.txt`. Run behind a TLS reverse proxy if accessed remotely. Set `HOST=127.0.0.1` when the proxy is on the same host; configure a suitable private bind address if the proxy is in a separate container. Do not expose the service directly to the public internet.

Keep `keys.db` on persistent storage and out of version control. Treat any previously committed API token or database as compromised: rotate the tokens and network keys. Removing a secret from the current branch does not erase it from Git history; if a public repository contains secrets, purge the sensitive blobs from history with a coordinated history rewrite after rotating them.

## Key rotation behavior

The API changes the stored network key immediately on rotation. Existing Lua processes cache the key in memory and currently refresh it at startup or after a failed message authentication check. Therefore rotation is **not guaranteed to update every running client immediately**. Test and redesign key rollover before relying on it as an emergency revocation mechanism.

## Critical protocol limitation

The client protocol in `crypto.lua` still uses RC4 and a custom non-cryptographic hash labelled HMAC instead of a real message authentication code. Its nonce uses `math.random`, which is not a cryptographically secure random generator. The API hardening does not make this message protocol secure. Do not rely on this system to protect real doors, locks, or other safety-critical equipment until the protocol is replaced with reviewed authenticated cryptography supported by the actual CC:Tweaked environment and tested end-to-end.
