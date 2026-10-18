# CC:Tweaked Crypto Server / KMS

## Security configuration

The service refuses to start unless `API_TOKEN` is set to a random admin secret of at least 32 characters. It has no default admin credential.

- `API_TOKEN`: admin-only credential for device management and manual key rotation.
- `DEVICE_TOKENS_JSON`: maps each ComputerCraft computer ID to its own random token. The same token must be configured on that computer in `crypto.lua.txt`.
- `NETWORK_CONFIG_JSON`: maps network labels (the CC computer label is used as the network name) to allowed computer IDs.
- `DB_PATH`: path to persistent SQLite runtime state; use a persistent volume such as `/data/keys.db`.
- `ROTATION_INTERVAL_HOURS`: key rotation interval (1–8760 hours).

Copy `.env.example` to a private `.env`, replace every placeholder with random secrets, and never commit the private file. The example file is only a template.

## Device enrollment

The admin API can list, authorize, and revoke devices under `/v1/networks/{network}/devices`. When a device has no credential yet, the POST endpoint returns a newly generated `device_token` **once**. Copy it securely to that computer's `crypto.lua.txt` as its `API_TOKEN`. The token is not stored in plaintext in SQLite. If a device already has a credential, the API does not reveal it again.

A device must be a member of the requested network and present its own Bearer token. The admin device list includes only devices that have both a network membership and an active credential. The `User-Agent` computer ID is only a lookup hint, not proof of identity. Do not reuse the admin token on CC computers.

## Deployment

Install dependencies with `python -m pip install -r requirements.txt`. Run behind a TLS reverse proxy if accessed remotely. Set `HOST=127.0.0.1` when the proxy is on the same host; configure a suitable private bind address if the proxy is in a separate container. Do not expose the service directly to the public internet.

Keep `keys.db` on persistent storage and out of version control. The database previously tracked in this repository must be considered exposed: rotate all network keys and replace any credentials that may have been stored in it. Removing the file in this branch does not erase it from earlier Git history; if the repository is public, purge the sensitive blob from history with a coordinated history rewrite after rotating secrets.

## Important protocol limitation

Automatic or manual rotation changes the active network key immediately. Test how all running CC computers recover and refresh their in-memory key before enabling a short rotation interval; some clients may need a controlled restart or a protocol update.

This API protects key retrieval and management, but it does not fix the client-side `crypto.lua.txt` design by itself. That file still uses RC4 and a custom non-cryptographic hash instead of a real MAC. Do not rely on the overall system for real-world door security until the client protocol is replaced with reviewed authenticated cryptography and tested end-to-end.
