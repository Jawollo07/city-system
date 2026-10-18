# Security hardening review (2026-10)

## Changes in this branch

- Administrative commands in `server.lua` now require an explicit sender-ID allowlist. The default allowlist is empty (fail closed).
- Elevator access no longer trusts `payload.userLevel`; a successful database keycard lookup and a successful floor lookup are required.
- The DB service accepts requests only from configured Keller-Server ID 18.
- Relays accept triggers only from configured Keller-Server ID 18 and only for their configured floor ID; outputs are reset after the pulse.
- The crypto module no longer uses a hard-coded fallback key. Missing API configuration or unavailable keys cause requests to fail closed.
- The old committed API token has been removed from the source and replaced with a placeholder.
- Admin API requests require HTTPS, and their HTTP failure handler no longer treats the failure string as a response handle.
- Keycard and clearance values are validated.

## Required deployment configuration

1. Rotate/revoke the previously committed token `SuperSecretDeviceToken_2026` on the API immediately. Assume it is compromised even if it was only intended as a placeholder.
2. Generate one random `API_TOKEN`, configure it on the KMS server and in `crypto.lua`, and do not commit it. `admin.lua` reads the same key from `crypto.lua`.
3. Set `ADMIN_IDS` in `server.lua` to the real computer IDs running `admin.lua` and `sec_server.lua`. Until then all admin operations are intentionally denied.
4. Set `FLOOR_ID` in each `relay.lua` to match the floor's `relayID` in `db.lua` (the current defaults map floor IDs 0–3 to relay IDs 10–13).
5. Verify that the DB server is actually computer ID 19 and Keller-Server is ID 18. Update `KELLER_SERVER_ID` and other ID constants if the real topology differs.
6. Back up `db_data.txt` and test in a non-production world before deployment.

## Critical limitation — do not treat this as production-secure yet

The existing crypto implementation still uses RC4 and a custom, non-cryptographic hash function labelled HMAC. These cannot provide modern confidentiality or message authenticity. The nonce is also generated with `math.random`, which is not a cryptographically secure random generator. The changes in this branch remove the unsafe fallback and add input checks, but **they do not make the existing cipher/authentication construction secure**.

Before merging for real access control, replace this module with a reviewed cryptographic implementation supported by the actual CC:Tweaked environment (for example a vetted cryptographic library with authenticated encryption or HMAC-SHA-256), or redesign the protocol to use an authenticated trusted gateway. Do not invent a replacement cipher or silently downgrade to plaintext. Until that is done, do not rely on this system to protect real doors or other safety-critical equipment.

## API review status

The API implementation is in `crypto-server/app.py`. All routes require one shared Bearer `API_TOKEN`; device key retrieval additionally checks the device's network membership. This deliberately gives every client holding the key administrative access to enrollment and key rotation. Deployment still requires protecting the shared key and using a TLS reverse proxy for remote access. This is not a complete end-to-end security audit: the Lua client still uses RC4, a custom non-cryptographic MAC, and `math.random` for nonces, as described above.

## Test checklist

- [ ] Verify Lua syntax on the exact CC:Tweaked version used by the world.
- [ ] Confirm all valid admin IDs are allowlisted and unlisted IDs receive `DENIED`.
- [ ] Confirm an unknown keycard and a DB timeout deny elevator access.
- [ ] Confirm `payload.userLevel` has no effect on authorization.
- [ ] Send a trigger from a non-server computer; relay must stay off.
- [ ] Send a trigger for the wrong floor; relay must stay off.
- [ ] Simulate API outage and missing token; no fallback key must be used.
- [ ] Verify the same API key works for admin operations and key retrieval, while missing/incorrect keys are rejected.
- [ ] Confirm network membership still restricts key retrieval when a device ID is not authorized.
- [ ] Complete cryptographic replacement and test interoperability across every device.
- [ ] Verify TLS reverse-proxy configuration before remote access.
