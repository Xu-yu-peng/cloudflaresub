# Exact desktop subscription snapshots

`POST /api/desktop-sources` accepts JSON with `subscriptionText`, `nodeCount`,
`fingerprints` and a UTF-8 `sha256`. Each nonempty line must be a supported raw
VMess, VLESS or Trojan link. The desktop performs a lossless round-trip check
before upload and compares downloaded bytes and fingerprints before migration.

Writes require `Authorization: Bearer <SUB_ACCESS_TOKEN>`. A missing management
secret fails closed. Responses return a random `/sub/desktop-<id>?token=...`
private read link. KV records use the existing `SUB_STORE` binding with the
`desktop:` prefix and **no expiration or TTL**. Only a token hash is stored.
Revoke with the same authenticated POST and `{ "action": "revoke", "id": "..." }`.
Do not put secrets, subscription bodies or complete URLs in logs or issues.

Existing pages, legacy subscription routes, global legacy token handling and
the separate seven-day phone `/api/export` snapshots remain unchanged. Keep
the declared KV binding in `wrangler.toml` when deploying through Workers Builds.

Validation: `npm run check`. Tests cover authorization, fail-closed secrets,
exact text, malformed input, durable links, independent tokens, revocation,
phone TTL and legacy routes. Production smoke tests should use synthetic
reserved IP addresses, verify exact bytes and revoke the fixture afterwards.
