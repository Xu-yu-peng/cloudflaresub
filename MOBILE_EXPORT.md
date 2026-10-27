# Mobile snapshot export

This change adds `POST /api/export` and `/sub/export-<random-id>?target=clash&token=<per-export-token>`.
The existing page, `/api/generate`, legacy `/sub/<id>` and `SUB_ACCESS_TOKEN` are unchanged.

Send JSON `{configText, nodeCount, resultAt, sha256}`. `configText` is a complete Clash configuration serialized as JSON (valid YAML), `sha256` is its UTF-8 SHA-256, and `resultAt` is Unix seconds. The endpoint validates the node count and single `最低延迟` url-test group, then stores the supplied text exactly. It never expands or substitutes IPs. Downloads return that exact text with YAML content type.

KV uses a separate `export:` namespace, 7-day TTL, 128-bit random ID and 256-bit bearer token. Only the token digest is stored. Links must be kept private; anyone holding a link can read the connection credentials until expiry. KV config text is not encrypted by this application. No request bodies or URLs are logged by this code.

No new binding, secret or migration is required: reuse `SUB_STORE`. Existing Wrangler `run_worker_first = ["/api/*", "/sub/*"]` already covers the routes. Deploy the module graph with Wrangler / Workers Builds; uploading only worker.js through the dashboard is insufficient.

Validation: `node tests/smoke.mjs` and `node tests/mobile-export.mjs`. These use synthetic nodes only, including exact-text downloads, invalid and missing tokens, expiry, size limit, validation errors, unique links, original assets and legacy global token behavior.
