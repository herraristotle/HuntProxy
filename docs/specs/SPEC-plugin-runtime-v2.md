# Spec: Plugin Runtime v2 — Capability-Bridge Extensions

## Decision (principal-engineer, 2026-10-11)

We **do not** clone Caido's backend plugin runtime wholesale. We adopt their authoring ergonomics and SDK *shape*, not their ambient-authority security model.

| Caido backend runtime | HuntProxy v2 decision |
|---|---|
| Persistent QuickJS thread, `init(sdk)`, long-lived | **Rejected for now** — ephemeral plan/analyze stays the execution model; background work belongs to host services plugins configure |
| Ambient `fetch` (`caido:http`), unproxied | **Bridged + gated** — `net.external` capability: host-executed fetch to hosts allowlisted in the manifest, audited like every network op |
| Ambient `crypto` (partial) | **Adopted as pure module** — host-implemented `crypto` in QuickJS (hash/hmac/aes-gcm/ctr/random/rsa-oaep/base64/hex): zero authority, zero side effects |
| Ambient `fs`, `child_process`, `net.connect`, `sqlite` | **Rejected** — contradicts the capability-gated thesis (HuntProxy-Plugins `docs/architecture.md`); revisit only with a concrete porting need and explicit capability grants |
| `setInterval` timers in plugin JS | **Rejected** — pollers/schedulers are host services (see OAST background poller); plugins start/stop/read them via bridges |
| `sdk.meta.path()` / `sdk.meta.db()` per-plugin storage | **Bridged** — `store` host module: per-plugin namespaced KV in the host DB (`store.get/set/delete/list`), audited, project-scoped where applicable |
| `sdk.env` secrets | **Bridged later** — not in v2 MVP (OAST secrets are host-owned; plugin secrets can wait for a real consumer) |
| `sdk.api` RPC / `sdk.events` | **Covered** — v1 already has MCP `extension_*` actions and flow/js triggers; events-on-request = flow triggers today |
| Manifest without permissions | **Kept ours** — manifest-v2 `capabilities` remain the enforcement surface; Caido's trust model (sandbox + user opt-in only for `onUpstream`) is weaker than ours |

**Rationale:** our product wedge is agent-native (docs/ideas/agent-native-proxy.md) — plugins see credential-bearing context on every job. Capability-gating, host-mediated network, and audited bridges are the security story we sell over "a sandboxed JS file that can fetch anywhere." Caido can afford ambient fetch because their invasive hook is per-domain opt-in and their users are humans in a GUI; our callers are agents that will happily hand a malicious plugin the session cookie.

## What v2 Adds

Three host modules injected into the existing plan/analyze QuickJS environments, plus one new operation family:

### 1. `crypto` module (no capability — pure functions)

Host-implemented (Rust crates behind rquickjs), matching the Caido `crypto` surface shape so ported plugin code looks familiar:

- `crypto.randomBytes(n) → Uint8Array`
- `crypto.createHash(alg)` — `sha256|sha512|sha1|md5` → `.update()`/`.digest("hex"|"base64")`
- `crypto.createHmac(alg, key)` — same digest API
- `crypto.createCipheriv/createDecipheriv(alg, key, iv)` — `aes-256-gcm`, `aes-256-ctr`, `aes-128-ctr` → `.update()`/`.final()`/`.getAuthTag()`
- `crypto.privateDecrypt({key, padding: oaepSHA256}, buf)` — RSA-OAEP (interactsh decrypt pattern)
- `crypto.fromBase64/toBase64/fromHex/toHex`

### 2. `store` module (capability `store.use`)

Per-plugin namespaced KV persisted in the host DB (plugin id = namespace; values JSON, size-capped ~256 KiB):

- `await store.get(key)`, `await store.set(key, value)`, `await store.delete(key)`, `await store.list(prefix?)`

### 3. `oast` bridge (capability `oast.use`)

Thin client over the core `OastService` (SPEC-oast.md) — plugins mint tokens and read interactions; Rust keeps owning crypto, sessions, sockets, polling:

- `await oast.create({purpose?, watch?}) → {session_id, payload_url, ...}`
- `await oast.newUrl(session_id, {case_index?}) → {payload_url, label}` (interactsh)
- `await oast.poll(session_id) → Interaction[]`
- `await oast.interactions(session_id, {label?, cursor?}) → Interaction[]`

### 4. `net.external` capability — allowlisted host fetch

New host operation `http_external` (planned from `plan()` like every other op):

```json
{"kind": "http_external", "method": "GET", "url": "https://api.example.com/x", "headers": {...}, "body": "..."}
```

- Enforced at plan **and** execute: URL host must match an entry in the manifest's new `external_hosts` allowlist (exact host or `*.suffix`); non-matching → job fails, op never sent
- Responses returned as observations (bounded, same truncation rules); `save` option **false by default** — external API calls are not target traffic and stay out of History unless the plugin opts in
- Scope checks do **not** apply (these are deliberately out-of-scope third-party calls) — the allowlist is the boundary; audited via op log

## Manifest Changes (schema v2, additive)

- `capabilities[]` += `store.use`, `oast.use`, `net.external`
- new optional `external_hosts: string[]` — required non-empty when `net.external` declared; host patterns only (`api.example.com`, `*.postb.in`); rejected: paths, ports-as-scopes, wildcards beyond leading `*.`

## Explicit Non-Goals (v2)

- Persistent plugin runtimes / `init(sdk)` / background JS threads
- `fs`, `child_process`, raw `net`/TCP, `sqlite`
- Plugin-visible timers; plugin-defined background pollers (host services instead)
- Secret/env-var stores; frontend plugin runtime (see packaging spec — reserved only)
- Zip install / Ed25519 signing (distribution phase, later)

## Worked Example: QuickSSRF-class port

A blind-SSRF confirmation plugin under v2: `plan()` returns `oast.create` (via bridge, executed host-side) + the target request via existing `http.semantic`; `analyze()` calls `oast.poll`/`interactions` and emits a finding via flow/js `sdk.findings.create`. No fetch, no timers, no stores-of-its-own beyond `store` for session bookkeeping — ~150 lines, fully audited, every network action visible. A generic "poll a webhook" plugin additionally declares `net.external` + `external_hosts: ["*.webhook.site"]`. This is the porting proof the packaging spec's migration guide references.

## Testing

- Unit (Rust): crypto module round-trips vs Rust fixtures (hash/hmac/aes-gcm/ctr/rsa-oaep/base64); store CRUD + size cap + namespace isolation; oast bridge against mock provider (from SPEC-oast tests); `external_hosts` matching (`*.suffix`, exact, reject port/path forms)
- Integration: a fixture plugin declaring each new capability runs end-to-end; missing `external_hosts` with `net.external` → manifest rejected at load; op with non-allowlisted host → job error, nothing sent
- Negative: `store.use` absent → module undefined in JS; `oast.use` absent → bridge calls fail closed

## Boundaries

- **Always:** new capabilities additive to schema v2 + validator; every bridged call audited and bounded; DomainError on all failure paths; index-stage edits to crawler-interleaved files; fmt/clippy/test + CI gate
- **Ask first:** adding any further ambient module (fs/net/timers); changing bridge op shapes; touching schema v2 required fields
- **Never:** ambient fetch/fs/process in QuickJS; plugin-authored background pollers; secrets in plugin-visible store values without redaction review
