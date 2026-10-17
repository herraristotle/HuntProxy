# Spec: OAST (Out-of-Band Interaction Tracking)

## Objective

Close the Collaborator/interactsh gap: give agents (and enigma) first-party OAST tokens for blind XSS, blind SSRF, and other OOB vulnerability classes. HuntProxy becomes an MCP-exposed **OAST client** with a provider abstraction covering the same four providers as Caido's official QuickSSRF plugin — **interactsh** (primary; self-hosted mainline server), **postbin**, **webhooksite**, and **custom** (user-supplied poll URL) — issuing payload URLs, polling for interactions, and persisting them per project. It does **not** reimplement receivers; the provider owns reception.

**Protocol verified against local clone `proxy/interactsh` (`pkg/client/client.go`, `pkg/settings/default.go`) and cross-checked with Caido's official QuickSSRF plugin (`caido-oss/quickssrf`):**
- **Session setup:** client generates RSA-2048 keypair; correlation-id = anonymous xid, **20 chars** from `[0-9a-v]` (4-byte timestamp + 8 crypto-random bytes); secret-key = **UUID v4 string**; `POST {server}/register` body `{public-key, secret-key, correlation-id}` where public-key = `base64(PEM(PKIX SPKI))`; auth header `Authorization: {token}` (never `x-interactsh-token`)
- **Payload URL:** one DNS label = `correlation-id(20) + zbase32(random)[..13]` + `.{domain}` — **fresh nonce label per URL on the SAME registered session** (official `client.URL()`); interactions carry `full-id` (whole 33-char label) enabling per-label correlation without extra registrations
- **Poll:** `GET {server}/poll?id={cid}&secret={secret}` (+ `Authorization`) → `{data: [b64 blobs], aes_key, extra?, tlddata?}`
- **Decrypt (NOT GCM):** `aes_key` = RSA-OAEP-SHA256 decrypt (session private key) of b64(aes_key); each `data[]` entry = b64decode → IV = first 16 bytes → **AES-CTR** XOR → interaction JSON
- **Interaction fields:** `{protocol, unique-id, full-id, raw-request, raw-response, remote-address, timestamp}`

**Industry answers (evidence: QuickSSRF backend, nuclei, Burp):**
- **Token granularity:** protocol-native pattern = one registration per logical unit (job/engagement), unlimited distinct payload URLs via per-URL nonce labels, correlate by `full-id`. QuickSSRF uses one-URL-per-session (human simplicity); nuclei issues fresh URLs per request on a shared session. HuntProxy: **one oast session per fuzz job (or per manual `create`), one label per case** — precise per-case correlation, single registration.
- **Polling:** QuickSSRF auto-polls all active sessions on a `setInterval` (configurable, `autoPolling` config); Burp polls continuously; nuclei polls during scans. HuntProxy is a 24/7 daemon → **MVP includes a lightweight background poller** (tokio interval over `watch` sessions) plus manual `oast poll`.
- **Plugin in HuntProxy?** Not as the protocol owner. Caido ships QuickSSRF as a plugin because their *backend plugin runtime* is long-lived, privileged JS with Node-shim `crypto`, `fetch`, `setInterval`, and SDK secret/session stores (see `caido-oss/quickssrf/packages/backend`). Our extension runtime is deliberately different (HuntProxy-Plugins README: no sockets/files/processes/Node/fetch; bounded plan/analyze stages) — hosting a QuickSSRF-equivalent as a v1 plugin would require first granting extensions fetch + crypto + timers + secret stores, each its own security decision (runtime-v2 conversation). **Post-MVP follow-up:** expose a thin host bridge (`oast.create_label`, `oast.poll`) to the plugin runtime — same pattern as `sdk.findings.create` in flow/js — so vulnerability-class plugins (cache-analyzer, 403-bypasser) can consume OAST for blind confirmation while Rust keeps owning crypto, sessions, and sockets. Core MCP tool ships first; bridge is a fast-follow, not a blocker.

**Ecosystem note:** enigma's `core/engines/ssrf/interactsh.ts` and parallax's `src/oob.ts` poll a non-existent `GET /interactions` with `x-interactsh-token` — a speculative dialect mainline server does not serve; their OOB path silently no-ops against real interactsh-server. HuntProxy is the first correct client; enigma gains OOB by pointing `--canary` at HuntProxy-issued token URLs (enigma client fix is out of scope here).

User stories:
- As an agent, I call `oast create` and get a unique payload URL; I inject it via `fuzz_start`/`reply_send`/flows; later I call `oast poll` and see whether the target made contact (DNS lookup, HTTP fetch, headers, source IP).
- As a human running enigma, I point `--canary` at a HuntProxy-issued token URL and get confirmation through HuntProxy's poll instead of an external canary service.
- As an operator, I point HuntProxy at my own self-hosted interactsh-server (with optional auth token); the same server can back every tool in the stack once their clients speak the mainline protocol.

## Tech Stack

- Rust (existing HuntProxy workspace), `src/oast/` module
- Existing: `reqwest` (register/poll HTTP), `sha2`, `rand`, `url`, `serde_json`, axum routes, MCP tool table, tokio (background poller)
- New deps: `rsa` (RSA-2048 keygen + OAEP-SHA256 decrypt; interactsh provider), `aes` + `ctr` (AES-CTR interaction decrypt; interactsh provider), `zbase32` (nonce labels; or hand-roll the tiny encoder) — postbin/webhooksite/custom providers add **no new deps** (plain `reqwest` + `serde_json`)
- Hand-rolled: anonymous xid correlation-ids (20 chars, `[0-9a-v]` alphabet — 4-byte BE timestamp + 8 random bytes, base32-xid encode)
- SQLite via existing migration system (`017_oast.sql`)

## Interactsh Protocol Notes (verified against local clone — authoritative)

- Per session: RSA-2048 keypair; correlation-id (20-char anonymous xid); secret (UUID v4 string)
- `POST /register` `{public-key: base64(PEM(PKIX)), secret-key, correlation-id}`; `Authorization: {token}` when server `-auth`
- Payload label per URL: `cid(20) + zbase32(rand)[..13]`; host = `label.{domain}`
- `GET /poll?id=&secret=` → `{data[], aes_key, extra?, tlddata?}`; `extra`/`tlddata` are plaintext strings
- Decrypt: RSA-OAEP-SHA256(aes_key) with session private key → AES key; each data blob: b64 → IV(16B prefix) → AES-CTR → interaction JSON
- Interactions: `protocol`, `unique-id`, `full-id` (the 33-char label → per-case correlation), `raw-request`, `raw-response`, `remote-address`, `timestamp`
- Correlation-id alphabet: xid `[0-9a-v]`; server validates via `isCorrelationID` — our generated ids must match

## Provider Abstraction (all four QuickSSRF providers)

Rust trait living in HuntProxy **core** (`src/oast/providers/`), one implementation per provider. Note: the OAST client is core Rust, not a plugin — Caido ships QuickSSRF as a *plugin* only because their runtime grants ambient fetch/crypto/timers; ours deliberately doesn't (plugins get a thin `oast.*` bridge post-MVP, per runtime-v2 spec). QuickSSRF's TypeScript provider clients serve as the protocol reference we reimplement in async Rust:

```rust
trait OastProvider {
    fn kind(&self) -> ProviderKind; // Interactsh | Postbin | Webhooksite | Custom
    async fn register(&self, opts: &RegisterOptions) -> Result<RegisterResult>;
    async fn poll(&self, session: &ProviderSession) -> Result<Vec<Interaction>>;
    async fn deregister(&self, session: &ProviderSession) -> Result<()>; // no-op for bin-style providers
}
```

Unified `Interaction` shape (mirrors QuickSSRF `shared` — the TS clients will use the same fields): `{id, session_id, index, protocol, raw_request, raw_response, remote_address, timestamp, unique_id, full_id}`.

Per-provider notes (verified against local `proxy/caido-oss/quickssrf` source):

| Provider | Register | Poll | Payload URL | `new_url` | Stop |
|---|---|---|---|---|---|
| `interactsh` | RSA-2048 + `POST /register` (protocol section above) | `GET /poll?id=&secret=` + RSA-OAEP/AES-CTR decrypt | `cid(20)+zbase32(rand)[..13].{domain}` — fresh nonce label per URL | ✔ mint new label on same session | `POST /deregister` |
| `postbin` | `POST {server}/api/bin` → `{binId}` | `GET {server}/api/bin/{binId}/req/shift` — destructive, **one interaction per poll**, 204/404 = empty; source IP from `x-real-ip`/`cf-connecting-ip`/`x-forwarded-for` | `{server}/{binId}` — single URL per session | ✘ error: single-URL provider | no-op |
| `webhooksite` | `POST {server}/token` → `{uuid}` | `GET {server}/token/{uuid}/requests` — full list `{data:[{uuid,type,method,ip,content,created_at,url}]}`; dedupe by request `uuid` across polls | `{server}/{uuid}` — single URL per session | ✘ error | no-op |
| `custom` | no-op — URL is the configured `server` itself | `GET {server}` with optional `Authorization: Bearer {token}`; body = bare array or `{data|requests|events: []}`; fields `id/protocol/method/source/rawRequest/rawResponse/timestamp` | configured `server` as-is | ✘ error | no-op |

- **Session↔label model:** interactsh keeps the one-session-many-labels model; postbin/webhooksite/custom are one-URL-per-session (QuickSSRF parity — `new_url` rejected with a clear error naming the provider).
- **Poller:** the background poller walks all `watch=1` sessions regardless of provider; postbin's destructive shift means each poll drains at most one request (poll interval keeps up).
- **Defaults:** postbin → `https://www.postb.in`, webhooksite → `https://webhook.site` (public SaaS, QuickSSRF defaults); interactsh and custom **require** explicit `server` (interactsh also `domain`) — no public interactsh instance is ever baked in (self-host/enterprise opt-in, unchanged product stance).
- **TS clients (enigma/parallax):** interactsh-only fixes in their sibling specs; provider abstraction is HuntProxy-core scope.

## Project Structure

```
src/oast/mod.rs          # OastService: config, token issue, poll, decrypt, persist
src/storage/oast_store.rs # oast_sessions + oast_interactions tables
migrations/017_oast.sql
src/mcp/mod.rs           # + tool `oast` (actions: create, list, poll, interactions)
src/api/mod.rs           # + routes /api/v1/projects/{id}/oast[...] mirror
src/app/mod.rs           # AppState wiring (index-stage; crawler WIP)
src/config/mod.rs        # [oast] section
src/fuzzer/mod.rs        # payload generator type "oast"
tests/api_oast.rs        # integration vs mock poll server
```

## Config

Self-hosted mainline interactsh-server (same instance enigma/parallax *would* use once fixed). **Opt-in** — disabled until a server is configured (matches enigma's `INTERACTSH_*` env pattern; no public `oast.*` baked in):

```toml
[oast]
# Omit the section to disable the oast tool entirely.
provider = "interactsh"           # interactsh | postbin | webhooksite | custom
server = "https://oast.example.com"  # interactsh/custom: REQUIRED; postbin/webhooksite: default applied when empty
                                    # postbin default: https://www.postb.in ; webhooksite default: https://webhook.site
domain = "oast.example.com"       # interactsh payload domain (server -domain); required for interactsh
token = ""                        # interactsh server -auth token; custom provider Bearer token
poll_timeout_ms = 10000
auto_poll = true                  # background poller over watch sessions
poll_interval_ms = 5000           # background poll cadence
```

Env parity for ops: `HUNTPROXY_OAST_PROVIDER`, `HUNTPROXY_OAST_SERVER`, `HUNTPROXY_OAST_DOMAIN`, `HUNTPROXY_OAST_TOKEN` override config (the last three match enigma's `INTERACTSH_*` names).

### Provider registry (design B — user decision 2026-10-11)

Providers are managed like Caido/QuickSSRF's plugin (`Provider` rows + `defaultProviderId`), but the registry lives in HuntProxy **core** (protocol stays Rust, `oast.*` plugin bridge remains post-MVP):

- Global table `oast_providers` (daemon infrastructure, **not** project-scoped): `name UNIQUE`, `kind`, `server`, `domain`, `token`, `enabled`, `is_default`. Managed over MCP tool `oast_providers` (list/add/update/delete/set_default — project-less, like `extension_list`) and REST `/api/v1/oast-providers`.
- `[oast]` config remains: (a) the **seed** row (name `config`, upserted on first resolve; becomes default only when no default exists yet) and (b) the polling settings (`auto_poll`, `poll_interval_ms`, `poll_timeout_ms`).
- Session resolution order: explicit `provider_id` (must be enabled) → enabled default row → single enabled row → error (`Unavailable` when none, `InvalidArgument` when ambiguous). `create` accepts optional `provider_id`.
- Sessions **snapshot** `server`, `domain`, and `provider_token` at create → later registry edits never break in-flight polling; deleting a provider does not orphan its sessions.
- Tokens are write-only: views/REST/MCP expose `token_configured: bool` only. Provider management actions are **not** gated by `require_enabled` (chicken-egg: MCP-only bootstrapping needs `add` first).

## Data Model (migration 017)

- `oast_providers(id INTEGER PK, name UNIQUE, kind, server, domain NULL, token NULL, enabled, is_default, created_at, updated_at)` — global registry row (see provider registry above); disabling a default row clears `is_default`
- `oast_sessions(id INTEGER PK, project_id, provider_kind TEXT, correlation_id UNIQUE NULL, secret TEXT NULL, server, domain TEXT NULL, rsa_private_key_pem TEXT NULL, rsa_public_key_pem TEXT NULL, provider_meta TEXT NULL, provider_token TEXT NULL, label TEXT NULL, purpose, watch INTEGER, status, created_at, last_polled_at)` — `provider_kind` selects the registered provider implementation; `correlation_id`/`secret`/`rsa_*` are interactsh-only (NULL for bin-style providers); `provider_meta` (JSON) carries per-provider ids (`binId`, webhooksite `tokenId`); `provider_token` snapshots the registry token for poll/deregister auth — RSA private key + secret at rest like other host-side credentials; `watch=1` sessions are polled by the background poller
- `oast_interactions(id INTEGER PK, session_id FK, project_id, protocol, unique_id, full_id, remote_address, raw_request, raw_response, timestamp, received_at, UNIQUE(session_id, full_id, timestamp, protocol))` — `full_id` (33-char label for interactsh; bin/request ids otherwise) correlates interactions back to fuzz cases
- `oast_labels(id INTEGER PK, session_id FK, label, case_index INTEGER NULL, created_at, UNIQUE(session_id, label))` — per-URL nonce labels issued under an interactsh session; fuzz writes `case_index`; single-URL providers write exactly one synthetic label at register time

## MCP / API Surface

Single multi-action tool (house style: `capture_sessions`, `fuzz_manage`):

- `oast` action `create` → `{project_id, label?, purpose?, watch?, provider_id?}` → `{session_id, payload_url, correlation_id, server}` (issues first label; `watch` defaults true so the background poller picks it up; `provider_id` selects a registry row, otherwise default resolution applies)
- `oast` action `new_url` → `{project_id, session_id, label?, case_index?}` → `{payload_url, label}` — additional nonce label on an existing **interactsh** session (per-case fuzz tokens; no new registration); errors with a clear message on single-URL providers (postbin/webhooksite/custom)
- `oast` action `list` → sessions with interaction counts + last_polled_at
- `oast` action `poll` → `{project_id, session_id}` → polls server, persists new interactions, returns them (idempotent; empty array if none; manual trigger alongside background poller)
- `oast` action `interactions` → paged read of stored interactions for a session (optional `label` filter via full_id prefix)
- `oast` action `stop` → deregisters session (`POST /deregister`), marks stopped, excluded from poller
- `oast_providers` (project-less, like `extension_list`) → actions `list`/`add`/`update`/`delete`/`set_default` over the global registry; add takes `{name, kind, server, domain?, token?, enabled?}`, update takes `provider_id` plus optional fields (empty `token` clears it); responses expose `token_configured` only

REST mirror under `/api/v1/projects/{id}/oast*` for parity (thin client later), plus registry routes `GET|POST /api/v1/oast-providers`, `PATCH|DELETE /api/v1/oast-providers/{pid}`, `POST /api/v1/oast-providers/{pid}/default`.

## Fuzz Integration

- New payload generator: `{type: "oast"}` — at job start, creates **one oast session per fuzz job** (`watch=1`); for **interactsh**, issues **one `new_url` label per case** (recorded in `oast_labels.case_index`; no per-case registrations, RSA keygen once per job); for single-URL providers (postbin/webhooksite/custom) all cases share the session URL — per-case correlation unavailable, job result notes the shared URL
- `fuzz_manage` case results expose `oast_session_id`/`label` when present; `fuzz_manage` gains action `oast_poll` (poll the job's session, return interactions grouped by case via label)
- Correlation: interaction `full_id` == `{label}{cid}` → `oast_labels` → case_index — no auto-findings (agent decides)

## Background Poller

- Tokio task started with `OastService` when `auto_poll=true` and at least one `watch=1` session exists; interval `poll_interval_ms` (default 5s, clamped 1s–5min)
- Polls each active watch session once per tick (sequential, single attempt, bounded); persists interactions; never panics on poll errors (logs + continues)
- Manual `oast poll` always available and shares the same persist path (idempotent by unique constraint)
- On server "correlation id not found" (evicted): mark session `expired`, drop from poller, surface on next list/poll

## Security Boundaries

- Interaction raw-request/raw-response may contain target data → project-scoped like exchanges; not redacted (it is the evidence), never cross-project
- Secrets (correlation secret, auth token) never logged
- Poll failures surface as `DomainError` with bounded messages; no retry storm (single attempt per poll call)
- Payload URLs always point at the selected provider's server/domain — taken from the resolved registry row (config seed or user row) or the session snapshot, never from per-call tool input beyond choosing `provider_id` (no arbitrary host injection)
- Poll/register use `Authorization: {token}` header when configured; token and correlation secret never logged

## Testing Strategy

- Unit (`src/oast/mod.rs` tests): correlation-id shape (20 chars, `[0-9a-v]`); secret = UUID v4; label = cid + zbase32[..13]; RSA keygen + public-key PEM/base64 encoding round-trip; AES-CTR decrypt round-trip with locally generated fixture (RSA-OAEP wrap + CTR blob, mirroring Go client); config parse + opt-in gating
- Integration (`tests/api_oast.rs`): local hyper/axum mock serving `POST /register` + `GET /poll` with a valid RSA+CTR encrypted fixture (fixture generated in-test with the same crates) → `oast create` via API → `oast poll` decrypts, persists, lists, pages; `new_url` issues distinct labels; full_id→label correlation; cross-project read rejected; auth-token header asserted when configured
- Provider unit tests (in `src/oast/providers/`): postbin mock (`POST /api/bin`, destructive `GET /req/shift`, 204-empty, IP header extraction), webhooksite mock (`POST /token`, `GET /token/{uuid}/requests`, cross-poll dedupe by uuid), custom mock (bare array + `{data:[]}` shapes, Bearer header, field fallbacks); `new_url` rejected on all three with provider-named error; config defaults applied (postbin/webhooksite) and required-field validation (interactsh server+domain, custom server)
- Fuzz unit: oast generator creates one session + per-case labels (interactsh); single-URL providers reuse one URL across cases
- Fuzz unit: oast generator creates one session + per-case labels; bounds respected
- Poller unit: watch sessions polled on interval; non-watch skipped; expired marking on unknown-id
- No live network in CI; no real interactsh-server contact from tests

## Commands

```
export PATH="$HOME/.local/bin:$PATH" LIBCLANG_PATH=/usr/lib/llvm-21/lib BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/llvm-21/lib/clang/21/include"
cargo fmt
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
# final gate: push, gh run watch <id>, gh run view --log-failed on failure
```

## Boundaries

- **Always:** DomainError/ErrorCode for failures; migrations numbered sequentially; index-stage edits to crawler-interleaved files (`app/mod.rs`, `api/mod.rs`, `storage/migrations.rs`); fmt/clippy/test green; CI via gh as final gate
- **Ask first:** adding `rsa`/`aes`/`ctr`/`zbase32` to Cargo.toml; any change to this spec's data model
- **Never:** contact live interactsh servers from tests; log correlation secrets, RSA private keys, or auth token; commit crawler WIP files alongside; auto-create findings from interactions; shell out to an `interactsh-client` binary; implement the receiver (DNS/TLS/SMTP listeners)

## Success Criteria

- [ ] `oast create` returns a payload URL `{cid}{zbase32[..13]}.{domain}` and registers via `POST /register` with base64(PEM(PKIX)) public key + `Authorization` header when token set
- [ ] `oast poll` against mock server decrypts RSA-OAEP-wrapped AES key + AES-CTR blobs, persists, and returns interactions idempotently
- [ ] `oast new_url` issues distinct labels on one session; interactions' `full_id` maps back to `oast_labels.case_index`
- [ ] Provider selection honored: `provider = "postbin"|"webhooksite"|"custom"` registers/polls/deregisters per the provider table (mock-server tests); single-URL providers reject `new_url`; per-provider config defaults + required-field validation work
- [ ] Registry honored: `oast_providers add/update/delete/set_default` manage rows; token never serialized; `create(provider_id=…)` selects that row; default-row → single-row → error resolution order; config seed upserted once; registry-only setup (no `[oast]` config) gates create/open correctly
- [ ] Background poller polls `watch=1` sessions on interval; `stop` deregisters via `POST /deregister`
- [ ] Interactions are project-scoped; other project gets not-found
- [ ] Fuzz template accepts `{type:"oast"}` generator; cases carry unique payload URLs; sessions recorded on the job
- [ ] Unit + integration tests green locally; clippy/fmt clean outside crawler WIP; CI green on push
- [ ] Config `[oast]` honored (seed row + polling settings); disabled-with-no-registry setup returns clear Unavailable error on session actions

## Open Questions

1. ~~Token granularity?~~ **Resolved: protocol-native** — one session (registration + RSA keypair) per fuzz job or manual create; one nonce label per case via `oast new_url`; correlate by `full_id`. Matches nuclei's shared-session pattern; avoids N× RSA keygens.
2. ~~Background poller?~~ **Resolved: yes** — QuickSSRF/Burp/nuclei all auto-poll; HuntProxy is a 24/7 daemon, so a watch-session background poller ships in MVP (`auto_poll`, `poll_interval_ms`), plus manual `oast poll`.
3. ~~enigma doc note?~~ **Resolved: code fix, not doc-only** — enigma + parallax clients are corrected to mainline protocol as sibling modules (see `MAP-oast.md`, `SPEC-enigma-oast.md`, `SPEC-parallax-oast.md`). README gains a short `--canary="<payload_url>"` usage note at implement time.
4. ~~Multi-provider?~~ **Resolved: all four providers in MVP** (user direction 2026-10-11 — "can we also use all providers quickssrf uses?" → yes): interactsh (primary, self-hosted, full per-case label model), postbin, webhooksite, custom via the `OastProvider` trait above. postbin/webhooksite public SaaS defaults match QuickSSRF; interactsh/custom stay explicit-config opt-in. TS clients (enigma/parallax) remain interactsh-only per their specs.
