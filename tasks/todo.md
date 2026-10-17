# Task List: OAST + Plugin Architecture

See `tasks/plan.md` and `docs/specs/` for design detail. Standing constraints: never touch crawler WIP; index-stage for interleaved files; cargo env exports required; CI via gh is the final gate.

## Phase 1: huntproxy-oast (Rust core)

### Task 1: Cargo deps + [oast] config
**Description:** Add `rsa`, `aes`, `ctr` to Cargo.toml; add `OastConfig` (`provider`, `server`, `domain`, `token`, `poll_timeout_ms`, `auto_poll`, `poll_interval_ms`) with `#[serde(default)]` on `Config`; env parity `HUNTPROXY_OAST_{PROVIDER,SERVER,DOMAIN,TOKEN}`; validation rules (interactsh requires server+domain; custom requires server; postbin/webhooksite defaults).
**Acceptance:**
- [x] Deps in Cargo.toml; config parses from TOML + env overrides
- [x] Validation rejects incomplete interactsh/custom config with clear error; defaults apply for postbin/webhooksite
**Verification:** unit tests in `src/config/mod.rs` (or oast config tests) pass; `cargo check` clean — DONE (9/9 tests, check clean)
**Dependencies:** None
**Files:** `Cargo.toml`, `src/config/mod.rs`
**Scope:** S
**Status:** COMPLETE 2026-10-11

### Task 2: Migration 017 + oast_store
**Description:** `migrations/017_oast.sql` per spec data model (`oast_sessions`, `oast_interactions`, `oast_labels`); `src/storage/oast_store.rs` with insert/get/list/update + interaction persist/dedupe + label mint/correlate; register migration in `src/storage/migrations.rs` via index-stage.
**Acceptance:**
- [x] Tables created; store CRUD + dedupe by unique constraint works (4/4 tests: session scoping, watch list, interaction dedupe/paging/label filter, label uniqueness)
- [x] `migrations.rs`/`mod.rs` registered (index-stage at commit time)
**Verification:** store unit tests pass — DONE
**Dependencies:** Task 1
**Files:** `migrations/017_oast.sql`, `src/storage/oast.rs`, `src/storage/mod.rs`, `src/storage/migrations.rs`
**Scope:** M
**Status:** COMPLETE 2026-10-11

### Task 3: Provider trait + interactsh provider
**Description:** `src/oast/providers/mod.rs` (trait, `Interaction`, kinds); helpers: anonymous xid correlation-ids (20 chars `[0-9a-v]`), zbase32 encoder (hand-rolled), RSA-2048 keygen + base64(PEM(PKIX)) public key, OAEP-SHA256 unwrap + AES-CTR decrypt; `providers/interactsh.rs`: register/poll/deregister/new label URL.
**Acceptance:**
- [x] Unit: cid shape; label = cid+zbase32[..13]; public-key encoding matches Go client expectations; decrypt round-trip with local fixture (RSA-OAEP wrap + CTR blob) — 11/11 tests incl. golden base32 vectors
- [x] `Authorization: {token}` header when token set; no secrets logged
**Verification:** `cargo test oast` unit tests green — DONE
**Dependencies:** Task 1
**Files:** `src/oast/mod.rs`, `src/oast/helpers.rs`, `src/oast/providers/{mod.rs,interactsh.rs}`
**Scope:** L
**Status:** COMPLETE 2026-10-11

### Task 4: postbin + webhooksite + custom providers
**Description:** Port QuickSSRF provider HTTP dances: postbin (`POST /api/bin`, destructive `GET /api/bin/{id}/req/shift`, 204/404-empty, IP header fallbacks), webhooksite (`POST /token`, `GET /token/{uuid}/requests`, dedupe by uuid), custom (GET URL + optional Bearer, array or `{data|requests|events}` shapes).
**Acceptance:**
- [x] Unit tests vs local mock servers for all three (wiremock; postbin shift/IP/raw-request, webhooksite list map, custom shapes+bearer+timestamp normalization)
- [x] `new_url` unsupported → clear provider-named error (tested on all three)
**Verification:** provider unit tests green — DONE (17/17 oast tests)
**Dependencies:** Task 3
**Files:** `src/oast/providers/{postbin.rs,webhooksite.rs,custom.rs,tests.rs}`
**Scope:** M
**Status:** COMPLETE 2026-10-11

### Task 5: OastService + background poller
**Description:** Orchestration per spec: create/new_url/list/poll/interactions/stop; provider dispatch by config; watch-session background poller (tokio interval, clamp 1s–5min, expired marking); single synthetic label row for bin-style providers.
**Acceptance:**
- [x] create returns payload_url; new_url errors on single-URL providers; poll persists idempotently; stop deregisters (interactsh) / no-op (others)
- [x] Poller polls watch sessions; non-watch skipped; expired marking on unknown-id (23/23 tests incl. timing test)
**Verification:** service unit tests with mock providers — DONE
**Dependencies:** Tasks 2–4
**Files:** `src/oast/mod.rs`
**Scope:** M
**Status:** COMPLETE 2026-10-11 (amended same day for design B: see Task 5b)

### Task 5b: Provider registry (design B)
**Description:** User decision 2026-10-11 ("B: Core provider registry"): global `oast_providers` table (+ `provider_token` snapshot column on sessions); `OastService` provider CRUD + `resolve_provider` precedence (explicit id → enabled default → single enabled → error); config `[oast]` becomes seed row (name `config`, upserted) + polling settings; async `require_enabled` (config OR enabled registry row); dispatch by session row kind/token (fixes interactsh poll/deregister auth — token now sent from `provider_token` snapshot); MCP `oast_providers` tool + REST `/api/v1/oast-providers`; `oast create` gains `provider_id`; drop `enabled()`/`mints_per_case_urls()` (fuzzer uses `session.provider == "interactsh"`); `start_poller` async (auto_poll + provider presence check).
**Acceptance:**
- [x] Migration 017 edited directly (uncommitted): `oast_providers` + `oast_sessions.provider_token`
- [x] Storage CRUD incl. upsert_config seed, default-on-insert, disable clears default
- [x] Service: registry CRUD (token never serialized, `token_configured` only), resolution, gates, row-based dispatch
- [x] MCP/REST plumbing (index-stage pending for api/app/proxy)
- [ ] `cargo check --all-targets` + `cargo test --lib` green (build in flight)
**Verification:** new unit tests in `src/oast/mod.rs` (registry-only enable, explicit id, default-vs-seed, ambiguity, disabled, CRUD conflicts, seed upsert)
**Dependencies:** Task 5
**Files:** `migrations/017_oast.sql`, `src/storage/oast.rs`, `src/oast/mod.rs`, `src/oast/providers/interactsh.rs`, `src/mcp/mod.rs`, `src/api/mod.rs`, `src/fuzzer/mod.rs`, `src/app/mod.rs`, `src/proxy/mod.rs`, `docs/specs/SPEC-oast.md`
**Scope:** M
**Status:** IN PROGRESS

### Task 6: MCP tool + REST mirror + AppState wiring
**Description:** MCP `oast` tool (actions create/new_url/list/poll/interactions/stop) per house style; REST `/api/v1/projects/{id}/oast*` mirror; `AppState.oast` wiring via index-stage edits to `src/app/mod.rs` + `src/api/mod.rs`; tool hidden/error when `[oast]` disabled.
**Acceptance:**
- [ ] MCP tool listed when enabled; clear error when disabled
- [ ] REST handlers project-scoped; cross-project → not-found
- [ ] Index-stage only for interleaved files
**Verification:** unit/schema tests + manual MCP call in dev; `git diff --cached` clean of crawler hunks
**Dependencies:** Task 5
**Files:** `src/mcp/mod.rs`, `src/api/mod.rs`, `src/app/mod.rs`
**Scope:** M

### Task 7: Fuzz generator + fuzz_manage oast_poll
**Description:** `{type:"oast"}` payload generator: one session per fuzz job; per-case labels (interactsh) or shared URL (bin-style, noted in job result); `fuzz_manage` action `oast_poll` grouping interactions by case via label.
**Acceptance:**
- [ ] Generator creates session + labels recorded with case_index
- [ ] oast_poll returns interactions grouped by case
**Verification:** fuzz unit tests
**Dependencies:** Task 5
**Files:** `src/fuzzer/mod.rs`
**Scope:** M

### Task 8: Integration tests
**Description:** `tests/api_oast.rs`: mock interactsh (register+poll with RSA/CTR fixture) end-to-end via REST; auth header asserted; cross-project rejected; mock postbin/webhooksite/custom flows; poller timing test; fuzz generator integration.
**Acceptance:**
- [ ] All success-criteria items of SPEC-oast.md covered
- [ ] No live network
**Verification:** `cargo test --locked --all-targets` green; checkpoint fmt/clippy
**Dependencies:** Tasks 1–7
**Files:** `tests/api_oast.rs`
**Scope:** M

## Checkpoint: Phase 1
- [ ] SPEC-oast.md success criteria met; crawler WIP untouched; CI green

## Phase 2: TS client fixes

### Task 9: enigma-oast
**Description:** Rewrite `core/engines/ssrf/interactsh.ts` per SPEC-enigma-oast.md: RSA-2048 keypair, xid cid (20 `[0-9a-v]`), UUID-v4 secret, base64(PEM(PKIX)) register, `Authorization` header, `/poll` + OAEP-SHA256 + AES-256-CTR decrypt, per-URL nonce labels; keep exported API stable (OobConfig, OobInteraction, FetchLike, oobConfigFromEnv, register/nextPayload/pollOnce/waitForInteraction/isReady); self-disable on register failure.
**Acceptance:**
- [ ] Unit tests updated (mainline dialect, decrypt round-trip, no live network)
- [ ] Consumers (`cli/commands/ssrf/blind.ts`, decision-trees, index) compile unchanged
**Verification:** enigma test suite green
**Dependencies:** None (protocol knowledge from spec; parallelizable)
**Files:** `enigma/core/engines/ssrf/interactsh.ts`, `enigma/tests/ssrf-interactsh.test.ts`
**Scope:** M

### Task 10: parallax-oast
**Description:** Same fix in `engines/parallax/src/oob.ts` + tests, keeping exported API stable.
**Acceptance:**
- [ ] Tests green; API surface unchanged
**Verification:** parallax test suite green
**Dependencies:** Task 9 (shared learnings)
**Files:** `parallax/src/oob.ts`, `parallax/src/__tests__/oob.test.ts`
**Scope:** M

## Checkpoint: Phase 2
- [ ] Both TS suites green; commits per repo

## Phase 3: plugin-packaging

### Task 11: build-plugin script + exemplar
**Description:** `HuntProxy-Plugins/scripts/build-plugin.mjs` (esbuild bundle → dist/index.js, write entrypoint_sha256, validate); workspace devDeps; migrate one exemplar plugin (e.g., jwt-analyzer) to `src/+package.json` layout; docs note in writing-plugins.md.
**Acceptance:**
- [ ] Script builds exemplar; validator green; digest updated automatically
- [ ] Plain-JS plugins unaffected
**Verification:** `node scripts/build-plugin.mjs plugins/jwt-analyzer` + validate
**Dependencies:** None
**Files:** `HuntProxy-Plugins/scripts/build-plugin.mjs`, `package.json`, one plugin dir, docs
**Scope:** S

## Phase 4: plugin-runtime-v2

### Task 12: crypto module
**Description:** Host-implemented `crypto` in plan/analyze QuickJS (randomBytes, createHash, createHmac, createCipheriv/Decipheriv aes-gcm/ctr, privateDecrypt OAEP-SHA256, base64/hex) — pure, no capability.
**Acceptance:** round-trip unit tests vs Rust fixtures; module present in all plugin jobs
**Verification:** `cargo test plugins`
**Dependencies:** None
**Files:** `src/plugins/` (crypto host module + JS glue)
**Scope:** M

### Task 13: store module + store.use
**Description:** Per-plugin KV in host DB; size cap; namespace isolation; capability `store.use` additive in schema v2 + validator.
**Acceptance:** CRUD tests; missing capability → module undefined
**Verification:** `cargo test plugins` + validator test
**Dependencies:** Task 2 (migration style; store tables may live in new migration 018)
**Files:** `src/plugins/`, `schemas/plugin-manifest-v2.json`, `HuntProxy-Plugins/scripts/validate-plugin.mjs`
**Scope:** M

### Task 14: oast bridge + oast.use
**Description:** JS-visible `oast.create/newUrl/poll/interactions` host bridge over OastService; capability `oast.use`.
**Acceptance:** fixture plugin mints URL + reads interactions in integration test; capability-gated
**Verification:** `cargo test plugins` + `cargo test oast`
**Dependencies:** Task 5
**Files:** `src/plugins/`, schema/validator additive
**Scope:** S

### Task 15: net.external + external_hosts
**Description:** `http_external` host op; `external_hosts` allowlist enforcement at plan+execute; save=false default; capability `net.external`; additive schema.
**Acceptance:** allowlisted fetch succeeds to mock; non-allowlisted fails at plan; missing allowlist → manifest rejected
**Verification:** `cargo test plugins`
**Dependencies:** Task 6 (op plumbing patterns)
**Files:** `src/plugins/`, schema/validator
**Scope:** M

## Checkpoint: Phase 4
- [ ] fmt/clippy/test green; CI green; runtime-v2 success criteria met
