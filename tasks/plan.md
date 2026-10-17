# Implementation Plan: OAST + Plugin Architecture (approved 2026-10-11)

## Overview

Ship the four approved specs in build order: core multi-provider OAST client in HuntProxy (Rust), correct the two TS OOB clients to mainline interactsh, align plugin authoring layout with Caido conventions, then add the capability-bridge runtime v2. Specs are the source of truth: `SPEC-oast.md`, `MAP-oast.md`, `SPEC-enigma-oast.md`, `SPEC-parallax-oast.md`, `SPEC-plugin-packaging.md`, `SPEC-plugin-runtime-v2.md` (all in `docs/specs/`).

## Architecture Decisions (from approved specs)

- OAST client is HuntProxy **core Rust** (`src/oast/`), not a plugin; `OastProvider` trait with interactsh (full protocol) + postbin/webhooksite/custom (QuickSSRF-parity HTTP dances); one background poller over `watch=1` sessions; hand-rolled xid + zbase32 (no zbase32 crate)
- New Cargo deps (spec-approved): `rsa`, `aes`, `ctr`
- Migration `017_oast.sql`; enigma/parallax stay interactsh-only TS fixes; packaging = progressive `src/+build` layout, plain-JS stays valid; runtime v2 = bridges only (crypto/store/oast/net.external), no ambient authority

## Constraints (standing)

- **Never touch/commit crawler WIP** (`src/crawler/*` untracked, `migrations/016_*`, `src/storage/crawl_store.rs`); index-stage edits for interleaved files (`src/api/mod.rs`, `src/app/mod.rs`, `src/storage/migrations.rs`) via `git show HEAD:<path>` → transform → `hash-object -w` → `update-index --cacheinfo`
- Local cargo env: `export PATH="$HOME/.local/bin:$PATH" LIBCLANG_PATH=/usr/lib/llvm-21/lib BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/llvm-21/lib/clang/21/include"`
- Final gate: push + `gh run watch`; failed runs via `gh run view --log-failed` (strip ANSI)
- Specs gate: any data-model/spec deviation → STOP, ask

## Task List

### Phase 1: huntproxy-oast (Rust core)
- Task 1: Cargo deps + `[oast]` config (env parity, provider validation, gating) — S
- Task 2: Migration `017_oast.sql` + `src/storage/oast_store.rs` + index-stage registration — M
- Task 3: Provider trait + helpers (xid cid, zbase32, RSA/CTR) + interactsh provider + unit tests — L
- Task 4: postbin + webhooksite + custom providers + unit tests — M
- Task 5: `OastService` (create/new_url/list/poll/interactions/stop + background poller) — M
- Task 6: MCP `oast` tool + REST mirror + AppState wiring (index-stage) — M
- Task 7: Fuzz `{type:"oast"}` generator + `fuzz_manage` `oast_poll` — M
- Task 8: Integration tests `tests/api_oast.rs` (mock interactsh + bin-style mocks) — M

### Checkpoint: Phase 1
- [ ] fmt/clippy/test green (crawler WIP failures excluded); CI green on push; success criteria of SPEC-oast.md met

### Phase 2: TS client fixes
- Task 9: enigma-oast — mainline InteractshClient + tests (SPEC-enigma-oast.md) — M
- Task 10: parallax-oast — same shape in `src/oob.ts` + tests — M

### Checkpoint: Phase 2
- [ ] enigma + parallax test suites green; no live-network tests

### Phase 3: plugin-packaging (repo-side)
- Task 11: `scripts/build-plugin.mjs` (esbuild, digest write, validate) + workspace devDeps + one exemplar plugin migrated — S

### Phase 4: plugin-runtime-v2 (Rust core)
- Task 12: `crypto` module in QuickJS host (pure fns) + tests — M
- Task 13: `store` KV module + `store.use` capability + tests — M
- Task 14: `oast.*` bridge module + `oast.use` capability + tests — S (depends Task 5)
- Task 15: `net.external` op + `external_hosts` allowlist + schema/validator additive + tests — M
- Checkpoint: Phase 4 — fmt/clippy/test + CI

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Index-stage staging mistakes touching crawler WIP | Stage only transformed HEAD blobs; verify `git diff --cached --stat` shows only intended hunks; never `git add` whole interleaved files |
| rsa/aes API friction on OAEP-SHA256 | Follow rsa 0.9 `Oaep` + sha2 digest; unit round-trip test with locally generated fixture mirrors Go client |
| postbin destructive shift races with background poller | Poller sequential per session; unique constraint dedupes |

## Open Questions

None — all spec open questions resolved; proceed autonomously per approved specs.
