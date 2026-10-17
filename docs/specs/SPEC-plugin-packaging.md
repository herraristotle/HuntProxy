# Spec: Plugin Packaging v2 — Caido-Aligned Layout, Backend-Only First-Class

## Decision (2026-10-11)

Align the **authoring layout and build pipeline** of `HuntProxy-Plugins` with Caido's plugin repo conventions (`caido-oss/quickssrf`, official `create-plugin` templates) while keeping **our manifest schema and runtime contract**. Backend-only plugins are first-class (Caido's `no-frontend` template proves the model); frontend plugin support is explicitly reserved for the thin-client milestone and not built now.

## Answers To The Open Questions

- **"Same dir structure like caido-oss?"** — Yes, per-plugin: TypeScript source under `src/`, a build step producing the entrypoint bundle, manifest at plugin root, README, resources. We do **not** adopt Caido's per-plugin pnpm monorepo (`packages/backend` + `packages/frontend` + `caido.config.ts`) — overkill for our 10-plugin in-repo pack; the repo root already is the workspace.
- **"Backend no need for frontend?"** — Correct. Every existing plugin is backend-only; the host loads `plugin.json` + entrypoint and never requires a UI entry. Caido tooling ships a first-class `no-frontend` template for exactly this.
- **"Does the web UI need the plugin frontend?"** — No. The web UI is an operator console (history/editor), not a plugin host. Schema-v2's reserved `ui{}` section (routes/commands) is the future thin-client contract; nothing consumes it today, and the thin client is a separate milestone (see product one-pager). Backend plugins must degrade gracefully headless — agents are the primary caller.

## Per-Plugin Layout (target for new/ported plugins)

```
plugins/<id>/
├── plugin.json          # manifest v2 (kept name — loader/validator/docs reference it)
├── package.json         # dev-only: build script, typescript/esbuild devDeps
├── tsconfig.json
├── src/
│   └── index.ts         # plan/analyze entry (types from packages/plugin-dev)
├── dist/
│   └── index.js         # built bundle — the manifest `entrypoint`
├── README.md
├── resources/           # optional, unchanged
└── test/                # optional node:test suites (unchanged runner)
```

- `entrypoint` in `plugin.json` points at `dist/index.js`; `entrypoint_sha256` is the digest of that built file (integrity model unchanged)
- Plain-JS plugins (like the current 10) remain **valid without `src/`** — layout is progressive enhancement, not a breaking cut. Migrate on touch, no big-bang rewrite
- `dist/` **is committed** for this repo (plugins install by directory copy; no registry step yet — zip+sign is a later distribution phase)

## Build Pipeline

`scripts/build-plugin.mjs <plugin-dir>`:

1. esbuild bundle `src/index.ts` → `dist/index.js` (ESM, target ES2022, minify, no sourcemap; external: none — everything inlined like Caido's tsup pass)
2. Compute SHA-256 of the bundle; write it into `plugin.json` `entrypoint_sha256` (single source of truth — kills the manual digest step)
3. Run the existing `scripts/validate-plugin.mjs <plugin-dir>` as the gate

Workspace `package.json` gains `esbuild` + `typescript` devDeps; per-plugin `package.json` only wires `"build": "node ../../scripts/build-plugin.mjs ."`.

## What We Deliberately Do NOT Copy From Caido

| Caido convention | Why not us |
|---|---|
| `manifest.json` (renamed from `plugin.json`) | Cosmetic; our loader, validator, 10 plugins, and docs all speak `plugin.json` — churn without portability gain (their manifest lacks capabilities/limits/actions anyway, so a Caido plugin cannot drop in) |
| `caido.config.ts` + zod manifest generation | Our manifest is hand-authored JSON with a JSON-Schema validator already (`schemas/plugin-manifest-v2.json`); a generator adds a build-time dependency for zero runtime benefit |
| Per-plugin pnpm workspace + `packages/backend` nesting | One plugin = one directory in a pack repo, not a shippable standalone zip; monorepo-of-monorepos is ceremony |
| `plugin_package.zip` + Ed25519 `.sig` + store index | Distribution phase later (when we have a store); directory install + sha256 pinning suffices for now |
| Frontend packages, `@caido/frontend-sdk`, PrimeVue | No plugin UI surface exists; `ui{}` stays reserved in schema v2 |

## Migration Guide (existing 10 plugins)

Mechanical, per-plugin, when touched: add `package.json`/`tsconfig.json`, move `index.js` → `src/index.ts` (types from `packages/plugin-dev`), run build, commit `dist/` + updated `plugin.json`. Validator and host behavior unchanged — no HuntProxy-core code changes required for packaging (the runtime-v2 spec is the separate core work).

## Boundaries

- **Always:** validator green post-build; `entrypoint_sha256` updated by the build script only; plain-JS plugins keep loading; schema v2 unchanged (additive changes live in runtime-v2 spec)
- **Ask first:** renaming `plugin.json`; making `src/` mandatory; adding bundler config beyond esbuild single-file
- **Never:** require frontend packages for backend plugins; ship unsigned zip as trusted; break directory-install contract
