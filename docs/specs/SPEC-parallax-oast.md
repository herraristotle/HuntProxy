# Spec: parallax-oast (Mainline Interactsh Client Fix)

## Objective

Parallax's `src/oob.ts` `InteractshClient` has the same speculative-dialect defect as enigma's (`GET /interactions`, `x-interactsh-token`, UUID cid, no RSA) and silently no-ops against mainline interactsh-server. Fix it to the verified protocol so cache-poisoning OOB confirmation works against the shared self-hosted server.

## Scope

- Rewrite internals of `InteractshClient` in `src/oob.ts`
- Keep the exported API **unchanged**: `OobConfig`, `OobInteraction`, `FetchLike`, `oobConfigFromEnv(env)`, `register() / nextPayload() / pollOnce() / waitForInteraction() / isReady()` — consumers (`cache-poison.ts`, `cache-internal.ts`, `discover.ts`, `pipeline.ts`) unchanged
- Update `src/__tests__/oob.test.ts` to the new wire shape with in-test crypto fixtures (vitest)
- Default fetch stays lazy `node-fetch` import (parallax dependency model); RSA/CTR via `node:crypto`

## Protocol (authoritative — same as `SPEC-enigma-oast.md` / `proxy/interactsh/pkg/client/client.go`)

1. RSA-2048 keypair (`node:crypto`)
2. correlation-id: 20-char anonymous xid `[0-9a-v]` (4-byte BE timestamp + 8 random, xid base32)
3. secret-key: `randomUUID()`
4. Register: `POST /register` `{public-key: base64(PEM(DER-SPKI)), secret-key, correlation-id}` + `Authorization: {token}` header
5. `nextPayload()`: bare hostname `{cid}{zbase32(rand)[..13]}.{domain}` (single label)
6. Poll: `GET /poll?id=&secret=` (+ `Authorization`) → `{data[], aes_key}` → RSA-OAEP-SHA256 unwrap → AES-256-CTR (IV = first 16 bytes) → interaction JSON
7. Keep self-disable-on-register-failure and poll-error→`[]` resilience

## Testing

- Parallax house runner: vitest (`npx vitest run src/__tests__/oob.test.ts`)
- Same unit matrix as enigma spec (cid shape, register body/headers, payload format, `/poll` path, decrypt fixture, self-disable)
- No live network

## Boundaries

- Always: public API stable; vitest green
- Ask first: exported-name or env-var changes
- Never: contact real servers from tests; change pipeline/cache logic beyond oob.ts + its tests
