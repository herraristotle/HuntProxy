# Spec: enigma-oast (Mainline Interactsh Client Fix)

## Objective

Enigma's `core/engines/ssrf/interactsh.ts` `InteractshClient` speaks a speculative dialect that mainline interactsh-server does not serve (`GET /interactions`, `x-interactsh-token` header, UUID correlation-ids, no RSA). Its OOB path silently no-ops against a real self-hosted server. Fix it to the verified mainline protocol so `enigma-ssrf blind --watch` and canary confirmation work against the same interactsh-server HuntProxy uses.

## Scope

- Rewrite internals of `InteractshClient` in `core/engines/ssrf/interactsh.ts`
- Keep the exported API **unchanged**: `OobConfig`, `OobInteraction`, `FetchLike`, `oobConfigFromEnv(env)`, `client.register() / nextPayload() / pollOnce() / waitForInteraction() / isReady()` — consumers (`blind.ts`, `decision-trees.ts`, `index.ts`) must not need changes beyond tests
- Update `tests/ssrf-interactsh.test.ts` (and any blind.ts tests touching the client) to the new wire shape, with real crypto fixtures generated in-test
- No changes to SSRF engine logic, CLI flags, or env var names (`INTERACTSH_SERVER/DOMAIN/TOKEN` stay)

## Protocol (authoritative — mirror `proxy/interactsh/pkg/client/client.go`)

1. RSA-2048 keypair via `node:crypto` `generateKeyPairSync`
2. correlation-id: 20 chars `[0-9a-v]` — 4-byte BE unix timestamp + 8 crypto-random bytes, xid base32 encode (NOT `randomUUID()` — dashes/length fail server `isCorrelationID`)
3. secret-key: `randomUUID()` string
4. Register: `POST {server}/register`, body `{public-key, secret-key, correlation-id}` where public-key = `base64(PEM(DER-SPKI))` (PEM block type label irrelevant; server parses SPKI); auth = `Authorization: {token}` header (never `x-interactsh-token`)
5. `nextPayload()`: bare hostname `{cid(20)}{zbase32(rand)[..13]}.{domain}` (single label, official `URL()` shape; keep returning bare host — callers prepend `http://`)
6. Poll: `GET {server}/poll?id={cid}&secret={secret}` (+ `Authorization`) → `{data: string[], aes_key: string}`
7. Decrypt: `privateDecrypt(aes_key, {OAEP, sha256})` → AES key; each `data[i]`: base64-decode → IV = bytes[0..16] → AES-256-CTR decrypt → JSON interaction `{protocol, unique-id, full-id, raw-request, raw-response, remote-address, timestamp}`
8. Map to existing `OobInteraction` shape (protocol, remoteAddress←remote-address, fullId←full-id, rawRequest←raw-request); keep self-disable on register failure; decryption errors → treat as expired (return [] and disable, matching current resilience)

## Testing

- `npm test` / `node --experimental-strip-types --test ./tests/**/*.test.ts` (enigma house command)
- Unit: xid cid shape (20 chars, alphabet, timestamp prefix recent); register body contains public-key + Authorization header when token set; nextPayload = cid+13-suffix single label; pollOnce hits `/poll` (assert pathname), decrypts a fixture generated in-test with the same node:crypto primitives (RSA-OAEP wrap + CTR blob); register failure still self-disables
- No live network

## Boundaries

- Always: keep public API surface stable; tests green via enigma's test script
- Ask first: changing exported names or env vars
- Never: contact real servers from tests; weaken the self-disable behavior; change SSRF engine/CLI beyond the client + its tests
