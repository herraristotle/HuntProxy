# Capability Map: OAST Across the Stack

Three sibling modules. HuntProxy's Rust client is the reference implementation and covers the full provider set (interactsh mainline protocol verified against local `proxy/interactsh` clone, plus postbin/webhooksite/custom); enigma and parallax get their dead-dialect TS clients corrected to mainline interactsh so one self-hosted interactsh-server serves the whole stack.

| Module id | Responsibility | Depends on |
|---|---|---|
| huntproxy-oast | Core MCP/API OAST client in HuntProxy (see `SPEC-oast.md`): `OastProvider` trait with all four QuickSSRF providers (interactsh primary + postbin/webhooksite/custom), global provider registry (design B: `oast_providers` table + `oast_providers` MCP tool + `/api/v1/oast-providers`, `[oast]` config as seed), sessions, labels, poll, background poller, fuzz integration | — |
| enigma-oast | Fix enigma's `InteractshClient` (core/engines/ssrf/interactsh.ts) to mainline protocol: RSA-2048, xid cid, `/poll`, AES-CTR, `Authorization` header | — (protocol knowledge from `SPEC-oast.md`) |
| parallax-oast | Fix parallax's `InteractshClient` (src/oob.ts) the same way | — (protocol knowledge from `SPEC-oast.md`) |

Build order: huntproxy-oast → enigma-oast → parallax-oast (reference first; the two TS fixes are identical in shape and can share test-vector lessons).

Module specs: `SPEC-oast.md`, `SPEC-enigma-oast.md`, `SPEC-parallax-oast.md` (this directory).
