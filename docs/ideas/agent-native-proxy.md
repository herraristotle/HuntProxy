# HuntProxy: Agent-Native Security Engine

## Problem Statement

How might HuntProxy win a defined slice of the web-app security testing market when Burp (~20y incumbent, closed, expensive) and Caido (funded company, modern UI, plugins, workflows) already own the human-GUI buyer?

## Recommended Direction

**HuntProxy is a headless, agent-native security engine.** Humans never interact with a GUI directly — they talk to their AI agent (Claude, etc.), and the agent drives HuntProxy end-to-end via MCP: crawl → scope → replay → flows → findings.

This is not "Caido with AI bolted on." Burp AI and Caido AI are features layered onto GUI-first products. HuntProxy inverts the stack: the API/MCP surface is the product; any future UI is a view over it. The architecture already reflects this — MCP server, REST API, flows-as-reusable-automation, `sdk.findings.create`, a 43-workflow native pack, an autonomous crawler.

The desktop question is settled: **not now, and never Caido-class.** If a desktop ever materializes it is a thin Tauri shell rendering the existing REST API (history, findings, replay) — built only when (a) the itch is real and (b) the API already does everything. It is not a second product.

## Key Assumptions to Validate

- [ ] **Agents can drive real pentests through MCP today.** Test: run an autonomous crawl+scan against a real vulnerable app with the human only supervising; time it against a manual baseline. If it needs hand-holding, the core claim is false.
- [ ] **"Speed of automated testing" is demonstrable, not just claimed.** Needs a public demo/writeup (e.g., "Claude finds XSS in app X end-to-end, zero human clicks") before it counts as a wedge.
- [ ] **Paying users can come later from the open core** (hosted engine, team features) without pivoting to GUI. If 6-month revenue is non-negotiable, this direction conflicts — pick one.
- [ ] **Agent-native primitives are a moat, not just positioning.** The moat candidates: flows-as-agent-skills, the workflow pack, findings-as-API, crawl→plan→analyze loops. If Caido ships equivalent MCP next quarter and nobody notices, there was no moat.

## MVP Scope

In:
- MCP as the primary interface; keep extending it until every Burp-adjacent primitive is agent-callable (replay, scope, findings, crawl, scan jobs).
- One flagship public demo: fully autonomous vulnerability discovery on a real target, human only approves scope.
- Keep the engine headless: HTTP API + MCP in lockstep; no GUI code.
- Agent ergonomics: predictable errors, structured findings, resumable jobs — things an LLM can reason about.

Out (see Not Doing).

## Not Doing (and Why)

- **Full Caido-class desktop product** — multi-year solo trap; Caido/Burp add AI faster than you can add 20 years of GUI polish. Desktop ambition parked indefinitely; thin Tauri client only if the API is already complete and the itch is real.
- **Burp feature-list parity** (Sequencer, Comparer, DOM Invader, Collaborator, BApp store…) — a checklist of things an agent-driven engine *doesn't need* as GUI screens; most become API endpoints or flows when an agent actually asks for them.
- **Competing on GUI UX, plugins UI, project management UI** — distribution games the funded incumbent wins.
- **Bolting a chat box onto a proxy and calling it AI** — the inversion (agent-first, UI optional) is the whole point.
- **HTTPQL / Caido-importer compatibility in the runtime** — already removed; the native edition-1 format + workflow pack is the compatibility story.

## Open Questions

- What is the flagship demo target (a public deliberately-vulnerable app vs a real bug-bounty program)?
- MCP ergonomics audit: what can't an agent do today that it would reach for Burp/Caido to do?
- Revenue path if any: hosted engine? team features? or deliberately unmonetized portfolio piece with paid support later?
- When is "thin client" allowed to start? Explicit trigger (e.g., 3+ real users asking for a GUI, or your own third manual workflow through Claude) — not a date.
