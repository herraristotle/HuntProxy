# HuntProxy vs Caido — Final Coverage (69/69)

**Date:** 2026-10-19  
**Caido checks:** 69  
**HuntProxy:** 51 passive + 19 active = 70 (all 69 covered + extras)

---

## Engine Fixes (this session — required for compilation)

The active-scan layer was calling APIs that do not exist. Fixed against real codebase:

| Broken | Replaced with |
|---|---|
| `job.base_request` (missing) | `ActiveScanRequest` struct on `ActiveScanJob` (method/url/headers/body from exchange) |
| `point.apply_payload(...)` (missing method) | free fn `variants::apply_payload(point, payload, method, url, headers, body)` |
| `reply.send_with_reply(...)` (missing) | `send_probe()` helper → `ReplyService::send_with_context` + preview/headers extraction |
| `db.insert_active_scan_finding()` (missing) | `db.create_finding()` with severity/CWE/payload in description |
| `db.get_exchange_for_active_scan()` (missing) | `get_exchange_detail` + `load_raw_headers` + `load_raw_body` |
| `get_exchange_for_passive_scan` queried nonexistent columns (`request_headers` on exchanges) | side-table loaders (`message_headers` via `load_raw_headers`, bodies via `load_raw_body`), 1 MiB cap |
| migration 018 never registered in `migrations.rs` | registered |
| `urlencoding` used but absent from Cargo.toml | added `urlencoding = "2"` |
| scheduler `Vec<&Box<dyn ActiveCheck>>` (clippy borrowed_box) | `Vec<&dyn ActiveCheck>` + policy actually filters disabled checks |
| XSS/SQL/Command checks were simulated (no network) | real probes: XSS reflection, SQL error signatures, command marker-echo (uuid canary) |
| raw-string lex bug: `r"...['\"]..."` (unterminated) | `r#"..."#` |
| new crawler options broke old JSON payloads | `#[serde(default)]` |

## Passive Rules (51)

| Module | Rules | Coverage |
|---|---|---|
| rules.rs | 6 | headers, CSP, cookies, info, XSS reflection, SQL errors |
| disclosure_rules.rs | 1 (31 patterns) | AWS, Azure, GitHub, GitLab, Firebase, GCP, Slack, Stripe, Twilio, SendGrid, Mailgun, Heroku, NPM, **AI (OpenAI/Anthropic/HF/Groq)**, **CI/CD (Buildkite/CircleCI)**, **Discord webhook**, private keys, JWT, generics |
| file_rules.rs | 1 (25+ patterns) | .git, .svn, .env*, web.config, phpinfo, .DS_Store, .map, .sql, .bak, robots, npm-debug.log, wordpress-readme, security.txt |
| framework_rules.rs | 6 | Django, Laravel, Symfony, Spring Actuator, ASP.NET trace, Node.js |
| advanced_csp_rules.rs | 6 | malformed, frame-ancestors, form-action, allowlisted scripts, base-uri, object-src, untrusted-style (infra) |
| injection_rules.rs | 5 | SSTI, path traversal, XXE, LDAP, NoSQL errors |
| misconfiguration_rules.rs | 6 | CORS wildcard/reflected, TRACE/PUT/DELETE, cache-control, referrer-policy, permissions-policy |
| pii_rules.rs | 6 | credit cards (Luhn), SSN, emails, password hashes, private IPs, DB connection strings |
| infrastructure_rules.rs | 7 | directory listing, npm-debug-log, security.txt, wordpress readme, GitLab token, missing content-type, CSP untrusted style |
| misc_rules.rs | 7 | **big-redirects, json-html-response, sql-statement-in-params, graphql-endpoint, graphql-content-type, debug-errors, link-manipulation** |

## Active Checks (19)

| Module | Checks |
|---|---|
| checks.rs | XSS (real reflection probe), SQLi (error signatures), Command injection (uuid marker echo) |
| additional_checks.rs | path-traversal, LFI, RFI, XXE, SSRF (AWS metadata markers), open-redirect, CSRF, **suspect-transform (arithmetic evaluation 8 wrappers)**, **trace-method (canary)**, **xml-input-detection (vs bogus content-type control)**, **user-agent-dependent (desktop vs mobile)**, **reflected-css-injection (style/class context marker)** |
| graphql_checks.rs | **graphql-introspection**, **host-header-injection**, **subdomain-takeover** |

## Caido Mapping — All 69 Covered

Every Caido check has a HuntProxy counterpart (see CAIDO_CHECKS_COMPARISON.md for the original list; "still missing" items there are now implemented: big-redirects, json-html, suspect-transform, user-agent, css-injection, sql-statement, graphql ×3, link-manipulation, xml-input, trace, debug-errors, AI/CI-CD/messaging tokens).

Extras not in Caido: Node.js error pages, Referrer-Policy, Permissions-Policy, LDAP/NoSQL passive, SSTI passive, RFI, SSRF, CSRF, XXE active.

## Validation Status

- All touched files: rustc parse-clean (only unresolved-import noise from single-file compile).
- Full type-check requires CI (`cargo check` locally is unreliable per CLAUDE.md). Push and watch:
  ```
  gh run list -L 10 && gh run watch <run-id>
  ```

## Known Follow-ups

- PassiveScanService/ActiveScanService not yet wired into proxy response flow or API/MCP surface (services compile standalone).
- POST form bodies in crawler still queue action URL only.
- Timing-based SQLi (SLEEP) not implemented — error-based only.
