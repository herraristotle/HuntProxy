## Passive Scan Implementation Summary

**Created Files:**
1. `src/passive_scan/mod.rs` - Core service with `PassiveScanService`
2. `src/passive_scan/rules.rs` - 6 initial rules (security headers, CSP, cookies, info disclosure, XSS, SQL errors)
3. `src/storage/passive_scan_alerts.rs` - Alert persistence with deduplication
4. `migrations/018_passive_scan_alerts.sql` - Schema with severity/confidence/CWE

**Architecture:**
- Hook into proxy response flow
- Rule trait for extensibility
- Deduplication by hash(project_id, exchange_id, rule_id)
- Confidence scores (0-100), severity levels (info→critical)

**Rules Implemented:**
1. Missing security headers (X-Frame-Options, HSTS, X-Content-Type-Options)
2. Weak CSP (unsafe-inline, unsafe-eval, wildcards)
3. Insecure cookies (missing Secure, HttpOnly, SameSite)
4. Info disclosure (stack traces, paths, DB errors)
5. XSS reflection detection (parameter values in HTML)
6. SQL error patterns (MySQL, PostgreSQL, Oracle, SQL Server)

**Next Steps:**
- Integrate with proxy handler to auto-scan responses
- Add MCP tools (list_alerts, get_alert, enable_rule)
- Add more rules (CORS, XXE, command injection patterns)
