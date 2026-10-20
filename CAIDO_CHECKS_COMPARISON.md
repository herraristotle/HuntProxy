# Caido Scanner - Complete Check List (69 checks)

**Source:** caido-oss/scanner/packages/backend/src/checks/

---

## Passive Checks

### API Key & Token Disclosure (15 checks)
1. ✅ ai-key-disclosure (OpenAI, Anthropic)
2. ✅ aws-key-disclosure
3. ✅ azure-key-disclosure
4. ✅ cicd-token-disclosure (CircleCI, Travis, Jenkins)
5. ⚠️ credit-card-disclosure (HuntProxy: not implemented)
6. ✅ firebase-config-disclosure
7. ✅ gcp-key-disclosure (Google Cloud)
8. ✅ generic-api-key
9. ✅ github-token-disclosure
10. ⚠️ gitlab-token-disclosure (HuntProxy: not implemented)
11. ✅ jwt-disclosure
12. ✅ messaging-token-disclosure (Twilio, SendGrid, Mailgun)
13. ✅ payment-key-disclosure (Stripe)
14. ✅ private-key-disclosure (RSA, SSH)
15. ✅ slack-token-disclosure

### Sensitive File Disclosure (10 checks)
16. ✅ ds-store-disclosure (.DS_Store)
17. ✅ exposed-env (.env files)
18. ✅ git-config (.git/config)
19. ⚠️ npm-debug-log (HuntProxy: not implemented)
20. ✅ phpinfo (phpinfo.php)
21. ✅ robots-txt
22. ⚠️ security-txt (HuntProxy: not implemented)
23. ✅ sourcemap-disclosure (.map files)
24. ✅ svn-disclosure (.svn)
25. ✅ web-config-disclosure (web.config)
26. ⚠️ wordpress-readme (HuntProxy: not implemented)

### Framework Debug Detection (5 checks)
27. ✅ django-debug
28. ✅ laravel-debug
29. ✅ spring-actuator
30. ✅ symfony-profiler
31. ⚠️ debug-errors (generic debug pages - HuntProxy: partial via Node.js check)

### CSP Issues (8 checks)
32. ✅ csp-allowlisted-scripts
33. ✅ csp-clickjacking (missing frame-ancestors)
34. ✅ csp-form-hijacking (missing form-action)
35. ✅ csp-malformed-syntax
36. ✅ csp-not-enforced (missing CSP header)
37. ✅ csp-untrusted-script (unsafe-inline, unsafe-eval)
38. ⚠️ csp-untrusted-style (HuntProxy: not implemented)
39. ✅ anti-clickjacking (X-Frame-Options)

### Cookie Security (2 checks)
40. ✅ cookie-httponly
41. ✅ cookie-secure

### CORS & Security Headers (2 checks)
42. ✅ cors-misconfig
43. ⚠️ missing-content-type (HuntProxy: not implemented)

### Information Disclosure (11 checks)
44. ✅ application-errors (stack traces)
45. ⚠️ db-connection-disclosure (HuntProxy: not implemented)
46. ⚠️ directory-listing (HuntProxy: not implemented)
47. ⚠️ email-disclosure (HuntProxy: not implemented)
48. ⚠️ hash-disclosure (password hashes - HuntProxy: not implemented)
49. ⚠️ private-ip-disclosure (HuntProxy: not implemented)
50. ⚠️ ssn-disclosure (Social Security Numbers - HuntProxy: not implemented)
51. ⚠️ big-redirects (HuntProxy: not implemented)
52. ⚠️ json-html-response (HuntProxy: not implemented)
53. ⚠️ suspect-transform (HuntProxy: not implemented)
54. ⚠️ user-agent-dependent-response (HuntProxy: not implemented)

---

## Active Checks

### Injection Attacks (7 checks)
55. ✅ command-injection
56. ✅ path-traversal
57. ✅ reflected-xss (basic)
58. ⚠️ reflected-css-injection (HuntProxy: not implemented)
59. ✅ sql-injection (mysql-error-based, mysql-time-based)
60. ⚠️ sql-statement-in-params (HuntProxy: not implemented)
61. ✅ ssti (Server-Side Template Injection)

### GraphQL (3 checks)
62. ⚠️ graphql-endpoint (HuntProxy: passive detection only)
63. ⚠️ graphql-introspection (HuntProxy: not implemented)
64. ⚠️ graphql-content-type (HuntProxy: not implemented)

### Other Active (5 checks)
65. ⚠️ host-header-injection (HuntProxy: not implemented)
66. ⚠️ link-manipulation (HuntProxy: not implemented)
67. ✅ open-redirect
68. ⚠️ subdomain-takeover (HuntProxy: not implemented)
69. ⚠️ trace-method-enabled (HuntProxy: passive detection via OPTIONS)
70. ⚠️ xml-input-detection (HuntProxy: not implemented)

---

## Coverage Summary

| Category | Caido | HuntProxy | Coverage |
|----------|-------|-----------|----------|
| **API Key Disclosure** | 15 | 13 | 87% |
| **Sensitive Files** | 11 | 7 | 64% |
| **Framework Debug** | 5 | 4 | 80% |
| **CSP Issues** | 8 | 7 | 88% |
| **Cookie Security** | 2 | 2 | 100% |
| **CORS/Headers** | 2 | 1 | 50% |
| **Info Disclosure** | 11 | 1 | 9% |
| **Injection (Active)** | 7 | 5 | 71% |
| **GraphQL** | 3 | 0 | 0% |
| **Other Active** | 5 | 1 | 20% |
| **TOTAL** | **69** | **41** | **59%** |

---

## Missing Checks (28)

### High Priority (10)
1. credit-card-disclosure
2. db-connection-disclosure
3. directory-listing
4. email-disclosure
5. hash-disclosure
6. private-ip-disclosure
7. ssn-disclosure
8. host-header-injection
9. graphql-introspection
10. subdomain-takeover

### Medium Priority (11)
11. gitlab-token-disclosure
12. npm-debug-log
13. security-txt
14. wordpress-readme
15. csp-untrusted-style
16. missing-content-type
17. reflected-css-injection
18. sql-statement-in-params
19. graphql-endpoint (active)
20. graphql-content-type
21. link-manipulation

### Low Priority (7)
22. big-redirects
23. json-html-response
24. suspect-transform
25. user-agent-dependent-response
26. xml-input-detection
27. debug-errors (generic)
28. trace-method-enabled (active)

---

## Next Steps

Implement high priority missing checks (~800 lines):
1. PII disclosure (credit cards, SSN, emails, hashes)
2. Infrastructure issues (directory listing, db connection strings)
3. GraphQL security (introspection, endpoint discovery)
4. Host header injection
5. Subdomain takeover detection

