# Scoreboard — mcpm@0.54.0

Corpus: 57 cases — 37 expected-detection (33 `attacks/` + 4 `warn/`), 20 benign. Scored 57.

| metric | value |
|---|---|
| recall (attack detection) | 86.5% |
| false-positive rate (benign) | 0.0% |
| precision | 100.0% |
| exact-action accuracy | 87.7% |

Confusion: TP 32 · FN 5 · FP 0 · TN 20

## By category (attack recall)

| category | detected / total | recall |
|---|---|---|
| MCP-CREDENTIAL-EXFIL | 2/3 | 67% |
| MCP-CREDENTIAL-PHISHING | 2/2 | 100% |
| MCP-COMMAND-INJECTION | 2/2 | 100% |
| MCP-CODE-INJECTION | 2/2 | 100% |
| MCP-QUERY-INJECTION | 1/1 | 100% |
| MCP-ARGUMENT-INJECTION | 0/1 | 0% |
| OWASP-MCP-1 | 9/11 | 82% |
| OWASP-MCP-2 | 11/12 | 92% |
| OWASP-MCP-7 | 3/3 | 100% |

## Misses (5)

- `cve-2026-25650-mcp-salesforce-token-disclosure` — missed attack (expected warn, got pass)
- `cve-2026-39884-mcp-server-kubernetes-argument-injection` — missed attack (expected block, got pass)
- `deadbugz-post-flip-tool-description-poisoning` — missed attack (expected block, got pass)
- `deadbugz-supply-chain-mongodb-tool-poisoning` — missed attack (expected block, got pass)
- `deadbugz-post-flip-prompt-exfil-instructions` — missed attack (expected warn, got pass)
