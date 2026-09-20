# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities through
[GitHub's private vulnerability reporting](https://github.com/getmcpm/mcp-guardbench/security/advisories/new)
rather than opening a public issue. We aim to acknowledge a report within **48 hours**
and will coordinate a fix and disclosure timeline with you.

## Scope

**In scope:** the benchmark runner (`runner/`) and adapter contract (`adapters/`) —
anything that could let a malicious case or adapter execute unintended code, corrupt
the scoreboard, or exfiltrate data when CI runs the suite.

**Not a vulnerability:** the benchmark corpus (`cases/`) intentionally contains
deliberately malicious JSON-RPC frames — prompt injection, credential exfiltration,
tool-poisoning payloads, and similar attack content — used as *test fixtures* to
measure guard detection. Finding malicious-looking content in `cases/` is expected,
not a report. A guard scoring a `pass` on an attack case is a benchmark result, not a
vulnerability in this repo — file that as a regular issue, or against the guard being
measured.

## Supported versions

This is a benchmark tool, not a versioned release; only `main` is supported.

## See also

[getmcpm/cli's `SECURITY.md`](https://github.com/getmcpm/cli/blob/main/SECURITY.md)
documents the disclosure process for the mcpm CLI itself, which this benchmark
measures but does not ship.
