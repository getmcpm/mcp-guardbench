# McpVanguard — adapter

Scores [`mcp-vanguard`](https://pypi.org/project/mcp-vanguard/) (MIT,
[provnai/McpVanguard](https://github.com/provnai/McpVanguard)) through its
published CLI. Nothing is imported; no detection logic is copied.

```bash
python3 -m venv .venv-vanguard && .venv-vanguard/bin/pip install mcp-vanguard==2.2.1
VANGUARD_BIN=.venv-vanguard/bin/vanguard \
  node runner/run.mjs --adapter "node adapters/mcp-vanguard/adapter.mjs" --name mcp-vanguard@2.2.1
```

## Read the score with these two caveats or do not quote it

**1. Layer-scoped, not the full composed proxy.** McpVanguard's real deployment
is `vanguard start --server "<cmd>"`, a stdio MITM proxy wrapping a real
upstream server. This adapter instead drives `vanguard benchmark-run`, which
evaluates each case through exactly **one named harness** — `rules_engine`,
`metadata_tool_list`, or `metadata_initialize` — read directly from source
(`core/rules_engine.py`, `core/metadata_inspection.py`), not the composed
pipeline a real deployment runs. **This under-represents the product**: a live
proxy might catch something a single layer in isolation misses (or vice
versa), and the semantic (L2, Ollama) and behavioral (L3) layers are not
exercised by this harness at all. Driving the real `vanguard start` proxy
against a synthetic upstream stub server would close this gap and is a known
next step, not yet built.

**2. It accepts 25 of 48 cases, and abstains on the other 23.** Verified by
reading `core/rules_engine.py` and `core/metadata_inspection.py`:
`rules_engine` reads `message.params` only (so it sees `tools/call` requests
and, incidentally, `elicitation/create`/`sampling/createMessage` requests,
since it does not gate on method); `metadata_tool_list`/`metadata_initialize`
read `message.result.{tools,instructions}`. **There is no harness that
inspects arbitrary tool-response or resource-content text** —
`behavioral_response` exists but only measures response *size*, not content —
so every `tools/call` **result** and `resources/read` result abstains here.
Those are exactly the carriers most of this corpus's credential-egress and
response-injection cases live on, so the scored slice skews toward
metadata/request-argument attacks and away from response-content attacks.

## Two behaviours any future adapter author must know

**Exit code is not a verdict channel here either.** `benchmark-run`'s exit
code reflects whether the batch's `actual_action` matched its
`expected_action` field — a pass/fail harness feature, not a run-health
signal. Since this adapter sends a placeholder `expected_action: "ALLOW"` for
every case (only `actual_action` is read), the process exits 1 on almost
every batch containing a real finding. Verdicts are parsed from
`--json-output` stdout unconditionally, ignoring the exit code — the same
lesson the Cisco adapter documents.

**JSON is a valid `.yaml` corpus file.** `benchmark-run --benchmark-file`
loads its corpus with `yaml.safe_load`, and JSON is a syntactic subset of
YAML — verified by execution. Case batches are therefore written as plain
JSON with a `.yaml` extension rather than hand-rolling a YAML serializer.

## Result, 2026-08-30 — `mcp-vanguard@2.2.1`, `--profile strict`, corpus v4

Scored 28/54 · abstained 26 · recall **27.8%** · fp-rate **0.0%** · precision
**100.0%** · exact-action 46.4% · 0 anomalies.

Corpus v4 added seven CVE-derived attack cases since the previous 2026-08-23
run (corpus v3, 48 cases); this guard misses all four of the new cases its
`rules_engine`/`tools/call` carrier covers (`cve-2025-53818`, `cve-2026-25546`,
`cve-2026-33980`, `cve-2026-39884`) and abstains on the rest, same as before.
The recall/coverage numbers above are **not comparable to the 2026-08-23
33.3%/25-of-48 figure** — different corpus, different denominator.

Full breakdown (by category, misses, carrier coverage) in
`out/scoreboard-mcp-vanguard@2.2.1-*.md`.
