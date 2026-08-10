# Cisco AI Defense MCP Scanner — adapter

Scores [`cisco-ai-mcp-scanner`](https://pypi.org/project/cisco-ai-mcp-scanner/)
(Apache-2.0, [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner))
through its published CLI. Nothing is imported; no detection logic is copied.

```bash
python3 -m venv .venv && .venv/bin/pip install cisco-ai-mcp-scanner==4.8.2
MCP_SCANNER_BIN=.venv/bin/mcp-scanner \
  node runner/run.mjs --adapter "node adapters/cisco/adapter.mjs" --name cisco@4.8.2-yara
```

## Read the score with these four caveats or do not quote it

**1. One of three analyzers.** The scanner's default analyzer set is `api,yara,llm`.
`api` requires `MCP_SCANNER_API_KEY` and `llm` requires an LLM key, so a run that any
third party can reproduce uses `--analyzers yara` only. **This under-represents the
product**, and the semantic detection a reader would most expect is plausibly in the two
analyzers we do not run. The adapter scrubs both key variables so a developer's local
credentials cannot silently convert a reproducible offline run into a networked one.
Set `MCP_SCANNER_ANALYZERS` to score the full product; label that row differently.

**2. It accepts 11 of 41 cases, and abstains on the other 30.** `mcp-scanner static`
consumes tools/prompts/resources *list* output. It has no input path for tool responses,
`tools/call` arguments, `initialize` instructions, or server-initiated
`elicitation/create` / `sampling/createMessage` frames. Those are recorded `unsupported`,
excluded from every rate in both directions. **The rates are computed over the 11-case
slice and are not comparable to a guard scored on the full corpus.**

**3. The corpus was extracted from mcpm's own fixture directory.** This is the
self-concealing shape mcpm documented in v0.27.0, pointed outward: a corpus shaped by one
guard's detection model cannot help but flatter that guard. Concretely — the Unicode
evasion family is over-weighted relative to its real-world frequency because mcpm shipped
TAG-block coverage in v0.28.0, days before this run. Cisco's scanner also detects
typosquatting, transport exposure, and vulnerable packages, for which this corpus contains
no cases at all, so it earns no credit for detection we simply never tested.

**4. The block-vs-warn ladder is ours, not the scanner's.** It emits `is_safe` plus a
severity string and takes no position on blocking. `HIGH`/`CRITICAL` → block,
`MEDIUM`/`LOW` → warn is a mapping this adapter chose; it moves `exact-action accuracy`
and nothing else.

## Result, 2026-08-09 — `cisco-ai-mcp-scanner@4.8.2`, YARA only

Scored 11/41 · abstained 30 · recall **25.0%** (2/8) · fp-rate **0.0%** (0/3) ·
precision 100% · 0 anomalies.

Missed, all on `tools/list` descriptions it *did* accept — capability, not scope:
`owasp-mcp-1-zwsp-in-description`, `-bidi-in-description`, `-ansi-in-description`
(hidden-character evasion), `-multitool-poisoning`, `-system-tag`, and
`exfil-param-in-schema` (no context-exfil property-key detector).

## Two behaviours any future adapter author must know

**Exit codes are not a verdict channel.** Measured: the scanner exits **0** on a HIGH
finding *and* exits **0** on `Error during scanning: Invalid tools file`. Gating on exit
status would score every attack as a pass at full confidence, silently — the same
false-green failure mode as a mocked-away dependency. Verdicts are parsed from
`--format raw`; anything that does not parse into the expected shape becomes `error`,
never `pass`. The adapter also fails closed when the scanner reports fewer scanned items
than were sent.

**A bare array is rejected.** `--tools` requires the `{"tools": [...]}` envelope; the raw
array from a JSON-RPC `result` produces `missing 'tools' key` — and, per the above, exit 0.
