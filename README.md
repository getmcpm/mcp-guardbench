<!-- NAME IS A WORKING TITLE. "MCPTox" is already a published benchmark; this
     repo needs its own name before any public release. Candidates: mcp-guardbench,
     guardbench, mcp-redteam-corpus. Decide before publishing. -->

# mcp-guardbench *(working title — see note below)*

**A guard-agnostic benchmark for MCP injection / exfil / tool-poisoning detection.**

A corpus of MCP JSON-RPC frames — attacks that a guard *should* flag and benign
traffic it *must not* — plus a runner that scores **any** guard, relay, or
client-side inspector through a simple stdio contract. mcpm ships as the
reference implementation; the point is that anyone can write an adapter and
compare.

> **Status: pre-publication draft.** Local only. Not yet on GitHub, not yet
> named. Built as the "give away the measuring stick" spoke of the mcpm trust
> flywheel (see `@getmcpm/cli` `docs/VISION.md`). A benchmark only builds trust
> if others can run it and beat you on it — so it lives outside the mcpm repo
> and treats mcpm as one subject among many.

## Why

The serious MCP attacks — tool-description poisoning, rug-pulls, response
injection, credential phishing, context exfiltration — happen in **runtime
JSON-RPC traffic**. There is no shared, reproducible measuring stick for whether
a given guard actually catches them. Vendors self-report. This corpus is that
stick: versioned cases, an open schema, a language-agnostic runner, a scoreboard.

## Quickstart

```bash
# score the reference guard (mcpm)
node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm
# → out/scoreboard-mcpm-<date>.md

# score your own guard — implement the stdio contract in any language
node runner/run.mjs --adapter "python my_guard_adapter.py" --name myguard
```

See [`adapters/README.md`](adapters/README.md) for the adapter contract.

## Corpus

33 single-frame cases today (19 attack, 11 benign, 3 warn-and-forward), each in
[`schema/case.schema.json`](schema/case.schema.json):

| bucket | must | maps to |
|---|---|---|
| `attacks/` | be flagged (`warn`/`block`) | OWASP-MCP-1 (tool-desc poisoning, line-jumping), -2 (response injection), -7 (path exfil), credential-phishing, exfil-param |
| `benign/`  | `pass` (false-positive floor) | realistic tools/list, file reads, i18n prose, "ignore" in legitimate docs |
| `warn/`    | `warn`, never `block` | injection in *retrieved* resource/prompt data (forward-with-warning) |

Provenance: extracted from `@getmcpm/cli`'s hand-authored guard fixtures, which
derive from **public** attack methodology (Invariant Labs 2025, MCPoison
CVE-2025-54136, Equixly/Pillar audits). License-clean — no MCPTox artifacts
copied. Regenerate/extend with `node scripts/extract-from-mcpm.mjs`.

**Deferred to v2:** stateful schema-drift / rug-pull scenarios (two frames + a
pin) need a stateful adapter contract; the single-frame v1 contract omits them.

## Reading a scoreboard

`recall` = attacks detected · `fp_rate` = benign wrongly flagged · `precision`
= detections that were real attacks · `exact_action_accuracy` = also matches
`block` vs `warn`. The reference guard scores 100% across the board **by
construction** (the corpus is its own test suite); that is a baseline, not a
boast. Real signal comes from scoring *other* guards and from adding cases the
reference guard misses.

## ⚠ Handling

`cases/attacks/` contains live prompt-injection payloads. Do not paste them into
prompts or AI-assistant contexts, and keep the directory out of any passive
file-ingestion scope.

## License

MIT — see [`LICENSE`](LICENSE).
