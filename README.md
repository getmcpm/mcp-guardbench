# mcp-guardbench

**A guard-agnostic benchmark for MCP injection / exfil / tool-poisoning detection.**

A corpus of MCP JSON-RPC frames — attacks that a guard *should* flag and benign
traffic it *must not* — plus a runner that scores **any** guard, relay, or
client-side inspector through a simple stdio contract. mcpm ships as the
reference implementation; the point is that anyone can write an adapter and
compare.

> **Conflict of interest, stated up front.** This corpus was extracted from
> [`@getmcpm/cli`](https://github.com/getmcpm/cli)'s guard fixtures, and it is
> published by the same people. So mcpm scores 100% here **by construction** —
> the corpus is its own test suite. That is a baseline, not a result, and it is
> not evidence mcpm is better than anything.
>
> The benchmark is only worth something if others can run it and beat us on it.
> Two rules keep that honest: every guard is scored through **the artifact its
> own users run** — its published CLI, or its published library API — never
> through a vendored copy of its internals (see
> [`adapters/README.md`](adapters/README.md)); and CI never fails on a low
> score, only on an unhealthy run — so adding a case mcpm misses is a welcome
> contribution, not a broken build.

## Why

The serious MCP attacks — tool-description poisoning, rug-pulls, response
injection, credential phishing, context exfiltration — happen in **runtime
JSON-RPC traffic**. There is no shared, reproducible measuring stick for whether
a given guard actually catches them. Vendors self-report. This corpus is that
stick: versioned cases, an open schema, a language-agnostic runner, a scoreboard.

## Quickstart

```bash
# score the reference guard through a pinned published mcpm (no install needed)
MCPM_CMD="npx --yes @getmcpm/cli@0.26.0 guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.26.0
# → out/scoreboard-mcpm@0.26.0-<date>.md

# or whatever `mcpm` is already on your PATH
npm run bench:mcpm

# score your own guard — implement the stdio contract in any language
node runner/run.mjs --adapter "python my_guard_adapter.py" --name myguard
```

**Requires Node 22.9+** (that is `@getmcpm/cli`'s own floor, not the runner's —
the runner itself needs nothing newer than Node 16) and **`@getmcpm/cli` 0.25.0
or later**, which is where `guard inspect` was added. An older `mcpm` on your
PATH fails with `unknown command 'guard'`, which surfaces as 38 adapter errors
rather than as a version message. No dependencies.

The runner exits non-zero only on an **unhealthy run** — a case that got no
verdict, an adapter error, or adapter output it could not classify. **Never on a
low score.**

### Current baseline

| guard | recall | fp-rate | precision | exact-action | coverage |
|---|---|---|---|---|---|
| `@getmcpm/cli@0.26.0` | 100.0% | 0.0% | 100.0% | 100.0% | 38/38 |

Measured through `npx @getmcpm/cli@0.26.0 guard inspect --json`. Again: 100% is
**by construction** (see the note at the top) — it is here so you can check your
adapter is wired up correctly, and so the number has a name and a version
attached instead of being a vendor claim.

This table has exactly one guard in it. That is the honest state of the field
right now, and the most useful contribution is a second row.

See [`adapters/README.md`](adapters/README.md) for the adapter contract.

## Corpus

38 single-frame cases today (21 attack, 14 benign, 3 warn-and-forward), each in
[`schema/case.schema.json`](schema/case.schema.json):

| bucket | must | maps to |
|---|---|---|
| `attacks/` | be flagged (`warn`/`block`) | OWASP-MCP-1 (tool-desc poisoning, line-jumping), -2 (response injection), -7 (path exfil), credential-phishing, exfil-param |
| `benign/`  | `pass` (false-positive floor) | realistic tools/list, file reads, i18n prose, "ignore" in legitimate docs |
| `warn/`    | `warn`, never `block` | injection in *retrieved* resource/prompt data (forward-with-warning) |

Provenance: extracted from `@getmcpm/cli`'s hand-authored guard fixtures, which
derive from **public** attack methodology (Invariant Labs 2025, MCPoison
CVE-2025-54136, Equixly/Pillar audits). License-clean — no MCPTox artifacts
copied. Regenerate/extend with `node scripts/extract-from-mcpm.mjs <path-to-getmcpm/cli>`
— it reads the upstream fixtures, so it needs a checkout of
[getmcpm/cli](https://github.com/getmcpm/cli) (it defaults to a sibling `../cli`
directory). The generated cases are committed, so this is only needed when the
upstream corpus grows; cloning this repo alone is enough to *run* the benchmark.

**Deferred to v2:** stateful schema-drift / rug-pull scenarios (two frames + a
pin) need a stateful adapter contract; the single-frame v1 contract omits them.

## Reading a scoreboard

`recall` = attacks detected · `fp_rate` = benign wrongly flagged · `precision`
= detections that were real attacks · `exact_action_accuracy` = also matches
`block` vs `warn`.

Every scoreboard also reports `coverage` — how many cases actually got a verdict
— and a **partial run is banner-marked at the top of the markdown**. Read that
first. Every rate is computed over only the cases that answered, so an adapter
that drops the cases it would fail otherwise reports a clean 100%; that is the
failure mode that quietly overstates a guard, and it is why an unhealthy run is
the one thing that fails CI.

A note on two different counts of the same corpus: the scoreboard's
"expected-detection" figure is **24** — the 21 `attacks/` cases *plus* the 3
`warn/` cases, since both must be flagged. The bucket split is printed alongside
it so the two never appear to disagree.

The reference guard scores 100% across the board **by construction** (the corpus
is its own test suite); that is a baseline, not a boast. Real signal comes from
scoring *other* guards and from adding cases the reference guard misses.

## ⚠ Handling

`cases/attacks/` contains live prompt-injection payloads. Do not paste them into
prompts or AI-assistant contexts, and keep the directory out of any passive
file-ingestion scope.

## Contributing

Two contributions matter most:

1. **An adapter for another guard.** Implement the stdio contract in any
   language — see [`adapters/README.md`](adapters/README.md). The only rule is
   that it must drive the guard's own published artifact (CLI or public library
   API), never a vendored copy of its internals.
2. **A case the reference guard misses.** That is the point of the exercise, and
   CI will not fail for it. Include a `source` field citing the public
   methodology or writeup the case comes from — every case has to be traceable
   to a real technique, not invented to pad a score.

Cases follow [`schema/case.schema.json`](schema/case.schema.json). Keep them
single-frame for now; stateful (rug-pull / schema-drift) scenarios need a
stateful adapter contract and are deferred to v2.

## License

MIT — see [`LICENSE`](LICENSE).
