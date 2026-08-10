# mcp-guardbench

**A guard-agnostic benchmark for MCP injection / exfil / tool-poisoning detection.**

A corpus of MCP JSON-RPC frames — attacks that a guard *should* flag and benign
traffic it *must not* — plus a runner that scores **any** guard, relay, or
client-side inspector through a simple stdio contract. mcpm ships as the
reference implementation; the point is that anyone can write an adapter and
compare.

> **Conflict of interest, stated up front.** This corpus was extracted from
> [`@getmcpm/cli`](https://github.com/getmcpm/cli)'s guard fixtures, and it is
> published by the same people. For its first 38 cases mcpm scored 100% **by
> construction** — the corpus was its own test suite. That was a baseline, not a
> result, and it was never evidence mcpm is better than anything.
>
> The benchmark is only worth something if others can run it and beat us on it.
> Two rules keep that honest: every guard is scored through **the artifact its
> own users run** — its published CLI, or its published library API — never
> through a vendored copy of its internals (see
> [`adapters/README.md`](adapters/README.md)); and CI never fails on a low
> score, only on an unhealthy run — so adding a case mcpm misses is a welcome
> contribution, not a broken build.
>
> That second rule has now been exercised for real: corpus v2 added 3 cases the
> then-current `@getmcpm/cli@0.26.3` **missed**, CI stayed green, and the result
> is still in the table below rather than erased once it was fixed. See
> [Current baseline](#current-baseline).

## Why

The serious MCP attacks — tool-description poisoning, rug-pulls, response
injection, credential phishing, context exfiltration — happen in **runtime
JSON-RPC traffic**. There is no shared, reproducible measuring stick for whether
a given guard actually catches them. Vendors self-report. This corpus is that
stick: versioned cases, an open schema, a language-agnostic runner, a scoreboard.

## Quickstart

```bash
# score the reference guard through a pinned published mcpm (no install needed)
MCPM_CMD="npx --yes @getmcpm/cli@0.27.0 guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.27.0
# → out/scoreboard-mcpm@0.27.0-<date>.md

# or whatever `mcpm` is already on your PATH
npm run bench:mcpm

# score your own guard — implement the stdio contract in any language
node runner/run.mjs --adapter "python my_guard_adapter.py" --name myguard
```

**Requires Node 22.9+** (that is `@getmcpm/cli`'s own floor, not the runner's —
the runner itself needs nothing newer than Node 16) and **`@getmcpm/cli` 0.25.0
or later**, which is where `guard inspect` was added. An older `mcpm` on your
PATH fails with `unknown command 'guard'`, which surfaces as 47 adapter errors
rather than as a version message. No dependencies.

The runner exits non-zero only on an **unhealthy run** — a case that got no
verdict, an adapter error, or adapter output it could not classify. **Never on a
low score.**

### Current baseline

| guard | recall | fp-rate | precision | exact-action | coverage |
|---|---|---|---|---|---|
| `@getmcpm/cli@0.28.0` | 100.0% | 0.0% | 100.0% | 100.0% | 47/47 |
| `@getmcpm/cli@0.27.0` | 100.0% | 0.0% | 100.0% | 100.0% | 47/47 |
| `@getmcpm/cli@0.26.3` | 88.9% | 0.0% | 100.0% | 93.6% | 47/47 |
| `cisco-ai-mcp-scanner@4.8.2` ⚠ YARA only | 25.0% | 28.6% | 50.0% | 46.7% | **15/47** |
| *naive baseline (substring match)* | 44.4% | 30.0% | 66.7% | 44.7% | 47/47 |

mcpm rows measured through `npx @getmcpm/cli@<version> guard inspect --json`; the Cisco row
through `mcp-scanner static`. Every guard is driven by its own published CLI.

**Corpus v3 (47 cases)** adds six benign cases written to break a substring matcher — see
[the floor](#the-floor-and-what-it-exposes-about-this-corpus) below. They are the first
cases here **not** extracted from mcpm's fixtures, and they moved three of the five rows.
Every row above was re-measured on v3; none is carried over from a smaller corpus.

> ### ⚠ The Cisco row is not comparable to the mcpm rows. Read this before quoting it.
>
> **It answered 47 of 47 and was *scored* on 15.** `mcp-scanner static` consumes
> tools/prompts/resources *list* output. It has no input path for tool responses,
> `tools/call` arguments, `initialize` instructions, or server-initiated
> `elicitation/create` / `sampling/createMessage` frames. The adapter returns
> `unsupported` on those 32 cases, and the runner excludes abstentions from every rate
> **in both directions** — they are neither misses nor clean passes. Its 25.0% recall is
> 2-of-8 on the slice it accepts, not 2-of-27 on the corpus, and its 28.6% fp-rate is
> 2-of-7 benign.
>
> **Its two false positives are not an artefact of our severity mapping.** `fp_rate`
> counts any non-pass on a benign case, so both would still be false positives if the
> adapter mapped them to `warn` instead of `block`. What they are is YARA-tier only, on a
> seven-case benign slice — a small denominator, and the analyzers we could not run are
> plausibly the ones that would contextualise a tool description.
>
> **It ran one of its three analyzers.** The default set is `api,yara,llm`; the other two
> need an API key and an LLM key, and a benchmark anybody can reproduce cannot require
> either. This under-represents the product, plausibly in exactly the semantic detection a
> reader would care most about. Score the full product by setting
> `MCP_SCANNER_ANALYZERS` — and label that row differently.
>
> **41 of the 47 cases were extracted from mcpm's own fixtures.** That is a structural
> home-field advantage, and it is the same self-concealing shape documented below, pointed
> outward. Seven of the 24 attack cases are Unicode-evasion (zero-width, bidi, ANSI,
> homoglyph, full-width) — a family mcpm normalises for by design, over-weighted relative
> to its real-world frequency, and four of Cisco's six misses fall in it. Cisco's scanner
> also detects typosquatting, transport exposure, and vulnerable packages — for which this
> corpus has no cases, so it earns no credit for detection we never tested. The six v3
> benign cases are the exception: they were written here, against no guard's
> implementation, and mcpm was measured on them like everyone else.
>
> **The block-vs-warn ladder is ours, not theirs.** It emits `is_safe` plus a severity and
> takes no position on blocking; mapping `HIGH`/`CRITICAL`→block and `MEDIUM`/`LOW`→warn is
> the adapter's choice and moves `exact-action` alone.
>
> Full detail and reproduction: [`adapters/cisco/README.md`](adapters/cisco/README.md).

### The floor, and what it exposes about this corpus

[`adapters/naive/adapter.mjs`](adapters/naive/adapter.mjs) is not a guard. It is eight
verbatim phrases and `String.includes` over the raw frame — no parsing, no normalisation,
no severity model, about thirty seconds of thought. It exists because **a score means
nothing without a floor**, and it is scored on the full corpus so any row can be compared
to it directly.

Publishing it immediately exposed two defects in this corpus, both ours. Corpus v3 is the
repair, and the numbers below are what the repair changed.

**1. Our benign corpus did not punish naive matching — now it does.** On corpus v2 the
baseline's false-positive rate was **0.0%** across all 14 benign cases. A dumb substring
matcher *should* trip on legitimate traffic: security changelogs describing an injection
CVE, a key-management server whose tools are about `~/.ssh`, a wallet server that
disclaims ever asking for a seed phrase. It did not, which meant the benign set was not
testing false-positive resistance at all, and every 0.0% in the table — mcpm's included —
was a weaker claim than it looked.

Six cases later the floor draws **30.0%**, and `@getmcpm/cli` still draws **0.0%**. That is
now a measurement rather than an artefact of an easy corpus. It is also the whole reason to
keep a floor: the number that mattered most was one nobody would have thought to question.

**2. The tools/list slice measured nothing on the false-positive axis.** On corpus v2, over
the 11 cases Cisco accepts, the naive baseline and `cisco-ai-mcp-scanner`'s YARA analyzer
drew the *same* false-positive rate — **0.0% each, on three benign cases**. Three benign
cases cannot separate a substring grep from a shipping scanner, and 0.0% against them is
not a measurement.

Four of the six v3 cases land on that carrier, and the FP axis came alive. Restricted to
the 15 cases Cisco now scores, the baseline runs **57.1% fp-rate** against YARA's
**28.6%** — Cisco halves it, which is real contextual signal a substring matcher does not
have. Recall did not move and was never tied: the floor scored **37.5%** against YARA's
**25.0%** on both corpora, so the substring floor has been ahead on recall the whole time.
Every one of these figures is one analyzer on a small slice; read them as directional, not
as a verdict on the product.

> An earlier revision of this section said the two "scored identically" on v2 and that "the
> tie broke". That was wrong, and the round-2 review caught it: only the false-positive
> rates ever tied. The recall gap was there from the start and we misread it.

Concretely: `tls-cert-rotation-tools-list` and `system-prompt-management-tools-list` fool
the baseline and Cisco passes them. `ssh-key-management-tools-list` and
`wallet-non-custodial-disclaimer` fool both. All four pass on every mcpm row.

**3. mcpm's lead over the floor is real, and now visible in both dimensions.** 44.4% → 100%
recall and 30.0% → 0.0% fp-rate, on identical cases. Whatever else is true of a
self-published benchmark, the reference guard is not merely pattern-matching the obvious —
and the case that most nearly caught it out was one written to catch it out.

We would rather publish a floor that embarrasses our own corpus than a scoreboard that
flatters it. Six cases is a start, not a fix: they were written by the same people who
maintain the reference guard, which is the exact provenance problem stated above. Benign
cases from outside this project are worth more than any of them.

**The 0.26.3 row is kept deliberately.** Corpus v2 added three cases —
`exfil-param-in-schema`, `credential-phishing-wallet-seed-phrase`,
`credential-phishing-card-cvv` — that the then-current release
missed, dropping its recall to 88.9%. Not because mcpm lacked those detectors:
it shipped all three and `mcpm guard list-signatures` advertised them. They were
unreachable *through the `guard inspect` seam this benchmark scores through*,
which composed fewer detectors than mcpm's own relay did.

The corpus could not have caught that while it was extracted from fixtures the
same incomplete pipeline validated — so the blind spot was invisible in the
guard, in its test suite, and here, simultaneously. That is the failure mode
this project exists to make visible, and erasing the evidence once it was fixed
would defeat the point.

[`@getmcpm/cli@0.27.0`](https://github.com/getmcpm/cli/pull/153) routes all
three detectors through one shared composition and restores 27/27 detections.
Both runs exit 0 — a low score has never failed CI here, and now that rule has
been exercised rather than assumed.

**What the second row actually taught us**, which was not what we expected: the hard part
of scoring a second guard was not detection quality, it was that guards do not agree on
what an input *is*. Every MCP-aware scanner we surveyed accepts tools/list-carried content
and nothing else. Without a way to say "this carrier is outside what I claim to inspect,"
those 32 cases would have been scored as misses — manufacturing a false negative against a
tool that never claimed to look there — or crashed the run outright. So the runner grew an
`unsupported` action before the row could be published honestly.

That is a benchmark-design result, not an mcpm result, and it generalizes: **a scoreboard
that cannot distinguish "did not detect" from "does not accept" measures scope and reports
it as capability.** Any guard whose input surface differs from mcpm's would have been
scored unfairly by the previous runner, including guards better than mcpm.

Two rows is still a thin field, and one of them is a partial-scope row. More adapters
remain the most useful contribution.

See [`adapters/README.md`](adapters/README.md) for the adapter contract.

## Corpus

47 single-frame cases today (24 attack, 20 benign, 3 warn-and-forward), each in
[`schema/case.schema.json`](schema/case.schema.json):

| bucket | must | maps to |
|---|---|---|
| `attacks/` | be flagged (`warn`/`block`) | OWASP-MCP-1 (tool-desc poisoning, line-jumping), -2 (response injection), -7 (path exfil), credential-phishing, exfil-param |
| `benign/`  | `pass` (false-positive floor) | realistic tools/list, file reads, i18n prose, "ignore" in legitimate docs |
| `warn/`    | `warn`, never `block` | injection in *retrieved* resource/prompt data (forward-with-warning) |

Provenance is **mixed, and each case says which it is.** 41 cases carry
`"provenance": "extracted"` (or no field, which predates the distinction): they come from
`@getmcpm/cli`'s hand-authored guard fixtures, which derive from **public** attack
methodology (Invariant Labs 2025, MCPoison CVE-2025-54136, Equixly/Pillar audits).
License-clean — no MCPTox artifacts copied. Six carry `"provenance": "native"`: written
here, against no guard's implementation, because **a corpus extracted from one guard's
fixtures cannot grow in a direction that guard cannot see** — the failure this project
exists to make visible. `cases/index.json` counts both.
⚠ **The corpus is deliberately pinned behind upstream, and re-extracting will change it.**
Corpus v3 = `@getmcpm/cli`'s fixtures as of **v0.28.0's release**, plus the six native
cases. Upstream has since grown to 55 single-frame fixtures; running the command below
today yields **61** cases and every published number above stops applying. The 14 extra are
held back on purpose: nine are TAG-block attacks added when mcpm shipped that coverage, and
importing a family the reference guard had just fixed would inflate its lead by
construction. Taking them is a corpus-balance decision that has to come with a re-measure of
every row, not a routine sync.

Regenerate/extend with `node scripts/extract-from-mcpm.mjs <path-to-getmcpm/cli>`
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

`coverage` splits three ways, and the distinction is load-bearing:

- **`scored`** — the guard returned a verdict and it counted.
- **`unsupported`** — the guard *answered*, declining the carrier as outside the input
  surface it claims. This is an **abstention, not a verdict and not a failure.** It is
  excluded from every rate in both directions: it is neither a miss nor a clean pass.
  Scoring an abstention as a miss measures scope and calls it capability; scoring it as a
  pass hands out credit for work not done.
- **`missingVerdict` / `adapterErrors`** — the guard was asked and did not answer. These
  are health problems and they fail CI.

`answered = scored + unsupported`. A run where `answered` is less than the corpus is
unhealthy; a run where `scored` is less than `answered` is merely **partial scope**, and
its rates describe only the slice it accepted. `scoredFraction` tells you how big that
slice was — read it before comparing two guards' numbers to each other.

**Abstention is self-reported and unverified.** A guard could abstain its way to a
flattering slice. That is why `scoredFraction` sits next to every rate and why the
markdown lists each abstained case with the reason the adapter gave: the claim is
auditable even though it is not enforced.

A note on two different counts of the same corpus: the scoreboard's
"expected-detection" figure is **27** — the 24 `attacks/` cases *plus* the 3
`warn/` cases, since both must be flagged. The bucket split is printed alongside
it so the two never appear to disagree.

Where the reference guard scores well, treat it as **construction, not evidence**
— the corpus began as its own test suite. Real signal comes from scoring *other*
guards, and from adding cases the reference guard misses. Corpus v2 did exactly
the latter and dropped mcpm's published recall to 88.9%; a benchmark whose author
always scores 100% is measuring nothing.

## ⚠ Handling

`cases/attacks/` contains live prompt-injection payloads. Do not paste them into
prompts or AI-assistant contexts, and keep the directory out of any passive
file-ingestion scope.

## Contributing

Three contributions matter most, and the first is new — it comes from what the naive
baseline exposed above:

1. **A benign case that a naive substring matcher gets wrong.** Corpus v3 took the floor's
   false-positive rate from 0.0% to 30.0%, which is the only reason mcpm's 0.0% means
   anything — but all six were written by the people who maintain the reference guard, so
   they cannot rule out the blind spot they were written to test. Realistic traffic that
   *looks* like an attack — security documentation quoting injection strings, a tool that
   legitimately manipulates SSH config, i18n prose, a changelog describing a CVE — is worth
   more to this benchmark right now than another attack case, and it is worth most of all
   coming from someone who did not write the guard.
2. **An adapter for another guard.** Implement the stdio contract in any
   language — see [`adapters/README.md`](adapters/README.md). The only rule is
   that it must drive the guard's own published artifact (CLI or public library
   API), never a vendored copy of its internals. If your guard only accepts some
   carriers, return `unsupported` for the rest rather than guessing — abstentions are
   excluded from the rates, not counted against you.
3. **A case the reference guard misses.** That is the point of the exercise, and
   CI will not fail for it. Include a `source` field citing the public
   methodology or writeup the case comes from — every case has to be traceable
   to a real technique, not invented to pad a score.

Cases follow [`schema/case.schema.json`](schema/case.schema.json). Keep them
single-frame for now; stateful (rug-pull / schema-drift) scenarios need a
stateful adapter contract and are deferred to v2.

## License

MIT — see [`LICENSE`](LICENSE).
