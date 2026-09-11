# A standards-compliant `notifications/tools/list_changed` slipped a rug-pull past our MCP guard. Here is the frame-by-frame reproduction.

## The campaign in three sentences

Pillar Security disclosed "Deadbugz" on 2026-08-12: a malicious MCP server distributed
through 23 pull requests opened from a single GitHub account (`zellkernel`) against
unrelated AI/MCP/dev-tool projects in a 74-minute window on 2026-08-10 (Pillar Security,
"Deadbugz: Currently Active MCP Supply-Chain Campaign", 2026-08-12,
<https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign>).
The server keeps an in-memory per-client counter of `tools/call` requests, stays benign
through the first three, and past that threshold flips its `tools/list` and `prompts/get`
responses to steer the agent toward SSH keys, AWS credentials, shell history, and
Kubernetes config while concealing the step from the user (same source). The post states
only that "the public code advertises tools.listChanged, which allows a compatible client
to refresh tool metadata" — the advertised *capability*, not a captured
`notifications/tools/list_changed` frame, and it does not say the server sends one. The
reproduction below, built by the guard's own maintainers, models the server as actually
sending that notification: a client that connected before the third call already fetched
the benign list at `initialize`, so absent a re-list it goes on using it
(getmcpm/cli@707be738:`src/guard/__tests__/deadbugz.test.ts`, docstring).

## The miss

On 2026-08-31, `getmcpm/cli` commit `707be738` ("test(guard): reproduce the Deadbugz
runtime-gated rug-pull sequence") drove that exact multi-frame sequence through the
relay's real building blocks — `inspectForDriftSync`, `isToolsListChangedNotification`,
`inspectFrame`, `applyPolicy`, the same functions `run-inner.ts`'s `inspectChild` composes
— instead of arguing about it. At that commit the first test was named `GAP: benign list
-> 3 calls -> list_changed -> poisoned list is UNDETECTED` and asserted
`flipped.action` to be `"pass"` with zero findings
(getmcpm/cli@707be738:`src/guard/__tests__/deadbugz.test.ts`).

The mechanism is precise, and it is not a regex gap. H4's `list_changed` re-validation
arm exists so a legitimate upstream upgrade is not treated as a same-session rug-pull; it
correctly bypasses the F3 same-session guard here too. But this is the server's
first-ever session with mcpm, so there is no on-disk pin to fall back on either — nothing
replaces the missing baseline (getmcpm/cli `CHANGELOG.md`, `[0.33.0] - 2026-08-31`). The
pattern engine finds nothing on its own either: the poisoned wording *adds* a hidden
collection step to an otherwise ordinary tool description, which reads nothing like a
system-prompt-override attempt and matches none of the four
`owasp-mcp-1-tool-description-injection` regex shapes (same CHANGELOG entry). This is
trust-on-first-use, not detection quality: the benign first list *had* been captured into
the session cache, but the armed path did not consult it, and behind it there was no disk
pin at all — `baselineForDrift` is frozen at session start, so `pinned` is `undefined` and
`inspectToolDrift` returns `null` before it ever tiers the change (same test file, the
first test's inline comments).

## The fix, and why the class took three releases

**`[0.33.0]` (2026-08-31, TODOS #58).** When the `list_changed` arm is triggered, an
existing tool's change is now tiered against the *session's own first-seen field
hashes* — the same cosmetic/security H4 doctrine the durable disk-pin path already used,
now applied even with no disk pin at all (getmcpm/cli `CHANGELOG.md`, `[0.33.0]`). The
same commit documents its own residual: "the `prompts/get` channel has no drift/pin
mechanism at all — it is a structural no-op for this check" (same entry).

**`[0.34.1]` (2026-09-01, TODOS #27).** The 0.33.0 fix compares against a baseline held
in memory for the session. Before this release, a never-pinned server's first `tools/list`
was forwarded to the client as soon as the synchronous check passed, while the disk pin
write happened off-thread; a crash or kill in that gap left nothing durable, so the next
launch "looked like *another* first session, with no baseline left to catch a swapped
tool definition against" (getmcpm/cli `CHANGELOG.md`, `[0.34.1]`; CLAUDE.md Decisions Log,
2026-09-01 row). The fix holds that one frame until the pin write has been
attempted and either confirmed or loudly warned about (`PIN-COMMIT-UNCONFIRMED`) — so a
server cannot keep itself permanently unpinned, which would leave every later session with
no durable baseline and only its own first-seen frame, poisoned or not, to compare
against.

**`[0.35.0]` (2026-09-02, TODOS #58's last piece).** Both the session cache and the
disk-pin lookup keyed a tool by its raw `name` string, so a server could re-deliver the
poisoned definition under a look-alike of the trusted name — `Format_Code`, Cyrillic
`fоrmat_code` (U+043E), or a zero-width variant — and the "new name = legitimate
addition" carve-out waved it through with zero findings (getmcpm/cli `CHANGELOG.md`,
`[0.35.0]`; CLAUDE.md Decisions Log, 2026-09-02 row). Both keyings now use a canonical
form. Pre-release review then found a regression in that very fix: an earlier design
*excluded* a same-frame name-collision group from inspection, but the group always
contains the incumbent tool, so "appending one throwaway ASCII case-variant beside a real
tool removed **that tool** from drift inspection — measured, five critical blocks became
zero and the exact Deadbugz sequence returned to `pass`" (same CHANGELOG entry).

## What is still open

Stated as plainly as what closed. **`prompts/get` still has no drift or pin mechanism.**
The test file at `v0.39.1` keeps a test named `GAP: mcpm has no drift/pin protection for
prompts/get at all`, and it asserts a literal no-op — `{ action: "pass", findings: [] }`.
Between `[0.35.0]` and `v0.39.1` only two changes touch `drift.ts` or `run-inner.ts` at
all: an unrelated NFC-hashing fix (`cc2bf0f`, shipped in `[0.36.0]`) and a one-line type
narrowing that came with the OWASP-pin release (`[0.39.0]`, `event: string` →
`event: ConfineEventName`). Neither adds a mechanism on this channel
(`git log e583c61..v0.38.0 -- src/guard/drift.ts src/guard/run-inner.ts`, then a diff of
those two files between `v0.38.0` and `v0.39.1`; `src/guard/__tests__/deadbugz.test.ts`
at `v0.39.1`).

**And the two single-frame corpus cases below still score a miss** at `@getmcpm/cli@0.38.0`
and `0.39.1` — not because the pin/drift fix regressed, but because a lone post-flip frame
with no prior session has nothing for a pin to compare against, so it falls back to the
same stateless pattern engine that missed on 2026-08-31 and still does (measured below;
`cases/attacks/deadbugz-post-flip-tool-description-poisoning.json` and
`cases/warn/deadbugz-post-flip-prompt-exfil-instructions.json`, `source` fields).

So: what is closed is the multi-frame `tools/list` flip, on the live relay, in a session
the relay was watching. What is not closed is the `prompts/get` half of the same campaign,
and any single frame the relay has no prior state for.

## The same frames through two guards

Both corpus cases are single, standalone post-flip frames — no prior session, the shape
a corpus scorer can express (this repo's `README.md`, "Corpus v5" section).
`@getmcpm/cli` reads each frame and matches nothing: both score `pass` with zero findings,
measured 2026-09-08 against `0.38.0` (`README.md`, "Corpus v5" section) and reproduced
below against `0.39.1`.

`mcp-vanguard@2.2.1` (`--profile strict`) splits the two cases across its own coverage
boundary, measured 2026-08-30. It *scores and misses*
`deadbugz-post-flip-tool-description-poisoning`: its `metadata_tool_list` harness reads
`result.tools` but does not flag the added exfil sentence — a real detection miss, not an
abstention. It *abstains* on `deadbugz-post-flip-prompt-exfil-instructions`: no harness in
`benchmark-run` reads `result.messages`, so the `prompts/get` channel is outside its
scored surface entirely (`adapters/mcp-vanguard/README.md`, "Result, 2026-08-30 ...
corpus v5"). This repo's own README states the vanguard row is "not comparable to the
mcpm rows either" and that it is scored through one offline harness rather than vanguard's
live composed proxy (`README.md`, the McpVanguard caveat block — whose own counts are the
older v4 ones). On corpus v5 it scores 29 of 56 and abstains on the other 27
(`README.md`, the baseline table's v5 row; `adapters/mcp-vanguard/README.md`, "Result,
2026-08-30 ... corpus v5").

One sentence each: mcpm misses both cases by reading them and matching nothing; vanguard
misses one the same way and never looks at the other at all.

## Reproduce it in five minutes

**(a) The single-frame misses, through the published CLI.**

```
$ MCPM_CMD="npx --yes @getmcpm/cli@0.39.1 guard inspect --json" \
    node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.39.1

─── mcpm@0.39.1 ───
recall 88.9%  fp-rate 0.0%  precision 100.0%  exact 89.3%
confusion: TP 32 FN 4 FP 0 TN 20  (scored 56/56)
misses: 4
```

The run writes a scoreboard beside those figures
(`out/scoreboard-mcpm@0.39.1-<utc-date>.md`; `out/scoreboard-*` is gitignored, so it is a
local artefact of your own run, not a file in this repo). Its miss list names both Deadbugz
cases among the four:

```
- cve-2026-25650-mcp-salesforce-token-disclosure — missed attack (expected warn, got pass)
- cve-2026-39884-mcp-server-kubernetes-argument-injection — missed attack (expected block, got pass)
- deadbugz-post-flip-tool-description-poisoning — missed attack (expected block, got pass)
- deadbugz-post-flip-prompt-exfil-instructions — missed attack (expected warn, got pass)
```

**(b) The stateful sequence, blocked in a real session.**

```
$ git clone --branch v0.39.1 https://github.com/getmcpm/cli.git && cd cli
$ pnpm install --frozen-lockfile && pnpm vitest run src/guard/__tests__/deadbugz.test.ts --reporter=verbose

 ✓ Deadbugz — first-ever session (no pre-existing pin) > #58 FIXED: benign list -> 3 calls -> list_changed -> poisoned list is now BLOCKED
 ✓ Deadbugz — first-ever session (no pre-existing pin) > control: the SAME flip WITHOUT list_changed cover is caught by F3 (schema-drift-in-session, BLOCK)
 ✓ #58 fix — FP safety: a real list_changed upgrade is never penalized > armed list_changed that ADDS a new tool name produces no finding (legitimate expansion)
 ✓ #58 fix — FP safety: a real list_changed upgrade is never penalized > armed list_changed whose existing tool is UNCHANGED produces no finding
 ✓ Deadbugz — later session, a durable pin already exists from a prior benign session > description-ONLY poisoning against a pinned baseline degrades to WARN, not BLOCK
 ✓ Deadbugz — later session, a durable pin already exists from a prior benign session > schema-touching poisoning against a pinned baseline IS BLOCKED
 ✓ Deadbugz — the prompts/get channel the disclosure also names > GAP: mcpm has no drift/pin protection for prompts/get at all
 ✓ Deadbugz — the prompts/get channel the disclosure also names > realistic exfil-instruction wording scores ZERO pattern findings (prompt_content catalog floor)

 Test Files  1 passed (1)
      Tests  8 passed (8)
```

(File paths and per-test timings are trimmed from the `--reporter=verbose` lines above;
the names and their order are verbatim.)

(The cli's `package.json` `engines` field requires Node `^22.22.2 || ^24.15.0 || >=26.0.0`;
`pnpm install` does not enforce it unless `engine-strict=true` is set, so check `node --version`
first rather than trusting a silent install.)

The first test's name is not a typo: `#58 FIXED` asserts `"block"`, the closed half of
this story. The seventh test, `GAP: mcpm has no drift/pin protection for prompts/get at
all`, asserts a no-op — the open half, in the same file, still passing today.

**(c) The interactive path — [guard-playground](https://getmcpm.github.io/guard-playground/).**
The engine there is the same stateless `inspectFrame` composition scored above, bundled
from `getmcpm/cli` tag `v0.39.1` (`engine.lock.json`) out of exactly three entry modules —
`inspect-frame.ts`, `owasp.ts`, `signatures.ts` — and 10 more files they pull in
(`guard-playground/README.md`, "How the engine gets here"; `grep -c '^// src/'
site/engine.mjs` = 13). Both Deadbugz cases are preloaded in its case list, so one click
reproduces the same `pass` as (a) — no install, and a pasted frame of your own takes the
same path. It cannot show the block in (b): `pins.ts`, `drift.ts`, and `run-inner.ts` are
not part of the bundle, and the project's own plan says so directly —
"the same-session pin/drift defense — the part that catches a Deadbugz-style flip — needs
the relay" (`guard-playground/docs/PLAN.md`, line 49-50). The playground is a demo of the
stateless floor, not the stateful defense that actually closed this.

## What a reader can do with this

Write a case the reference guard misses and it will not fail CI for missing it: the runner
"exits non-zero only on an unhealthy run ... never on a low score" (`README.md`). Or write
an adapter for your own guard and score it through its published CLI or library API, never
a vendored copy of its internals. See `cases/` for the case format and
`adapters/README.md` for both contracts.
