# Writing an adapter

An adapter lets mcp-guardbench score **any** MCP guard, relay, or client-side
inspector — not just mcpm. The contract is a language-agnostic subprocess pipe.

## Contract

The runner spawns your adapter once and speaks NDJSON over stdio:

- **stdin** — one case per line: `{"id": "<case-id>", "message": <json-rpc frame>}`
- **stdout** — one verdict per line: `{"id": "<case-id>", "action": "<pass|warn|block>", "signature_id"?: "<string>"}`
  - `signature_id` is optional. A guard that flags the right frame with a
    differently-named rule is still scored correct on action; the signature is
    only used for informational per-rule reporting.
  - Emit `{"id": "...", "action": "error", "error": "..."}` if your guard
    throws on a frame — the runner counts it as unscored, not as a pass.
- Order-independent: the runner matches verdicts to cases by `id`, so you may
  buffer, reorder, or stream.
- Write anything else (logs) to **stderr**; the runner ignores non-JSON stdout lines.

## Scoring

- `attacks` and `warn` cases are **detections** — your guard should return a
  non-`pass` action. Missing one is a false negative (hurts recall).
- `benign` cases must return `pass`. Flagging one is a false positive (hurts
  fp-rate and precision).
- `exact-action accuracy` additionally rewards matching `block` vs `warn`
  exactly, but the headline recall/precision only care about pass-vs-not.

## Run

```
node runner/run.mjs --adapter "<your command>" --name <label>
# → out/scoreboard-<label>-<date>.{json,md}
```

## Reference adapter (mcpm)

`adapters/mcpm/adapter.mjs` shells out to `mcpm guard inspect --json` — mcpm's
own **published CLI**, the same binary its users run. It does not import mcpm's
engine. That rule is what makes the scoreboard comparable: no guard, including
the one that authored this corpus, gets a privileged in-process path.

```bash
# whatever `mcpm` is on PATH
npm run bench:mcpm

# a pinned published version (recommended for a citable run)
MCPM_CMD="npx --yes @getmcpm/cli@0.25.0 guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.25.0
```

mcpm scores 100% on this corpus **by construction** — the corpus was extracted
from mcpm's own CI fixtures, so a perfect reference score is expected and is
*not* a claim of superiority. The benchmark earns its keep when (a) other guards
are scored on the same cases and (b) the corpus grows with cases mcpm does
**not** catch. Treat 100% as the sanity check that the adapter is wired up, not
as a result.

## Publishing an adapter

Depend on the guard's real distributed artifact — never vendor its internals. A
bundled copy of a guard's engine drifts silently from what ships, and an
in-process import gives that guard a path no competitor can have; both quietly
invalidate the comparison. Shell out to the guard's own CLI (or its public
library API) and keep the adapter thin — its only job is NDJSON translation.

Pin the version you scored and put it in `--name`, so a scoreboard stays
reproducible after the guard moves on.
