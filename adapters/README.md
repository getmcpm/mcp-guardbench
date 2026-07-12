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

`adapters/mcpm/adapter.mjs` imports mcpm's inspection engine from a bundled
`engine.mjs` (a build of `@getmcpm/cli`'s `src/guard/{patterns,signatures}`).
It scores 100% on this corpus **by construction** — the corpus was extracted
from mcpm's own CI fixtures, so a perfect reference score is expected and is not
itself a claim of superiority. The benchmark earns its keep when (a) other
guards are scored on the same cases and (b) the corpus grows with cases mcpm
does **not** catch.

## Publishing an adapter

For a published adapter, prefer depending on the guard's real distributed
artifact over vendoring internals:

- **mcpm**: replace `engine.mjs` with a call to a public one-frame inspect API
  on the installed `@getmcpm/cli` (a `mcpm guard inspect` subcommand is the
  clean seam; it does not exist yet — tracked as benchmark-publication work).
- **other guards**: shell out to the guard's own CLI/library. Keep the adapter
  thin — its only job is the NDJSON translation.
