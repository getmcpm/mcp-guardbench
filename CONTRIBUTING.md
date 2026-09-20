# Contributing a case

The corpus lives in `cases/{attacks,benign,warn}/`, one JSON file per case, plus a
manifest at `cases/index.json`. A case is a single MCP JSON-RPC frame and the verdict
a guard should produce for it.

## Case file shape

Copy the field list from an existing case (e.g. `cases/attacks/deadbugz-supply-chain-mongodb-tool-poisoning.json`,
added in [PR #3](https://github.com/getmcpm/mcp-guardbench/pull/3), is a good worked
example):

```json
{
  "id": "short-kebab-case-id",
  "bucket": "attacks",
  "name": "One-line human-readable description",
  "category": "OWASP-MCP-1",
  "expected": { "action": "block", "signature_id": "..." },
  "source": "Where this comes from and why the expected verdict is correct.",
  "provenance": "native",
  "message": { "jsonrpc": "2.0", "id": 1, "result": { "...": "..." } }
}
```

- `bucket` matches the directory it lives in (`attacks`, `benign`, or `warn`).
- `source` must state where the case comes from **and its licence**: a real,
  publicly disclosed incident/CVE (cite it), a hand-authored reconstruction of a
  disclosed mechanism (say so explicitly — no copied payload text), or a benign
  fixture you wrote. Do not copy case text from a corpus that isn't under a
  permissive licence.
- `provenance` is `"native"` (hand-authored here), `"extracted"` (pulled from
  `@getmcpm/cli`'s own fixtures), or `"external"` (from a disclosed real-world
  incident).

## Updating the manifest

Bump `cases/index.json`: increment the top-level `count`, increment the matching
`sources.<provenance>.count`, and append an entry with `id`, `bucket`, `category`,
`expected` (just the action string here), and `provenance`. See PR #3 for the exact
diff shape.

## Running the benchmark

```
npm run bench:mcpm
```

This scores `@getmcpm/cli` (per the adapter contract in `adapters/README.md`) against
every case and writes a scoreboard to `out/`.

## What counts as a good contribution

A case the guard under test **misses** is a welcome contribution — it's the corpus
growing, not a failure. CI (`bench.yml`) fails only on incomplete coverage (a case
with no verdict, or an adapter error), never on a low score, so you don't need the
guard to pass your case for the PR to be mergeable.

Scoreboard rows in `README.md` are re-measured by maintainers after any corpus
change; contributors don't need to update them.

## CI on your PR

First-time contributors' CI runs only after a maintainer approves it — this is
normal, not a rejection.
