# Published mcpm 0.52.0 — unchanged 57-case corpus

Measured on 2026-11-08 (Hong Kong) through the unchanged public adapter and
runner. All 57 cases scored: TP 32, FN 5, FP 0, TN 20; recall 86.5%, precision
100.0%, exact actions 50/57 (87.7%). No unsupported cases, adapter errors,
anomalies or over-blocked warn cases. The same five detection misses remain.

The official runner produced `scoreboard.json` and `scoreboard.md`. A separate
adapter replay produced `verdicts-0.52.0.ndjson`; all 57 rows are byte-identical
to the retained published 0.51.0 result. Recalculating confusion and exact actions
from that replay agrees with the official runner. This is a fresh measurement,
not a copied score. Historical results remain unchanged.

`receipt.json` binds the exact command, Node binary, corpus, adapter, runner,
input and output hashes. `install-lock.json` pins an exact registry installation
of `@getmcpm/cli@0.52.0`, with lifecycle scripts disabled and disposable npm/client
state. `installed-archive-manifest.json` records all 136 installed package files
matching the authenticated npm tarball byte-for-byte (not only compiled code).

`published-proof.json` preserves release-manager and Astra verification outcomes
for npm SRI/SHA256, signed SLSA subject/source/tag/issuer and signed SBOM including
tamper rejection. It is a snapshot of those checks, not a standalone signed
attestation. This benchmark independently rechecked archive SHA256/SRI and every
installed package file. The release source is
`c14263670da862bee04a83d571df23731bce6f8e`, tag `v0.52.0`.

The corpus remains v5 at `ba18d3deb4e4836920735a6fd97ca96ad836679e`
(57 scored cases: 33 attack, 20 benign, 4 warn). Cases, expected actions, adapter
and runner were not changed. The adapter's 14 contract tests passed. Astra independently
reviewed the final source/results and reproduced all 57 verdicts through a fresh
offline locked installation with scripts disabled: all 136 installed package
files matched the archive, replay bytes matched, and independently recalculated
confusion and exact actions agreed. See `receipt.json` for the proof digest.

## Reproduce

Use Node 26.11.1 (the measured runtime), a disposable HOME and explicit empty
npm user/global configuration. In a fresh runtime directory create this manifest
and copy `install-lock.json` to `package-lock.json`:

```json
{
  "name": "mcpm-guardbench-release-runtime",
  "private": true,
  "version": "0.0.0",
  "dependencies": { "@getmcpm/cli": "0.52.0" }
}
```

Run `npm ci --ignore-scripts --no-audit --no-fund`, then compare installed files
with the exact-version npm archive and its registry integrity. From the benchmark
repository, with a minimal environment and that disposable HOME:

```sh
MCPM_CMD='node /absolute/runtime/node_modules/@getmcpm/cli/dist/index.js guard inspect --json' \
  node runner/run.mjs --adapter 'node adapters/mcpm/adapter.mjs' --name mcpm@0.52.0
npm test
```

The raw replay uses the same runner bucket/file order (`attacks`, `benign`,
`warn`) and `{id,message}` NDJSON through `adapters/mcpm/adapter.mjs`. Its input
SHA256 is recorded in the receipt. Keep payloads out of model prompts.

This is stateless single-frame `guard inspect` evidence. It does not exercise
VS Code scope inventory, host loading, stateful relay, managed-policy enforcement
or OS confinement. Scoring used a minimal environment, not an OS network sandbox.
No other guard was remeasured.
