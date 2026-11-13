# Published mcpm 0.54.0 — unchanged 57-case corpus

Measured on 2026-11-14 (Hong Kong; 2026-11-13 UTC) through the unchanged public adapter and
runner. All 57 cases scored: TP 32, FN 5, FP 0, TN 20; recall 86.5%, precision
100.0%, exact actions 50/57 (87.7%). No unsupported cases, adapter errors,
anomalies or over-blocked warn cases. The same five detection misses remain.

The official runner produced `scoreboard.json` and `scoreboard.md`. A separate
adapter replay produced `verdicts-0.54.0.ndjson`; all 57 rows are byte-identical
to the retained published 0.53.0 result. Recalculating confusion and exact actions
from that replay agrees with the official runner. This is a fresh measurement,
not a copied score. Historical results remain unchanged.

`receipt.json` binds the exact command, CLI version, Node binary, corpus,
adapter, runner, input and output hashes. `install-lock.json` pins the dedicated
clean installation from the authenticated npm archive, with lifecycle scripts
disabled and disposable npm/client state. `installed-archive-manifest.json`
records all 136 installed package files matching the archive byte-for-byte.
`runtime-tree.json` additionally binds all installed dependency files and symlink
targets with a deterministic digest; it describes this installation, including
npm's hidden lock, rather than claiming identical npm layouts across platforms.

`published-proof.json` preserves release-manager and Astra verification outcomes
for npm SRI/SHA256, signed SLSA subject/source/tag/issuer and signed SBOM including
tamper rejection. It is a snapshot of those checks, not a standalone signed
attestation. This benchmark independently rechecked archive SHA256/SRI and every
installed package file. The release source is
`88bfb58013e639acfbf73081913b2c70ca8c9c56`, tag `v0.54.0`.

The corpus remains v5 at `ba18d3deb4e4836920735a6fd97ca96ad836679e`
(57 scored cases: 33 attack, 20 benign, 4 warn). Cases, expected actions, adapter
and runner were not changed. The adapter's 14 contract tests passed.

## Reproduce

Use Node 26.11.1 and npm 11.20.0 (the measured runtime), a disposable HOME/cache
and explicit empty npm user/global configuration. Download the exact archive
into a fresh runtime directory as `cli-0.54.0.tgz`:

```sh
curl -fL https://registry.npmjs.org/@getmcpm/cli/-/cli-0.54.0.tgz -o cli-0.54.0.tgz
node --input-type=module - <<'JS'
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const bytes = readFileSync('cli-0.54.0.tgz');
assert.equal(createHash('sha256').update(bytes).digest('hex'), '3e85d1df5c478a196161f3a0a1a4827e9fa999aecf62adece9c5ac03e4ca20dd');
assert.equal('sha512-' + createHash('sha512').update(bytes).digest('base64'), 'sha512-QUfRWp73iiNXYSzX5i/QFS/DVVqO7U3fqYlXVl5c3S2NWma72YwOhZZ+Cz0BC9DBMmhUbY2a2MfM9T6DtF569w==');
JS
```

Create this manifest and copy `install-lock.json` to `package-lock.json`:

```json
{
  "name": "mcpm-guardbench-release-runtime",
  "private": true,
  "version": "0.0.0",
  "dependencies": { "@getmcpm/cli": "file:cli-0.54.0.tgz" }
}
```

Run `npm ci --ignore-scripts --no-audit --no-fund`, then compare every installed
CLI package file against the verified archive. From the benchmark repository,
with a minimal environment and that disposable HOME:

```sh
MCPM_CMD='node /absolute/runtime/node_modules/@getmcpm/cli/dist/index.js guard inspect --json' \
  node runner/run.mjs --adapter 'node adapters/mcpm/adapter.mjs' --name mcpm@0.54.0
npm test
```

The raw replay uses the same runner bucket/file order (`attacks`, `benign`,
`warn`) and `{id,message}` NDJSON through `adapters/mcpm/adapter.mjs`. Its input
SHA256 is recorded in the receipt. Keep payloads out of model prompts.

0.54.0 adds `mcpm mcp audit report`; it does not change the guard detector.

This is stateless single-frame `guard inspect` evidence. It does not exercise
0.54.0's MCP audit report, native loading, stateful relay, managed-policy
enforcement or OS confinement. Scoring used a minimal environment, not an OS
network sandbox. No other guard was remeasured.
