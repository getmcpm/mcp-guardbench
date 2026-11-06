# Published mcpm 0.50.1 measurement

The official runner scored the published `@getmcpm/cli@0.50.1` public CLI through
the unchanged reference adapter: 57/57 cases, 32 true positives, five false
negatives, zero false positives and 20 true negatives. Recall is 86.5%,
precision 100.0%, false-positive rate 0.0%, exact-action accuracy 87.7%.
There are no adapter errors, missing verdicts, unsupported cases or anomalies.
All earlier measurements and the corpus remain unchanged.

`scoreboard.{json,md}` are the official runner's output. The saved per-case
`verdicts-0.50.1.ndjson` comes from a separate replay through the same adapter
and exact installed CLI. Its confusion counts and rates were independently
reconciled with the scoreboard; all 57 lines are byte-identical to the retained
0.50.0 verdicts. The same five detection misses remain.

`receipt.json` records the actual command and the package/archive, release
source, Node binary, adapter, runner, input and output identities. The clean
installation used a disposable HOME/cache and disabled install scripts.
`install-lock.json` retains its exact npm dependency resolution;
`installed-archive-manifest.json` binds every installed CLI dist file and
package.json to byte-identical content from the verified npm archive (134 files).
`published-proof.json` is a snapshot of the release manager's cryptographic
verification outcomes, not a standalone signed attestation. The benchmark
independently rechecked the npm archive's SRI/SHA256 and installed file bytes;
the public npm attestation endpoint is recorded for independent provenance checks.

This measures stateless, single-frame `guard inspect` only. It does not exercise
managed-policy setup, native clients, stateful relay or OS confinement, and it
does not remeasure another guard.

## Reproduce

Use Node 24.20.0 and the unchanged repository base
`5b61b0e9d15da62034cd5531b1e3b6da92484e7f` with this result directory available.
The receipt names the measured macOS arm64 runtime; another platform/runtime is
a fresh measurement. Run from the repository root:

```sh
work=$(mktemp -d)
mkdir -p "$work/home" "$work/runtime" "$work/mcpm-release-0501-20261106"
curl -fL https://registry.npmjs.org/@getmcpm/cli/-/cli-0.50.1.tgz \
  -o "$work/mcpm-release-0501-20261106/actual.tgz"
node --input-type=module - "$work/mcpm-release-0501-20261106/actual.tgz" <<'JS'
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const bytes = readFileSync(process.argv[2]);
assert.equal(createHash('sha256').update(bytes).digest('hex'), '423866f3c8ce91e494ea66744f86053f868f59b9e2abaae96acc3d4d093e0e63');
assert.equal('sha512-' + createHash('sha512').update(bytes).digest('base64'), 'sha512-2ddRvViZNcJakVzcXNXMn/8qKXAGaN/ZBHedS3xYcNZi1JJCOb3WfUx++gBCpCfLlEV6O3DMs9KG+tkmXpOHfg==');
JS
cp results/mcpm-0.50.1-2026-11-06/install-lock.json "$work/runtime/package-lock.json"
cat > "$work/runtime/package.json" <<'JSON'
{"private":true,"dependencies":{"@getmcpm/cli":"file:../mcpm-release-0501-20261106/actual.tgz"}}
JSON
HOME="$work/home" npm ci --prefix "$work/runtime" --ignore-scripts --no-audit --no-fund
HOME="$work/home" MCPM_CMD="node $work/runtime/node_modules/@getmcpm/cli/dist/index.js guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.50.1
```

The official runner returns zero for a healthy measurement, including this one;
low recall does not fail the runner. Inspect the saved misses instead of treating
that exit status as evidence that every attack was detected. To reproduce the
separate verdict replay, generate the same input in runner bucket/file order:

```sh
node --input-type=module - <<'JS' > "$work/input.ndjson"
import { readdirSync, readFileSync } from 'node:fs';
for (const bucket of ['attacks', 'benign', 'warn']) {
  for (const name of readdirSync(`cases/${bucket}`).filter(name => name.endsWith('.json'))) {
    const { id, message } = JSON.parse(readFileSync(`cases/${bucket}/${name}`, 'utf8'));
    console.log(JSON.stringify({ id, message }));
  }
}
JS
HOME="$work/home" MCPM_CMD="node $work/runtime/node_modules/@getmcpm/cli/dist/index.js guard inspect --json" \
  node adapters/mcpm/adapter.mjs < "$work/input.ndjson" > "$work/verdicts.ndjson"
cmp "$work/verdicts.ndjson" results/mcpm-0.50.1-2026-11-06/verdicts-0.50.1.ndjson
```
