# Published mcpm 0.54.3 benchmark

Measured on 2026-11-20 (Hong Kong) through the public `mcpm guard inspect --json` command.
The existing adapter and runner scored all 57 cases with Node 26.11.1.
Corpus base: `c824affc5cf6eacbed95d254d2a2291e7c2e3e67`. All 14 adapter tests passed.
Recall was 86.49%, with zero false positives and 50 of 57 exact actions.

The scripts-disabled installation matched the exact npm archive.
`published-proof.json` records its digest, verified provenance and signed SBOM.

To reproduce, install the exact release archive after checking that digest, then run:

```sh
MCPM_CMD="/path/to/installed/mcpm guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.54.3
```
