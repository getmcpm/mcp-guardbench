# Published mcpm 0.54.2 benchmark

Measured on 2026-11-20 (Hong Kong) through the public `mcpm guard inspect --json` command.
The existing adapter and runner scored all 57 cases with Node 26.11.1.
Corpus base: `3c9e0bcbcaebdfe9fdf4c9c161716c2bb9e23636`. All 14 adapter tests passed.
Recall was 86.49%, with zero false positives and 50 of 57 exact actions.

The scripts-disabled installation matched the exact npm archive.
`published-proof.json` records its digest, verified provenance and signed SBOM.

To reproduce, install the exact release archive after checking that digest, then run:

```sh
MCPM_CMD="/path/to/installed/mcpm guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.54.2
```
