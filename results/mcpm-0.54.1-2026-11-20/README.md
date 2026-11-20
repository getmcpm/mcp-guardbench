# Published mcpm 0.54.1 benchmark

Measured on 2026-11-20 (Hong Kong) with Node 26.11.1. All 57 cases scored
on the unchanged v5 corpus at guardbench commit `13445a84989a1fee1038e82e04e911117a1bc08e`.
The runner measured TP 32, FN 5, FP 0 and TN 20. Recall was 86.49%,
with 50 of 57 exact actions and no false positives. The 14 adapter tests passed.

The adapter invoked the `mcpm guard inspect --json` command from a clean,
scripts-disabled install of the exact npm archive. All installed CLI package
files matched the archive. The release evidence in `published-proof.json`
records the verified npm integrity, signed provenance and signed SBOM.

To reproduce, install the archive named in the release evidence by matching
its SHA-256 digest, then run:

```sh
MCPM_CMD="/path/to/installed/mcpm guard inspect --json" \
  node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.54.1
```
