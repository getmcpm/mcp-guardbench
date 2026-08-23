#!/usr/bin/env node
/**
 * One-time (dev) extraction: transform the hand-authored mcpm-guard fixture
 * corpus into mcp-guardbench's public case schema. The RESULTING cases are
 * committed, so the benchmark is self-contained — this script only re-runs when
 * the upstream corpus grows.
 *
 * Provenance: the fixtures are derived from public attack methodology (Invariant
 * Labs 2025, MCPoison CVE-2025-54136, Equixly/Pillar audits) — license-clean,
 * no MCPTox artifacts copied. See the source repo's fixtures/mcptox/README.md.
 *
 * v1 scope: single-frame cases (attacks / benign / warn). Stateful schema-drift
 * scenarios (two frames + a pin) are deferred to a v2 case type.
 *
 * Usage: node scripts/extract-from-mcpm.mjs [path-to-mcpm-cli-repo]
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BENCH = path.join(HERE, "..");
const cliRepo = process.argv[2] ?? path.join(BENCH, "..", "cli");
const SRC = path.join(cliRepo, "src/guard/__tests__/fixtures/mcptox");
const OUT = path.join(BENCH, "cases");

const BUCKETS = ["attacks", "benign", "warn"]; // single-frame; drift deferred

let extractedCount = 0;
for (const bucket of BUCKETS) {
  const dir = path.join(SRC, bucket);
  const outDir = path.join(OUT, bucket);
  mkdirSync(outDir, { recursive: true });
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
    const fx = JSON.parse(readFileSync(path.join(dir, f), "utf8"));
    const id = f.replace(/\.json$/, "");
    const kase = {
      id,
      bucket,
      name: fx.name,
      category: fx.category ?? null,
      expected: {
        action: fx.expected_action, // "block" | "warn" | "pass"
        ...(fx.expected_signature_id ? { signature_id: fx.expected_signature_id } : {}),
      },
      source: fx.notes ?? null,
      message: fx.message,
    };
    writeFileSync(path.join(outDir, `${id}.json`), JSON.stringify(kase, null, 2) + "\n");
    extractedCount++;
  }
}

// The index is rebuilt by SCANNING the case directories, not by accumulating
// what this script just wrote. Cases hand-authored in this repo would otherwise
// disappear from the manifest on every re-extraction — and those are exactly the
// cases the corpus most needs, since a corpus extracted from one guard's fixtures
// cannot grow in a direction that guard cannot see. A case with no `provenance`
// field predates this distinction and came from the extraction.
const index = [];
for (const bucket of BUCKETS) {
  const outDir = path.join(OUT, bucket);
  for (const f of readdirSync(outDir).filter((f) => f.endsWith(".json"))) {
    const k = JSON.parse(readFileSync(path.join(outDir, f), "utf8"));
    index.push({
      id: k.id,
      bucket,
      category: k.category ?? null,
      expected: k.expected.action,
      provenance: k.provenance ?? "extracted",
    });
  }
}
// Counted per actual provenance value, not derived as "everything else" from a
// single native count — that shape silently mislabelled every future
// provenance value (e.g. 'external') as 'extracted' the moment one was added.
const nativeCount = index.filter((c) => c.provenance === "native").length;
const externalCount = index.filter((c) => c.provenance === "external").length;
const extractedCount2 = index.length - nativeCount - externalCount;

writeFileSync(
  path.join(OUT, "index.json"),
  JSON.stringify(
    {
      sources: {
        extracted: { from: "@getmcpm/cli guard fixture corpus", count: extractedCount2 },
        native: { from: "hand-authored in mcp-guardbench", count: nativeCount },
        external: { from: "real, publicly disclosed CVEs (see each case's `source` field)", count: externalCount },
      },
      count: index.length,
      cases: index,
    },
    null,
    2
  ) + "\n"
);
console.log(`Extracted ${extractedCount}; indexed ${index.length} (${nativeCount} native) in ${path.relative(BENCH, OUT)}/.`);
for (const b of BUCKETS) console.log(`  ${b}: ${index.filter((c) => c.bucket === b).length}`);
