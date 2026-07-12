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

let total = 0;
const index = [];
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
    index.push({ id, bucket, category: kase.category, expected: kase.expected.action });
    total++;
  }
}

writeFileSync(
  path.join(OUT, "index.json"),
  JSON.stringify({ generatedFrom: "@getmcpm/cli guard fixture corpus", count: total, cases: index }, null, 2) + "\n"
);
console.log(`Extracted ${total} cases into ${path.relative(BENCH, OUT)}/ (${BUCKETS.join(", ")}).`);
for (const b of BUCKETS) console.log(`  ${b}: ${index.filter((c) => c.bucket === b).length}`);
