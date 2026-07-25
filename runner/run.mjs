#!/usr/bin/env node
/**
 * mcp-guardbench runner — score ANY MCP guard against the case corpus.
 *
 * Spawns an adapter subprocess (any language), streams NDJSON cases to its
 * stdin, reads NDJSON verdicts from its stdout, and scores them against each
 * case's expected action. Emits a scoreboard (JSON + markdown).
 *
 * Usage:
 *   node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" [--name mcpm]
 *
 * Metrics (attack = expected non-pass; benign = expected pass):
 *   recall     = detected attacks / all attacks           (higher better)
 *   fp_rate    = benign flagged / all benign               (lower better)
 *   precision  = detected attacks / all non-pass verdicts  (higher better)
 *   exact_acc  = verdicts whose action == expected action  (block vs warn counts)
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const CASES = path.join(ROOT, "cases");

const argv = process.argv.slice(2);
function arg(flag, dflt) {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}
const adapterCmd = arg("--adapter", null);
const adapterName = arg("--name", "adapter");
if (!adapterCmd) {
  console.error('Usage: node runner/run.mjs --adapter "<command>" [--name <label>]');
  process.exit(2);
}

// ---- load cases -----------------------------------------------------------
function loadCases() {
  const out = [];
  for (const bucket of ["attacks", "benign", "warn"]) {
    const dir = path.join(CASES, bucket);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).filter((f) => f.endsWith(".json"))) {
      out.push(JSON.parse(readFileSync(path.join(dir, f), "utf8")));
    }
  }
  return out;
}
const cases = loadCases();
const byId = new Map(cases.map((c) => [c.id, c]));

// ---- run adapter ----------------------------------------------------------
async function runAdapter(cmd, cases) {
  const [bin, ...args] = cmd.split(" ");
  const child = spawn(bin, args, { cwd: ROOT, stdio: ["pipe", "pipe", "inherit"] });
  const verdicts = new Map();
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const done = new Promise((resolve, reject) => {
    rl.on("line", (line) => {
      const t = line.trim();
      if (!t) return;
      try {
        const v = JSON.parse(t);
        if (v.id) verdicts.set(v.id, v);
      } catch { /* ignore non-JSON adapter chatter */ }
    });
    child.on("error", reject);
    child.on("close", () => resolve());
  });
  for (const c of cases) child.stdin.write(JSON.stringify({ id: c.id, message: c.message }) + "\n");
  child.stdin.end();
  await done;
  return verdicts;
}

const t0 = Date.now();
const verdicts = await runAdapter(adapterCmd, cases);

// ---- score ----------------------------------------------------------------
const isAttack = (c) => c.expected.action !== "pass"; // attacks + warn
let TP = 0, FN = 0, FP = 0, TN = 0, exact = 0, missingVerdict = 0, adapterErrors = 0;
const misses = [];
const catAgg = {}; // category -> {n, detected}

for (const c of cases) {
  const v = verdicts.get(c.id);
  if (!v) { missingVerdict++; misses.push({ id: c.id, reason: "no verdict emitted" }); continue; }
  if (v.action === "error") { adapterErrors++; misses.push({ id: c.id, reason: `adapter error: ${v.error ?? ""}` }); continue; }
  const nonPass = v.action === "warn" || v.action === "block";
  if (v.action === c.expected.action) exact++;

  if (isAttack(c)) {
    const cat = c.category ?? "uncategorized";
    catAgg[cat] ??= { n: 0, detected: 0 };
    catAgg[cat].n++;
    if (nonPass) { TP++; catAgg[cat].detected++; }
    else { FN++; misses.push({ id: c.id, reason: `missed attack (expected ${c.expected.action}, got pass)` }); }
  } else {
    if (nonPass) { FP++; misses.push({ id: c.id, reason: `false positive on benign (got ${v.action})` }); }
    else TN++;
  }
}

const scored = cases.length - missingVerdict - adapterErrors;
const div = (a, b) => (b === 0 ? null : +(a / b).toFixed(4));
const board = {
  adapter: adapterName,
  ranAt: new Date().toISOString(),
  corpus: { total: cases.length, attacks: cases.filter(isAttack).length, benign: cases.filter((c) => !isAttack(c)).length },
  coverage: { scored, missingVerdict, adapterErrors },
  metrics: {
    recall: div(TP, TP + FN),
    fp_rate: div(FP, FP + TN),
    precision: div(TP, TP + FP),
    exact_action_accuracy: div(exact, scored),
  },
  confusion: { TP, FN, FP, TN },
  byCategory: Object.fromEntries(
    Object.entries(catAgg).map(([k, v]) => [k, { detected: v.detected, total: v.n, recall: div(v.detected, v.n) }])
  ),
  misses,
  elapsedMs: Date.now() - t0,
};

const stamp = new Date().toISOString().slice(0, 10);
const jsonPath = path.join(ROOT, "out", `scoreboard-${adapterName}-${stamp}.json`);
writeFileSync(jsonPath, JSON.stringify(board, null, 2) + "\n");

// ---- markdown scoreboard --------------------------------------------------
const m = board.metrics;
const md = [
  `# Scoreboard — ${adapterName}`,
  ``,
  `Corpus: ${board.corpus.total} cases (${board.corpus.attacks} attack, ${board.corpus.benign} benign). Scored ${scored}.`,
  ``,
  `| metric | value |`,
  `|---|---|`,
  `| recall (attack detection) | ${m.recall === null ? "—" : (m.recall * 100).toFixed(1) + "%"} |`,
  `| false-positive rate (benign) | ${m.fp_rate === null ? "—" : (m.fp_rate * 100).toFixed(1) + "%"} |`,
  `| precision | ${m.precision === null ? "—" : (m.precision * 100).toFixed(1) + "%"} |`,
  `| exact-action accuracy | ${m.exact_action_accuracy === null ? "—" : (m.exact_action_accuracy * 100).toFixed(1) + "%"} |`,
  ``,
  `Confusion: TP ${TP} · FN ${FN} · FP ${FP} · TN ${TN}`,
  ``,
  `## By category (attack recall)`,
  ``,
  `| category | detected / total | recall |`,
  `|---|---|---|`,
  ...Object.entries(board.byCategory).map(([k, v]) => `| ${k} | ${v.detected}/${v.total} | ${(v.recall * 100).toFixed(0)}% |`),
  ``,
  ...(misses.length ? [`## Misses (${misses.length})`, ``, ...misses.map((x) => `- \`${x.id}\` — ${x.reason}`)] : [`_No misses._`]),
  ``,
].join("\n");
const mdPath = path.join(ROOT, "out", `scoreboard-${adapterName}-${stamp}.md`);
writeFileSync(mdPath, md);

// ---- console --------------------------------------------------------------
console.log(`\n─── ${adapterName} ───`);
console.log(`recall ${pct(m.recall)}  fp-rate ${pct(m.fp_rate)}  precision ${pct(m.precision)}  exact ${pct(m.exact_action_accuracy)}`);
console.log(`confusion: TP ${TP} FN ${FN} FP ${FP} TN ${TN}  (scored ${scored}/${cases.length})`);
if (misses.length) console.log(`misses: ${misses.length}`);
console.log(`\n${mdPath}`);

// ---- exit status ----------------------------------------------------------
// Non-zero on INCOMPLETE COVERAGE only — a case that got no verdict or an
// adapter error means the harness is broken, and a partial scoreboard read as a
// full one is the failure mode that quietly overstates a guard.
//
// Deliberately NOT gated on the score. A new case that the guard under test
// misses is the benchmark working as intended (that is how the corpus grows);
// failing CI for it would create pressure to only add cases that already pass.
if (missingVerdict > 0 || adapterErrors > 0) {
  console.error(
    `\nincomplete coverage: ${missingVerdict} case(s) with no verdict, ${adapterErrors} adapter error(s) — ` +
      `scoreboard covers ${scored}/${cases.length}`,
  );
  process.exitCode = 1;
}

function pct(x) { return x === null ? "—" : (x * 100).toFixed(1) + "%"; }
