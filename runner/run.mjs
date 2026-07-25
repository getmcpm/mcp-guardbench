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
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
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

const VALID_ACTIONS = new Set(["pass", "warn", "block", "error"]);
const truncate = (s) => (s.length > 120 ? `${s.slice(0, 120)}...` : s);

// ---- run adapter ----------------------------------------------------------
async function runAdapter(cmd, cases) {
  const [bin, ...args] = cmd.split(" ");
  const child = spawn(bin, args, { cwd: ROOT, stdio: ["pipe", "pipe", "inherit"] });
  const verdicts = new Map();
  // Anomalies are reported, never swallowed. A scoreboard that silently drops
  // what it did not understand is exactly the confidently-wrong artifact this
  // benchmark exists to replace.
  const anomalies = [];
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const done = new Promise((resolve, reject) => {
    rl.on("line", (line) => {
      const t = line.trim();
      if (!t) return;
      let v;
      try {
        v = JSON.parse(t);
      } catch {
        anomalies.push(`non-JSON line on adapter stdout: ${truncate(t)}`);
        return;
      }
      if (v === null || typeof v !== "object" || Array.isArray(v)) {
        anomalies.push(`verdict is not an object: ${truncate(t)}`);
        return;
      }
      if (typeof v.id !== "string" || v.id === "") {
        anomalies.push(`verdict has no id: ${truncate(t)}`);
        return;
      }
      // An action outside the enum must NOT be scored. Treating an unknown or
      // missing action as falsy (and therefore "pass") let a structurally empty
      // verdict -- or a third-party adapter emitting "deny"/"BLOCK" -- report a
      // flawless 0% false-positive rate with full coverage.
      if (!VALID_ACTIONS.has(v.action)) {
        anomalies.push(`case ${v.id}: invalid action ${JSON.stringify(v.action)}`);
        verdicts.set(v.id, { id: v.id, action: "error", error: `invalid action ${JSON.stringify(v.action)}` });
        return;
      }
      if (verdicts.has(v.id)) anomalies.push(`duplicate verdict for case ${v.id} (last one wins)`);
      verdicts.set(v.id, v);
    });
    child.on("error", reject);
    // An adapter signals its own trouble with a non-zero exit (the reference
    // adapter does this when the guard writes stdout it could not classify, so
    // positional correlation may have shifted). Surfacing it is what keeps the
    // adapter's judgement from being silently overruled by a clean scoreboard.
    child.on("close", (code) => {
      if (code !== 0 && code !== null) {
        anomalies.push(`adapter exited ${code} — it reported the run as untrustworthy`);
      }
      resolve();
    });
  });
  for (const c of cases) child.stdin.write(JSON.stringify({ id: c.id, message: c.message }) + "\n");
  child.stdin.end();
  await done;
  return { verdicts, anomalies };
}

const t0 = Date.now();
const { verdicts, anomalies } = await runAdapter(adapterCmd, cases);

// ---- score ----------------------------------------------------------------
// Verdicts for ids that are not in the corpus mean the adapter and the runner
// disagree about what was sent -- a desync that leaves the id count intact and
// would otherwise be invisible. (`byId` existed for this check and went unused.)
for (const id of verdicts.keys()) {
  if (!byId.has(id)) anomalies.push(`verdict for unknown case id ${JSON.stringify(id)}`);
}

const isAttack = (c) => c.expected.action !== "pass"; // attacks + warn
let TP = 0, FN = 0, FP = 0, TN = 0, exact = 0, missingVerdict = 0, adapterErrors = 0, overBlocked = 0;
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
    if (nonPass) {
      TP++; catAgg[cat].detected++;
      // README: `warn/` cases must warn, never block -- blocking would corrupt
      // the document the user asked to read. Detection is still credited (the
      // guard did see it), but the contract violation is named, otherwise a
      // guard that simply blocks everything passes forward-with-warning
      // invisibly and the only trace is a diluted exact-action number.
      if (c.expected.action === "warn" && v.action === "block") {
        overBlocked++;
        misses.push({ id: c.id, reason: "over-blocked a warn-and-forward case (expected warn, got block)" });
      }
    }
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
  corpus: {
    total: cases.length,
    // `attacks` = expected-detection (attacks/ + warn/); the bucket split is
    // reported alongside so this never disagrees with the README's counts.
    attacks: cases.filter(isAttack).length,
    attackBucket: cases.filter((c) => c.bucket === "attacks").length,
    warnBucket: cases.filter((c) => c.bucket === "warn").length,
    benign: cases.filter((c) => !isAttack(c)).length,
  },
  coverage: { scored, missingVerdict, adapterErrors, complete: scored === cases.length },
  contractViolations: { overBlockedWarnCases: overBlocked },
  anomalies,
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

// `out/` is gitignored, so it does not exist in a fresh clone — create it rather
// than crashing on the first run (which is every new contributor and every CI job).
const OUT = path.join(ROOT, "out");
mkdirSync(OUT, { recursive: true });

const stamp = new Date().toISOString().slice(0, 10);
const jsonPath = path.join(OUT, `scoreboard-${adapterName}-${stamp}.json`);
writeFileSync(jsonPath, JSON.stringify(board, null, 2) + "\n");

// ---- markdown scoreboard --------------------------------------------------
const m = board.metrics;
const partial = scored !== cases.length;
const md = [
  `# Scoreboard — ${adapterName}`,
  ``,
  // A partial run's metrics are computed over ONLY the cases that answered, so
  // an adapter that drops the cases it would fail otherwise reports a clean
  // 100% here. This banner is what stops that number being quoted as a result.
  ...(partial
    ? [
        `> **⚠ PARTIAL RUN — metrics below are NOT comparable.** Only ${scored} of ${cases.length} cases produced a verdict`,
        `> (${missingVerdict} missing, ${adapterErrors} adapter error(s)). Every rate is computed over the ${scored} that answered,`,
        `> so dropped cases silently inflate them. Fix the adapter before quoting anything here.`,
        ``,
      ]
    : []),
  ...(anomalies.length
    ? [`> **⚠ ${anomalies.length} adapter anomal${anomalies.length === 1 ? "y" : "ies"}** — see the Anomalies section below.`, ``]
    : []),
  // "attack" here means "expected to be detected" = the attacks/ bucket PLUS the
  // warn/ bucket. Spelled out because the README counts the buckets separately
  // (21 attack / 3 warn) and two different corpus descriptions is a trap.
  `Corpus: ${board.corpus.total} cases — ${board.corpus.attacks} expected-detection (${board.corpus.attackBucket} \`attacks/\` + ${board.corpus.warnBucket} \`warn/\`), ${board.corpus.benign} benign. Scored ${scored}${partial ? ` of ${cases.length}` : ""}.`,
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
  ...(anomalies.length
    ? [`## Anomalies (${anomalies.length})`, ``, `Adapter output the runner could not use as scored data:`, ``, ...anomalies.map((a) => `- ${a}`), ``]
    : []),
].join("\n");
const mdPath = path.join(OUT, `scoreboard-${adapterName}-${stamp}.md`);
writeFileSync(mdPath, md);

// ---- console --------------------------------------------------------------
console.log(`\n─── ${adapterName} ───`);
console.log(`recall ${pct(m.recall)}  fp-rate ${pct(m.fp_rate)}  precision ${pct(m.precision)}  exact ${pct(m.exact_action_accuracy)}`);
console.log(`confusion: TP ${TP} FN ${FN} FP ${FP} TN ${TN}  (scored ${scored}/${cases.length})`);
if (misses.length) console.log(`misses: ${misses.length}`);
if (anomalies.length) console.log(`anomalies: ${anomalies.length} (see scoreboard)`);
console.log(`\n${mdPath}`);

// ---- exit status ----------------------------------------------------------
// Non-zero on INCOMPLETE COVERAGE only — a case that got no verdict or an
// adapter error means the harness is broken, and a partial scoreboard read as a
// full one is the failure mode that quietly overstates a guard.
//
// Deliberately NOT gated on the score. A new case that the guard under test
// misses is the benchmark working as intended (that is how the corpus grows);
// failing CI for it would create pressure to only add cases that already pass.
if (missingVerdict > 0 || adapterErrors > 0 || anomalies.length > 0) {
  console.error(
    `\nunhealthy run: ${missingVerdict} case(s) with no verdict, ${adapterErrors} adapter error(s), ` +
      `${anomalies.length} anomal${anomalies.length === 1 ? "y" : "ies"} — scoreboard covers ${scored}/${cases.length}`,
  );
  for (const a of anomalies.slice(0, 5)) console.error(`  - ${a}`);
  if (anomalies.length > 5) console.error(`  ... and ${anomalies.length - 5} more`);
  process.exitCode = 1;
}

function pct(x) { return x === null ? "—" : (x * 100).toFixed(1) + "%"; }
