#!/usr/bin/env node
/**
 * Reference adapter — @getmcpm/cli guard.
 *
 * Implements the mcp-guardbench adapter contract (see adapters/README.md):
 *   stdin:  NDJSON, one {"id","message"} per line
 *   stdout: NDJSON, one {"id","action","signature_id"?} per line
 *   action ∈ "pass" | "warn" | "block" | "error"
 *
 * It scores mcpm through mcpm's OWN PUBLISHED CLI — `mcpm guard inspect --json`
 * — not by importing the engine. That is deliberate and load-bearing for this
 * benchmark's credibility: every guard scored here, mcpm included, is measured
 * through the artifact its users actually run. (An earlier revision vendored an
 * esbuild bundle of mcpm's `src/guard/{patterns,signatures}`, which silently
 * drifted from the shipped engine and handed mcpm an in-process path no other
 * guard being scored could have.)
 *
 * `mcpm guard inspect --json` emits exactly one verdict per input frame in
 * INPUT ORDER, so this adapter pairs the Nth verdict with the Nth id.
 *
 * Configure the command under test with MCPM_CMD. The default assumes `mcpm` is
 * on PATH. To score a pinned published version (recommended for a citable run):
 *
 *   MCPM_CMD="npx --yes @getmcpm/cli@0.25.0 guard inspect --json" \
 *     node runner/run.mjs --adapter "node adapters/mcpm/adapter.mjs" --name mcpm@0.25.0
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const CMD = process.env.MCPM_CMD ?? "mcpm guard inspect --json";
const [bin, ...args] = CMD.split(" ").filter((s) => s !== "");

// Read every case up front so the id order is fixed before the child speaks.
const ids = [];
const frames = [];
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const trimmed = line.trim();
  if (trimmed === "") continue;
  try {
    const kase = JSON.parse(trimmed);
    ids.push(kase.id);
    frames.push(JSON.stringify(kase.message));
  } catch {
    // A malformed case line is the harness's problem, not the guard's — skip it
    // rather than desynchronizing the positional pairing below.
  }
}

const child = spawn(bin, args, { stdio: ["pipe", "pipe", "inherit"] });

let spawnFailed = false;
// A child that exits without draining stdin (wrong binary, unsupported
// subcommand) makes child.stdin.write raise EPIPE. Unhandled, that killed the
// adapter before the tail loop below could report the cases -- defeating this
// file's own guarantee that a case with no verdict is REPORTED, not dropped.
child.stdin.on("error", () => {});
child.on("error", (err) => {
  spawnFailed = true;
  process.stderr.write(`adapter: cannot run "${CMD}": ${err.message}\n`);
});

const VALID_ACTIONS = new Set(["pass", "warn", "block", "error"]);
const unexpectedLines = [];
let i = 0;
const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (trimmed === "") return;
  // Validate BEFORE consuming an id. Positional correlation means one stray
  // stdout line (a banner, an update notice, a future summary object) would
  // otherwise shift every following case by one and still report full coverage
  // -- a silent, confidently-wrong scoreboard. An unrecognized line is counted
  // as an anomaly instead, and the count check at the end fails the run.
  let verdict;
  try {
    verdict = JSON.parse(trimmed);
  } catch {
    unexpectedLines.push(trimmed);
    return;
  }
  if (verdict === null || typeof verdict !== "object" || !VALID_ACTIONS.has(verdict.action)) {
    unexpectedLines.push(trimmed);
    return;
  }
  const id = ids[i++];
  if (id === undefined) return; // more verdicts than cases — ignore the tail
  const out = { id, action: verdict.action };
  // Informational only — the runner scores on action. mcpm reports every
  // finding; the first is the one the action derives from.
  if (verdict.findings?.[0]?.signature_id) out.signature_id = verdict.findings[0].signature_id;
  if (verdict.action === "error" && verdict.error) out.error = verdict.error;
  process.stdout.write(JSON.stringify(out) + "\n");
});

for (const frame of frames) child.stdin.write(frame + "\n");
child.stdin.end();

await new Promise((resolve) => {
  // NOTE: a non-zero exit is EXPECTED — `guard inspect` exits 2 when any frame
  // would be blocked. The verdicts on stdout are the result; the code is not.
  let closed = 0;
  const bump = () => {
    if (++closed === 2) resolve();
  };
  rl.on("close", bump);
  child.on("close", bump);
  child.on("error", () => resolve());
});

// Any case that never got a verdict (guard missing, or the child died
// mid-stream) is reported, not silently dropped — "no verdict" and "passed" are
// very different claims, and the runner scores them differently.
const reason = spawnFailed ? `could not run "${CMD}"` : "no verdict emitted";
for (; i < ids.length; i++) {
  process.stdout.write(JSON.stringify({ id: ids[i], action: "error", error: reason }) + "\n");
}

// Anything the guard wrote to stdout that was not a verdict means the framing
// assumption behind positional correlation did not hold. Say so loudly rather
// than letting a possibly-shifted pairing be scored as data.
if (unexpectedLines.length > 0) {
  process.stderr.write(
    `adapter: ${unexpectedLines.length} unexpected stdout line(s) from "${CMD}" — ` +
      `positional correlation is unsafe, results for this run are not trustworthy.\n` +
      unexpectedLines.slice(0, 3).map((l) => `  ${l.slice(0, 120)}\n`).join(""),
  );
  process.exitCode = 1;
}
if (spawnFailed) process.exitCode = 1;
