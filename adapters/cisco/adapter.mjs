#!/usr/bin/env node
/**
 * Adapter — Cisco AI Defense MCP Scanner (`cisco-ai-mcp-scanner` on PyPI).
 *
 * Implements the mcp-guardbench adapter contract (see adapters/README.md):
 *   stdin:  NDJSON, one {"id","message"} per line
 *   stdout: NDJSON, one {"id","action"} per line
 *   action ∈ "pass" | "warn" | "block" | "unsupported" | "error"
 *
 * It drives the scanner's PUBLISHED CLI (`mcp-scanner static --tools`), the same
 * binary its users run. Nothing from the package is imported and no detection
 * logic is reproduced here — this file is NDJSON translation and nothing else.
 *
 *   python3 -m venv .venv && .venv/bin/pip install cisco-ai-mcp-scanner==4.8.2
 *   MCP_SCANNER_BIN=.venv/bin/mcp-scanner \
 *     node runner/run.mjs --adapter "node adapters/cisco/adapter.mjs" --name cisco@4.8.2
 *
 * ── Three things this adapter is deliberately careful about ────────────────
 *
 * 1. SCOPE, NOT CAPABILITY. `static` accepts tools/list-carried content only
 *    (--tools/--prompts/--resources). It has no input path for tool responses,
 *    tools/call arguments, or server-initiated elicitation/sampling frames. On
 *    those we emit "unsupported", never "pass" — reporting an abstention as a
 *    clean verdict would manufacture false negatives against a tool that never
 *    claimed to look there.
 *
 * 2. EXIT CODES ARE NOT A VERDICT CHANNEL. Measured: the scanner exits 0 on a
 *    HIGH finding AND exits 0 on `Error during scanning: Invalid tools file`.
 *    So a malformed invocation is indistinguishable from a clean sweep by exit
 *    status alone. The verdict is parsed from `--format raw` JSON, and anything
 *    that does not parse into the expected shape becomes "error" — never "pass".
 *
 * 3. OFFLINE MEANS YARA ONLY. Default analyzers are `api,yara,llm`; `api` needs
 *    MCP_SCANNER_API_KEY and `llm` needs an LLM key. We pass `--analyzers yara`
 *    so the run is reproducible with no account and no network. That is a real
 *    UNDER-representation of the product and must be stated wherever this row is
 *    published: we are scoring one of its three analyzers.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const BIN = process.env.MCP_SCANNER_BIN ?? "mcp-scanner";
// Comma-separated. Overridable so someone WITH keys can score the full product,
// but the default must stay key-free or the benchmark is not reproducible.
const ANALYZERS = process.env.MCP_SCANNER_ANALYZERS ?? "yara";

const log = (s) => process.stderr.write(`adapter(cisco): ${s}\n`);
const emit = (o) => process.stdout.write(JSON.stringify(o) + "\n");

/**
 * The scanner's own accepted surface, mapped from the JSON-RPC frame.
 * Returns the `static` flag plus the payload envelope it expects, or null when
 * the carrier is outside its input surface.
 *
 * Verified against `mcp-scanner static --help` and by execution: a bare array is
 * rejected with "missing 'tools' key", so the envelope is mandatory.
 */
function routeFrame(message) {
  const r = message?.result;
  if (!r || typeof r !== "object") return null;
  if (Array.isArray(r.tools)) return { flag: "--tools", payload: { tools: r.tools } };
  if (Array.isArray(r.prompts)) return { flag: "--prompts", payload: { prompts: r.prompts } };
  if (Array.isArray(r.resources)) return { flag: "--resources", payload: { resources: r.resources } };
  return null;
}

const SEVERITY_ACTION = { HIGH: "block", CRITICAL: "block", MEDIUM: "warn", LOW: "warn" };

/**
 * Map a scan result to an action.
 *
 * The severity ladder is OUR mapping, not the scanner's — it emits
 * is_safe + a severity string and takes no position on block-vs-warn. Recorded
 * explicitly because it is a judgement of ours sitting between the guard and its
 * score, and a reader is entitled to know which parts of a row we chose.
 */
function actionFor(parsed, expectedItems) {
  const results = parsed?.scan_results;
  if (!Array.isArray(results)) return { action: "error", error: "no scan_results array in --format raw output" };
  // Fail closed on a silent under-scan: if the scanner consumed fewer items than
  // we handed it, a "safe" verdict covers less than the frame did and must not
  // be scored as a pass. This is the anti-false-green gate — the same shape as
  // the exit-0-on-error behaviour documented above.
  if (results.length !== expectedItems) {
    return { action: "error", error: `scanned ${results.length} item(s), sent ${expectedItems}` };
  }
  let worst = "pass";
  for (const r of results) {
    for (const f of Object.values(r.findings ?? {})) {
      const mapped = SEVERITY_ACTION[String(f?.severity ?? "").toUpperCase()];
      if (mapped === "block") return { action: "block" };
      if (mapped === "warn") worst = "warn";
    }
    // is_safe:false with no severity we recognise still must not read as pass.
    if (r.is_safe === false && worst === "pass") worst = "warn";
  }
  return { action: worst };
}

function runScanner(flag, payload) {
  return new Promise((resolve) => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardbench-cisco-"));
    const file = path.join(dir, "payload.json");
    writeFileSync(file, JSON.stringify(payload));
    const args = ["--analyzers", ANALYZERS, "--format", "raw", "static", flag, file];
    // Scrub the key vars so a developer's local credentials cannot silently turn
    // a "reproducible offline run" into a networked one that nobody else can
    // reproduce. Reproducibility here is a property of the harness, not of the
    // machine that happened to run it.
    const env = { ...process.env };
    delete env.MCP_SCANNER_API_KEY;
    delete env.MCP_SCANNER_LLM_API_KEY;

    const child = spawn(BIN, args, { stdio: ["ignore", "pipe", "pipe"], env });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => {
      rmSync(dir, { recursive: true, force: true });
      resolve({ action: "error", error: `cannot run "${BIN}": ${e.message}` });
    });
    child.on("close", () => {
      rmSync(dir, { recursive: true, force: true });
      // stdout is one pretty-printed JSON document per process — parse the whole
      // buffer, never line-split.
      let parsed;
      try {
        parsed = JSON.parse(out);
      } catch {
        const hint = (err.match(/Error during scanning: .*/) ?? [out.slice(0, 120)])[0];
        return resolve({ action: "error", error: `unparseable --format raw output: ${hint}` });
      }
      resolve(actionFor(parsed, Object.values(payload)[0].length));
    });
  });
}

const cases = [];
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const t = line.trim();
  if (t === "") continue;
  try {
    cases.push(JSON.parse(t));
  } catch {
    // A malformed case line is the harness's problem. Verdicts are matched by
    // id, so skipping one cannot desynchronise the rest.
  }
}

let scored = 0;
let abstained = 0;
for (const kase of cases) {
  const route = routeFrame(kase.message);
  if (!route) {
    abstained++;
    emit({
      id: kase.id,
      action: "unsupported",
      error: "mcp-scanner static accepts tools/prompts/resources list output only; this carrier has no input path",
    });
    continue;
  }
  const verdict = await runScanner(route.flag, route.payload);
  scored++;
  emit({ id: kase.id, action: verdict.action, ...(verdict.error ? { error: verdict.error } : {}) });
}

log(`analyzers=${ANALYZERS} scored=${scored} abstained=${abstained} of ${cases.length}`);
