#!/usr/bin/env node
/**
 * Adapter — McpVanguard (`mcp-vanguard` on PyPI, github.com/provnai/McpVanguard).
 *
 * Implements the mcp-guardbench adapter contract (see adapters/README.md):
 *   stdin:  NDJSON, one {"id","message"} per line
 *   stdout: NDJSON, one {"id","action"} per line
 *   action ∈ "pass" | "warn" | "block" | "unsupported" | "error"
 *
 * Drives the published `vanguard benchmark-run` CLI — nothing from the package
 * is imported and no detection logic is reproduced here.
 *
 *   python3 -m venv .venv-vanguard && .venv-vanguard/bin/pip install mcp-vanguard==2.2.1
 *   VANGUARD_BIN=.venv-vanguard/bin/vanguard \
 *     node runner/run.mjs --adapter "node adapters/mcp-vanguard/adapter.mjs" --name mcp-vanguard@2.2.1
 *
 * ── Two things this adapter is deliberately careful about ──────────────────
 *
 * 1. LAYER-SCOPED, NOT THE FULL PROXY. `benchmark-run` evaluates a case
 *    through exactly ONE named harness (rules_engine / metadata_tool_list /
 *    metadata_initialize / ...), read directly from source
 *    (core/rules_engine.py, core/metadata_inspection.py) — not the composed
 *    `vanguard start` proxy pipeline a real deployment runs. This is a real
 *    under-representation and must be stated wherever this row is published.
 *    Verified by execution against corpus v3 (2026-08-23):
 *      - `rules_engine` reads only `message.params` (RulesEngine.check),
 *        regardless of method — so it covers tools/call REQUESTS and, read
 *        from source, any other method carrying `params` (elicitation/create,
 *        sampling/createMessage).
 *      - `metadata_tool_list` / `metadata_initialize` read `message.result`
 *        directly (metadata_inspection.py) — tools/list and initialize
 *        RESULTS.
 *      - There is NO harness that inspects arbitrary tool_response /
 *        resource_content — `behavioral_response` exists but (read from
 *        source) only measures response SIZE, not content. Those carriers
 *        abstain here, same as every list-scanner surveyed in this repo.
 *
 * 2. EXIT CODE IS NOT A VERDICT CHANNEL. `benchmark-run`'s exit code reflects
 *    whether `actual_action` matched the case's `expected_action` field — a
 *    pass/fail harness feature, not a run-health signal. Since every case
 *    here uses a placeholder `expected_action` (we read `actual_action`, not
 *    `passed`), the process exits 1 on almost every batch with a finding.
 *    Verdicts are parsed from `--json-output` stdout unconditionally; the
 *    exit code is ignored — the same lesson the Cisco adapter documents.
 *
 * JSON, not hand-rolled YAML: `benchmark-run --benchmark-file` reads its
 * corpus with `yaml.safe_load`, and JSON is a YAML subset — verified by
 * execution, so batches are written as plain JSON with a `.yaml` extension.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const BIN = process.env.VANGUARD_BIN ?? "vanguard";
const PROFILE = process.env.VANGUARD_PROFILE ?? "strict";

const log = (s) => process.stderr.write(`adapter(mcp-vanguard): ${s}\n`);
const emit = (o) => process.stdout.write(JSON.stringify(o) + "\n");

/**
 * Route a guardbench case's raw JSON-RPC message to the ONE Vanguard
 * benchmark harness that can see it, or null when no harness's documented
 * input surface (verified from source, see header) covers this carrier.
 */
function routeHarness(message) {
  if (message?.method && message?.params && typeof message.params === "object") {
    return "rules_engine";
  }
  const r = message?.result;
  if (r && typeof r === "object") {
    if (Array.isArray(r.tools)) return "metadata_tool_list";
    if ("protocolVersion" in r || typeof r.instructions === "string") return "metadata_initialize";
  }
  return null;
}

const ACTION_MAP = { ALLOW: "pass", WARN: "warn", BLOCK: "block" };

function runBatch(harness, batch) {
  return new Promise((resolve) => {
    const dir = mkdtempSync(path.join(tmpdir(), "guardbench-vanguard-"));
    const file = path.join(dir, "batch.yaml"); // JSON content, .yaml extension — see header
    const corpus = batch.map((kase) => ({
      case_id: kase.id,
      mcp38_id: "MCP-GUARDBENCH",
      title: kase.id,
      harness,
      // expected_action is a required field of Vanguard's own schema but is
      // never read by this adapter — only actual_action is scored.
      expected_action: "ALLOW",
      input: kase.message,
    }));
    writeFileSync(file, JSON.stringify(corpus));

    const args = ["benchmark-run", "--benchmark-file", file, "--json-output", "--profile", PROFILE];
    // No key/network env vars exist for this offline path (rules_engine and
    // metadata_* harnesses are deterministic, no Ollama semantic layer
    // invoked by benchmark-run) — nothing to scrub, unlike the Cisco adapter.
    const child = spawn(BIN, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => {
      rmSync(dir, { recursive: true, force: true });
      resolve({ error: `cannot run "${BIN}": ${e.message}` });
    });
    child.on("close", () => {
      rmSync(dir, { recursive: true, force: true });
      // Exit code is a pass/fail signal against our placeholder
      // expected_action, not a health signal (see header) — parse
      // unconditionally, never gate on it.
      let parsed;
      try {
        parsed = JSON.parse(out);
      } catch {
        const hint = err.split("\n").find((l) => l.trim()) ?? out.slice(0, 200);
        return resolve({ error: `unparseable --json-output: ${hint}` });
      }
      if (!Array.isArray(parsed?.evaluations)) {
        return resolve({ error: "no evaluations array in --json-output" });
      }
      resolve({ evaluations: parsed.evaluations });
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

// Group by harness so each is scored with exactly one `benchmark-run` call.
const byHarness = new Map();
let abstained = 0;
for (const kase of cases) {
  const harness = routeHarness(kase.message);
  if (!harness) {
    abstained++;
    emit({
      id: kase.id,
      action: "unsupported",
      error:
        "no McpVanguard benchmark harness inspects this carrier — rules_engine reads message.params only, " +
        "metadata_tool_list/metadata_initialize read message.result.{tools,instructions}; verified from source",
    });
    continue;
  }
  if (!byHarness.has(harness)) byHarness.set(harness, []);
  byHarness.get(harness).push(kase);
}

let scored = 0;
for (const [harness, batch] of byHarness) {
  const result = await runBatch(harness, batch);
  if (result.error) {
    for (const kase of batch) emit({ id: kase.id, action: "error", error: result.error });
    continue;
  }
  const byId = new Map(result.evaluations.map((e) => [e.case_id, e]));
  for (const kase of batch) {
    const ev = byId.get(kase.id);
    if (!ev) {
      // Fail-closed on a silent under-scan: a batch that returned fewer
      // evaluations than cases sent must not let the missing ones read as a
      // clean pass. Same doctrine as the Cisco adapter's item-count check.
      emit({ id: kase.id, action: "error", error: `no evaluation returned for this case (harness=${harness})` });
      continue;
    }
    const action = ACTION_MAP[ev.actual_action];
    if (!action) {
      emit({ id: kase.id, action: "error", error: `unrecognised actual_action ${JSON.stringify(ev.actual_action)}` });
      continue;
    }
    scored++;
    emit({ id: kase.id, action, ...(ev.actual_rule_id ? { signature_id: ev.actual_rule_id } : {}) });
  }
}

log(`profile=${PROFILE} scored=${scored} abstained=${abstained} of ${cases.length}`);
