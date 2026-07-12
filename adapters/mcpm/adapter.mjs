#!/usr/bin/env node
/**
 * Reference adapter — @getmcpm/cli guard.
 *
 * Implements the mcp-guardbench adapter contract (see adapters/README.md):
 *   stdin:  NDJSON, one {"id","message"} per line
 *   stdout: NDJSON, one {"id","action","signature_id"?} per line
 *   action ∈ "pass" | "warn" | "block"
 *
 * This reference build imports mcpm's inspection engine from engine.mjs (a tsup
 * bundle of src/guard/{patterns,signatures}). At publication this should instead
 * depend on the published @getmcpm/cli via a public one-frame inspect API — see
 * adapters/README.md "Publishing an adapter".
 */
import { createInterface } from "node:readline";
import { inspectMessage, OWASP_MCP_TOP_10 } from "./engine.mjs";

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  let kase;
  try {
    kase = JSON.parse(trimmed);
  } catch {
    continue; // skip malformed input line
  }
  let verdict;
  try {
    const result = inspectMessage(kase.message, OWASP_MCP_TOP_10);
    verdict = { id: kase.id, action: result.action };
    if (result.findings?.[0]?.signature_id) verdict.signature_id = result.findings[0].signature_id;
  } catch (err) {
    verdict = { id: kase.id, action: "error", error: err instanceof Error ? err.message : String(err) };
  }
  process.stdout.write(JSON.stringify(verdict) + "\n");
}
