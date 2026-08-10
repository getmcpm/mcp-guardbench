#!/usr/bin/env node
/**
 * Adapter — NAIVE BASELINE. This is not a guard and must never be presented as one.
 *
 * It is the floor: case-insensitive substring matching for a handful of obvious
 * attack phrases, over the whole frame, with no parsing, no normalisation, no
 * carrier awareness, and no notion of severity. Roughly thirty seconds of thought.
 *
 * WHY A BENCHMARK NEEDS ONE
 *
 * A score means nothing without a floor. If a real product cannot clearly beat
 * `String.includes`, the honest conclusion is usually that the corpus lacks
 * discriminating power on that slice — not that the product is bad. Publishing the
 * floor is how a reader can tell those two apart without trusting us.
 *
 * It deliberately does NOT abstain. It scores all 41 cases, so it is directly
 * comparable to any full-corpus row, and its false-positive rate is a real measure
 * of how much the benign corpus punishes naive matching.
 *
 * Keep this dumb. Every improvement made here makes the floor less useful. If you
 * find yourself adding normalisation or a decoder, you are writing a guard — put it
 * in its own adapter.
 */
import { createInterface } from "node:readline";

// Verbatim phrases only. No regex, no word boundaries, no Unicode handling — the
// point is to be beatable by anything that actually inspects the frame.
const PHRASES = [
  "ignore previous",
  "ignore all previous",
  "disregard previous",
  "system prompt",
  "id_rsa",
  ".ssh",
  "seed phrase",
  "private key",
];

for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const t = line.trim();
  if (t === "") continue;
  let kase;
  try {
    kase = JSON.parse(t);
  } catch {
    continue; // matched by id; a dropped line cannot desynchronise the rest
  }
  const hay = JSON.stringify(kase.message ?? "").toLowerCase();
  const hit = PHRASES.some((p) => hay.includes(p));
  // Always "block" when it fires — the baseline has no severity model, which is
  // exactly why its exact-action accuracy should look bad against warn-tier cases.
  process.stdout.write(JSON.stringify({ id: kase.id, action: hit ? "block" : "pass" }) + "\n");
}
