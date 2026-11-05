import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const adapter = new URL("./adapter.mjs", import.meta.url);
const input = JSON.stringify({ id: "case", message: {} }) + "\n";
function run(code, suffix = "", frames = input) {
  return spawnSync(process.execPath, [adapter.pathname], {
    input: frames, encoding: "utf8",
    env: { ...process.env, MCPM_CMD: `'${process.execPath}' -e '${code}' ${suffix}` },
  });
}
function verdict(result) {
  return JSON.parse(result.stdout.trim());
}

test("preserves unsupported verdict and reason", () => {
  const result = run('console.log(JSON.stringify({action:"unsupported",error:"outside scope"}))');
  assert.equal(result.status, 0);
  assert.deepEqual(verdict(result), { id: "case", action: "unsupported", error: "outside scope" });
});
test("preserves empty quoted arguments", () => {
  const result = run('console.log(JSON.stringify({action:process.argv[1] === "" ? "pass" : "error"}))', '""');
  assert.equal(verdict(result).action, "pass");
});
test("preserves literal backslashes in quoted paths", () => {
  // Use an error verdict to carry the argument back without executing the path.
  const echoed = run('console.log(JSON.stringify({action:"error",error:process.argv[1]}))', '"C:\\Program Files\\mcpm\\cli.js"');
  assert.equal(echoed.status, 0);
  assert.equal(verdict(echoed).error, "C:\\Program Files\\mcpm\\cli.js");
});
test("rejects unclosed command quotes", () => {
  const result = run('console.log(1)', '"');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unclosed/);
});
test("rejects ambiguous unsupported command escapes", () => {
  const result = run('console.log(JSON.stringify({action:"pass"}))', 'path\\ with\\ spaces');
  assert.notEqual(result.status, 0);
});
test("accepts complete warn verdicts with exit status 1", () => {
  const result = run('console.log(JSON.stringify({action:"warn"})); process.exitCode=1');
  assert.equal(result.status, 0);
  assert.equal(verdict(result).action, "warn");
});
test("preserves error verdicts with exit status 1 for runner rejection", () => {
  const result = run('console.log(JSON.stringify({action:"error",error:"cannot inspect"})); process.exitCode=1');
  assert.equal(result.status, 0);
  assert.deepEqual(verdict(result), { id: "case", action: "error", error: "cannot inspect" });
});
test("rejects exit status 1 when a block accompanies a warning", () => {
  const result = run('console.log(JSON.stringify({action:"block"})); console.log(JSON.stringify({action:"warn"})); process.exitCode=1', "", input + input.replace('"case"', '"case-2"'));
  assert.notEqual(result.status, 0);
});
test("accepts guard block exit status", () => {
  const result = run('console.log(JSON.stringify({action:"block"})); process.exitCode=2');
  assert.equal(result.status, 0);
  assert.equal(verdict(result).action, "block");
});
for (const [name, code] of [
  ["unknown action", 'console.log(JSON.stringify({action:"allow"}))'],
  ["extra verdict", 'console.log(JSON.stringify({action:"pass"})); console.log(JSON.stringify({action:"pass"}))'],
  ["crash after verdict", 'console.log(JSON.stringify({action:"pass"})); process.exitCode=1'],
  ["banner before verdict", 'console.log("banner"); console.log(JSON.stringify({action:"pass"}))'],
]) {
  test(`fails unhealthy output: ${name}`, () => assert.notEqual(run(code).status, 0));
}
test("missing verdict is reported as an error", () => {
  assert.equal(verdict(run("void 0")).action, "error");
});
