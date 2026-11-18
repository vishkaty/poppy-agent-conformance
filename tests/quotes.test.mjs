// Automated spec verification: every check must quote published 1.0 verbatim.
//
// This is the one discipline worth carrying over from the register, and it is first
// because it is the cheapest. A check whose quote is not in the specification is a check
// enforcing a rule nobody wrote, and the only way to be sure is to look it up rather than
// remember it. Written before the checks were trusted, and it immediately caught a
// placeholder quote on version.constant that the author knew was wrong and would otherwise
// have shipped.
//
// The capture is a PUBLISHED version, verified page by page against the authors' own
// sha256 by tools/capture-verified.mjs, so "verbatim in the specification" is a provable
// statement rather than a claim about whatever the site served that day.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHECKS, PAIRWISE } from "../checks.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SNAP = join(HERE, "../spec");

const hay = readdirSync(SNAP).filter(f => f.endsWith(".md")).sort()
  .map(f => readFileSync(join(SNAP, f), "utf8")).join("\n")
  .replace(/\s+/g, " ");

test("the capture is present and whole, or every quote fails for the same wrong reason", () => {
  assert.ok(hay.length > 300_000, `the 1.0 capture looks wrong, ${hay.length} chars`);
  const prov = JSON.parse(readFileSync(join(SNAP, "PROVENANCE.json"), "utf8"));
  assert.equal(prov.version, "1.0");
  assert.equal(prov.published, "2026-11-14");
  assert.equal(prov.verified_against_authors_hashes, true,
    "the checks must be written against a capture proved against the authors' own hashes");
});

test("every check quotes published 1.0 verbatim", () => {
  const missing = [];
  for (const c of [...CHECKS, ...PAIRWISE]) {
    const q = c.quote.replace(/\s+/g, " ").trim();
    assert.ok(q.length > 25, `${c.id}: the quote is too short to identify a rule`);
    if (!hay.includes(q)) missing.push(`${c.id}: ${q.slice(0, 90)}`);
  }
  assert.deepEqual(missing, [], `${missing.length} check(s) quote text 1.0 does not have`);
});

// Section-scoped verbatim. The plain check above cannot tell a real sentence about the
// wrong rule from the right one, which it proved by passing a placeholder quote about
// `supported_versions` URLs on a check that tests the Poppy-Version header. Requiring the
// quote to live in the section the check names catches the common case: reaching for a
// sentence from somewhere else. It does not prove a quote is the RIGHT rule, and saying so
// here is better than implying the suite guarantees more than it does.
test("every check's quote is inside the section the check names", () => {
  const spec = readFileSync(join(SNAP, "spec.md"), "utf8");
  const bySection = new Map();
  let cur = null, buf = [];
  for (const line of spec.split("\n")) {
    const h = /^#{2,4}\s+([\d.]+)/.exec(line);
    if (h) { if (cur) bySection.set(cur, buf.join(" ")); cur = h[1].replace(/\.$/, ""); buf = []; }
    else buf.push(line);
  }
  if (cur) bySection.set(cur, buf.join(" "));
  assert.ok(bySection.size > 20, `only ${bySection.size} sections parsed; has the format changed?`);

  const wrong = [];
  for (const c of [...CHECKS, ...PAIRWISE]) {
    assert.ok(c.section, `${c.id} declares no section`);
    const text = (bySection.get(c.section) ?? "").replace(/\s+/g, " ");
    if (!text) { wrong.push(`${c.id}: section ${c.section} is not in the capture`); continue; }
    if (!text.includes(c.quote.replace(/\s+/g, " ").trim()))
      wrong.push(`${c.id}: its quote is not in section ${c.section}`);
  }
  assert.deepEqual(wrong, [], `${wrong.length} check(s) cite a section their quote is not in`);
});

test("no two checks enforce the same sentence", () => {
  // Not a style rule. Two ids on one sentence means one of them is misattributed, which is
  // how this project once filed a scope rule under the Device Sign-In response shape.
  const seen = new Map();
  for (const c of [...CHECKS, ...PAIRWISE]) {
    const q = c.quote.replace(/\s+/g, " ").trim();
    if (seen.has(q)) seen.get(q).push(c.id); else seen.set(q, [c.id]);
  }
  const dupes = [...seen].filter(([, ids]) => ids.length > 1).map(([, ids]) => ids.join(" and "));
  assert.deepEqual(dupes, [], "checks sharing one sentence");
});

test("the README states the real number of mutations", async () => {
  // Same reason as the check count below: a number in a public README that nobody owns drifts
  // away from the code, and this one is a claim about how well tested the thing is.
  const { MUTATIONS } = await import("../tools/killtest.mjs");
  const readme = readFileSync(join(HERE, "../README.md"), "utf8");
  const words = { 31: "thirty one", 40: "forty", 43: "forty three", 44: "forty four",
                  45: "forty five", 50: "fifty", 53: "fifty three", 54: "fifty four", 55: "fifty five",
                  50: "fifty" };
  const n = MUTATIONS.length;
  assert.ok(readme.toLowerCase().includes(`${words[n] ?? n} mutations`)
            || readme.includes(`${n} mutations`),
    `the README does not say "${words[n] ?? n} mutations" for ${n}`);
});

test("the README states the real number of checks", () => {
  // A public README that overstates its own coverage is the cheapest possible way to lose
  // standing, and the count drifted once already: it was written before the number was
  // verified. The suite owns it now.
  const readme = readFileSync(join(HERE, "../README.md"), "utf8");
  const words = { 18: "Eighteen", 19: "Nineteen", 20: "Twenty", 21: "Twenty one",
                  22: "Twenty two", 23: "Twenty three", 24: "Twenty four",
                  25: "Twenty five", 26: "Twenty six" };
  const total = CHECKS.length + PAIRWISE.length;
  assert.ok(readme.includes(`${words[total]} checks over a recorded request log`),
    `the README does not say "${words[total]} checks over a recorded request log" for ${total} checks`);
  assert.ok(readme.includes(`${words[CHECKS.length]} need one Company`),
    `the README does not say "${words[CHECKS.length]} need one Company" for ${CHECKS.length}`);
});
