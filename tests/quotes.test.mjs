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

// Numbers as this README writes them. Two hand-written maps used to live in the tests below
// and each needed editing every time a count moved, which is how a test that owns a number
// becomes the thing standing in the way of the number changing.
const ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
              "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
              "seventeen", "eighteen", "nineteen"];
const TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"];
function spell(n) {
  if (n < 20) return ONES[n];
  if (n < 100) return (n % 10 === 0 ? TENS[Math.floor(n / 10)] : `${TENS[Math.floor(n / 10)]} ${ONES[n % 10]}`);
  return String(n);
}
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
  const n = MUTATIONS.length;
  assert.ok(readme.toLowerCase().includes(`${spell(n)} mutations`) || readme.includes(`${n} mutations`),
    `the README does not say "${spell(n)} mutations", nor "${n} mutations"`);
});

test("the README states the real number of checks", () => {
  // A public README that overstates its own coverage is the cheapest possible way to lose
  // standing, and the count drifted once already: it was written before the number was
  // verified. The suite owns it now.
  const readme = readFileSync(join(HERE, "../README.md"), "utf8");
  const total = CHECKS.length + PAIRWISE.length;
  const cap = (w) => w[0].toUpperCase() + w.slice(1);
  assert.ok(readme.includes(`${cap(spell(total))} checks over a recorded request log`),
    `the README does not say "${cap(spell(total))} checks over a recorded request log" for ${total}`);
  assert.ok(readme.includes(`${cap(spell(CHECKS.length))} need one Company`),
    `the README does not say "${cap(spell(CHECKS.length))} need one Company" for ${CHECKS.length}`);
});

test("the README's boundary paragraph names the real number of rules", () => {
  // "The twenty nine rules are concentrated almost entirely on one layer" sat on the first
  // screen while forty shipped, in the one paragraph a reader is told to take as the boundary
  // of the whole claim. Line 12 was derived and this prose was not, so a count the suite owns
  // in one sentence went stale in another. The derivation covers both now.
  const readme = readFileSync(join(HERE, "../README.md"), "utf8").replace(/\s+/g, " ");
  const total = CHECKS.length + PAIRWISE.length;
  assert.ok(readme.includes(`The ${spell(total)} rules are concentrated`),
    `the README does not say "The ${spell(total)} rules are concentrated" for ${total}`);
  assert.ok(readme.includes(`reading ${spell(total)} rules as`),
    `the README does not say "reading ${spell(total)} rules as" for ${total}`);
});

test("the README states the real coverage of the control that gates every lease", async () => {
  // The Status section said "23 of the 24 rules" after the count had moved twice, in the same
  // paragraph that says the test count is deliberately not quoted because it went stale. A
  // number in a public README that nobody owns drifts, and this one is the coverage claim a
  // reader would check first. The gate's own constants own it now.
  const { CANARY_RULES, CANARY_ABSTAINS } = await import("../rig.mjs");
  const readme = readFileSync(join(HERE, "../README.md"), "utf8").replace(/\s+/g, " ");
  const total = CHECKS.length + PAIRWISE.length;
  // On a deployment that fetches the agent's documents, the rules allowed to abstain must PASS
  // like any other, so the control covers all but the ones excluded outright.
  const covered = CANARY_RULES.length + Object.keys(CANARY_ABSTAINS).length;
  assert.ok(readme.includes(`${spell(covered)} of the ${spell(total)} rules`),
    `the README does not say "${spell(covered)} of the ${spell(total)} rules" for the control's coverage`);
  // Every rule the control cannot exercise, not a hand written list of one: the paragraph said
  // "the one it cannot exercise" while a second was being added, and a hard coded id would have
  // let that pass.
  const { CANARY_EXCLUDED } = await import("../rig.mjs");
  for (const id of Object.keys(CANARY_EXCLUDED))
    assert.ok(readme.includes(id),
      `the README does not name ${id}, which the control cannot exercise`);
});

test("the README states the real number of rules that are reported and never refused", async () => {
  // This number was wrong in the README twice: it said nine when the code had six, and still
  // said nine when the code had seven. A reader checking how much of this grader actually
  // refuses would have been misled in the direction that flatters us, which is the worst
  // direction. The code owns it now.
  const { ENFORCE_EXCLUDED } = await import("../enforce.mjs");
  const readme = readFileSync(join(HERE, "../README.md"), "utf8").replace(/\s+/g, " ");
  const n = Object.keys(ENFORCE_EXCLUDED).length;
  const cap = (w) => w[0].toUpperCase() + w.slice(1);
  assert.ok(readme.includes(`${cap(spell(n))} rules are reported and never refused`),
    `the README does not say "${cap(spell(n))} rules are reported and never refused" for ${n}`);
});
