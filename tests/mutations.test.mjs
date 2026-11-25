// Every mutation must still point at the code it claims to cover.
//
// A mutation whose anchor matches zero times is skipped, and one that matches twice cannot say
// which guard it broke. Either way it reports as covered while proving nothing, which is the
// same failure as a test that cannot fail. It has happened three times in one day: changing the
// key of a uniqueness map left an anchor matching zero, copying a helper into a second rule left
// one matching two, and extracting that helper to module level changed both its name and its
// indentation and broke three more.
//
// `npm run killtest` already reports stale anchors, but it takes twenty minutes, so this failure
// was only ever found long after the edit that caused it. This runs in milliseconds, so the edit
// and the complaint arrive together.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MUTATIONS } from "../tools/killtest.mjs";

const HERE = import.meta.dirname;

test("every mutation anchor matches exactly once in the file it names", () => {
  const sources = new Map();
  const wrong = [];
  for (const m of MUTATIONS) {
    if (!sources.has(m.file)) sources.set(m.file, readFileSync(join(HERE, "..", m.file), "utf8"));
    const n = sources.get(m.file).split(m.find).length - 1;
    if (n !== 1) wrong.push(`${m.id} in ${m.file}: ${n} matches`);
  }
  assert.deepEqual(wrong, [],
    `a mutation that cannot be pinned to one place proves nothing:\n  ${wrong.join("\n  ")}`);
});

test("a mutation really changes the file, and every id is unique", () => {
  // `to` equal to `find` would apply cleanly, break nothing, and be killed by nothing, so it
  // would read as a surviving mutation forever. Duplicate ids would let one entry hide another.
  const seen = new Set();
  for (const m of MUTATIONS) {
    assert.notEqual(m.find, m.to, `${m.id} replaces its anchor with itself`);
    assert.ok(!seen.has(m.id), `two mutations share the id ${m.id}`);
    seen.add(m.id);
    assert.ok(m.kills && m.kills.length > 3, `${m.id} names no test it must be killed by`);
  }
});
