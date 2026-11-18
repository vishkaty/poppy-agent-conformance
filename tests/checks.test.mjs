// Every check must be able to FAIL, and must say INCONCLUSIVE when it cannot see.
//
// This is the guard this project exists to apply, written down in PRINCIPLES.md as "a check
// that cannot fail is worse than no check" after three measurements reported success they
// had not earned. A grader is the worst possible place to get it wrong: a check that can
// only pass tells every agent builder they are conforming.
//
// So for each check there is one deliberate breach that must produce FAIL, the conforming
// log that must produce PASS, and the empty log that must produce INCONCLUSIVE. The map is
// asserted to cover every check, so adding a check without a way to fail it breaks the
// suite rather than quietly adding a green light.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS, PAIRWISE, grade, gradePair } from "../checks.mjs";
import * as f from "./fixture.mjs";

import { BREACH, CTX_A, CTX_B, keys, conforming } from "./breaches.mjs";

test("every check has a deliberate breach, so none can be a green light by omission", () => {
  const missing = CHECKS.map(c => c.id).filter(id => !BREACH[id]);
  assert.deepEqual(missing, [], `${missing.length} check(s) have no way to fail`);
  const extra = Object.keys(BREACH).filter(id => !CHECKS.some(c => c.id === id));
  assert.deepEqual(extra, [], "breaches naming checks that do not exist");
});

test("a conforming agent passes every check", () => {
  const out = grade(conforming, f.ctx);
  const notPass = out.filter(r => r.verdict !== "PASS");
  assert.deepEqual(notPass.map(r => `${r.id}: ${r.verdict} ${r.why}`), [],
    "the control: if a conforming log does not pass, every FAIL below is meaningless");
});

test("an empty log is INCONCLUSIVE everywhere, never PASS and never FAIL", () => {
  // A grader that reports PASS on silence is the most damaging failure available to it:
  // the builder reads conformance into a run where their agent did nothing.
  const out = grade([], f.ctx);
  const wrong = out.filter(r => r.verdict !== "INCONCLUSIVE");
  assert.deepEqual(wrong.map(r => `${r.id}: ${r.verdict}`), [],
    "a check reached a verdict without seeing a single request");
});

for (const c of CHECKS) {
  test(`${c.id} fails when its rule is broken`, async () => {
    const log = await BREACH[c.id]();
    const r = grade(log, f.ctx).find(x => x.id === c.id);
    assert.equal(r.verdict, "FAIL", `expected FAIL, got ${r.verdict}: ${r.why}`);
    assert.ok(r.why && r.why.length > 10, "a FAIL must say what was wrong");
  });
}

test("the pairwise checks fail when an agent reuses identity across Companies", async () => {
  const sid = "sid-x", sub = "user-shared", dlgCompact = await f.delegation(keys);
  const a = [await f.request(keys, { sid, sub, dlgCompact })];
  const b = [await f.request(keys, { sid, sub, dlgCompact })];
  const out = gradePair(a, b, CTX_A, CTX_B);
  for (const r of out) assert.equal(r.verdict, "FAIL", `${r.id} should fail: ${r.why}`);

  // and pass when it does not
  const k2 = await f.agentKeys();
  const b2 = [await f.request(k2, { sub: "user-other" })];
  const ok = gradePair(a, b2, CTX_A, CTX_B);
  for (const r of ok) assert.equal(r.verdict, "PASS", `${r.id} should pass: ${r.why}`);
});

test("the pairwise checks are INCONCLUSIVE with traffic at only one Company", () => {
  const out = gradePair(conforming, [], CTX_A, CTX_B);
  for (const r of out) assert.equal(r.verdict, "INCONCLUSIVE", `${r.id}: ${r.verdict}`);
});

test("every FAIL names at least one request that decided it", async () => {
  // A FAIL a builder cannot trace to a request is one they have to ask us about, and this
  // grader is meant to answer without us. Checks that filter a list rather than loop over
  // it were returning an empty decidedBy, so the report rendered "decided by request #"
  // with nothing after it.
  const missing = [];
  for (const c of CHECKS) {
    const log = await BREACH[c.id]();
    const v = grade(log, f.ctx).find(x => x.id === c.id);
    assert.equal(v.verdict, "FAIL", `${c.id} did not fail its own breach`);
    if (!v.decidedBy || v.decidedBy.length === 0) missing.push(c.id);
  }
  assert.deepEqual(missing, [], `${missing.length} check(s) FAIL without naming a request`);
});

test("a verdict never claims to have compared what it could not compare", async () => {
  // Three passes that were untrue on a single request. A builder reads "all 1 jti values were
  // distinct" as conformance, when nothing was compared at all; and under a Company that
  // rejects a bad request at once, every run would end with one request and print them.
  // 5.2's sentences are about reuse and stability, which need two requests to observe.
  const one = await f.request(keys, {});
  for (const id of ["session.jti-unique", "session.sub-stable"]) {
    const v = grade([one], f.ctx).find(x => x.id === id);
    assert.equal(v.verdict, "INCONCLUSIVE", `${id} claimed a pass on one request: ${v.why}`);
    assert.equal(v.cause, "unreached");
    assert.match(v.why, /one request|nothing to compare|could change/i, `${id}: ${v.why}`);
  }
  // and with two they mean something again
  const dlgCompact = await f.delegation(keys);
  const two = [await f.request(keys, { sid: "s1", sub: "u1", dlgCompact }),
               await f.request(keys, { sid: "s1", sub: "u1", dlgCompact })];
  for (const id of ["session.jti-unique", "session.sub-stable"])
    assert.equal(grade(two, f.ctx).find(x => x.id === id).verdict, "PASS",
      `${id} abstains even when it had two requests to compare`);
});

test("the signature check does not report verifying a signature it never verified", async () => {
  // It returned "every Session JWT verified against its delegation's key on 1 request(s)" for
  // a JWT with no delegation, because there was no key to verify against and the loop skipped
  // it. The verdict was harmless, since delegation.present fails, but the sentence was false,
  // and a false sentence in a report is the thing this project spends most of its effort on.
  const v = grade([await f.request(keys, { noDlg: true })], f.ctx).find(x => x.id === "session.signature");
  assert.equal(v.verdict, "INCONCLUSIVE", `${v.verdict}: ${v.why}`);
  assert.match(v.why, /carried a delegation|no key to verify against/i, v.why);
  assert.equal(grade([await f.request(keys, {})], f.ctx).find(x => x.id === "session.signature").verdict,
    "PASS", "a real signature stopped being verified");
});

test("every historical rule abstains when no Session had two requests to compare", async () => {
  // Stated as a property over all three, because fixing two of them and leaving the third is
  // exactly what happened: version.constant still passed on a Session of one request, where
  // "the same values on every request" cannot be observed at all.
  const one = await f.request(keys, {});
  for (const id of ["session.jti-unique", "session.sub-stable", "version.constant"]) {
    const v = grade([one], f.ctx).find(x => x.id === id);
    assert.equal(v.verdict, "INCONCLUSIVE", `${id} claimed something on one request: ${v.why}`);
  }
});

test("two Poppy-Session headers break the same rule as a header that is not a JWT", async () => {
  // One sentence of 5.2, both ways of breaking it, which is why they are one check. The
  // evidence must still say which, or a builder cannot tell a duplicated header from a
  // malformed one.
  const a = await f.request(keys, {});
  const b = await f.request(keys, {});
  const dup = await f.request(keys, {});
  dup.headers["poppy-session"] = `${a.headers["poppy-session"]}, ${b.headers["poppy-session"]}`;
  dup.sessionHeaderCount = 2;
  dup.sessionHeaderDecodable = false;
  dup.sessionHeaderDuplicated = true;

  const v = grade([dup], f.ctx).find(x => x.id === "session.header-jwt");
  assert.equal(v.verdict, "FAIL", `${v.verdict}: ${v.why}`);
  assert.match(v.evidence.join(" "), /2 Poppy-Session headers/, v.evidence.join(" "));

  const junk = await f.request(keys, {});
  junk.headers["poppy-session"] = "not-a-jwt";
  junk.sessionHeaderDecodable = false;
  const w = grade([junk], f.ctx).find(x => x.id === "session.header-jwt");
  assert.equal(w.verdict, "FAIL", `${w.verdict}: ${w.why}`);
  assert.match(w.evidence.join(" "), /not a JWT/, w.evidence.join(" "));
});
