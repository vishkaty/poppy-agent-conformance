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

test("an iat failure shows both clocks, and says when every request is off by the same amount", async () => {
  // The grader compares the agent's iat with its own clock, and the canary signs with that same
  // clock, so a deployment whose clock has drifted fails every conforming agent while its own
  // control passes. That cannot be gated from inside; it can be disclosed. So the failure
  // carries both numbers, and when every offset is about the same it says what that looks like.
  const keys = await f.agentKeys();
  const at = Math.floor(Date.now() / 1000);
  const drifted = [await f.request(keys, { at, iat: at - 600 }),
                   await f.request(keys, { at, iat: at - 601 }),
                   await f.request(keys, { at, iat: at - 599 })];
  const v = grade(drifted, f.ctx).find(x => x.id === "session.iat-window");
  assert.equal(v.verdict, "FAIL");
  assert.match(v.evidence.join(" "), /\b\d{9,}\b.*\b\d{9,}\b/,
    `the evidence does not show both the agent's iat and our clock: ${v.evidence.join(" | ")}`);
  assert.match(v.why, /same amount|constant|clock/i,
    `the failure does not mention that a constant offset looks like a clock: ${v.why}`);

  // and a single scattered failure must NOT claim a clock problem
  const scattered = [await f.request(keys, { at, iat: at - 600 }),
                     await f.request(keys, { at, iat: at - 50_000 })];
  const w = grade(scattered, f.ctx).find(x => x.id === "session.iat-window");
  assert.equal(w.verdict, "FAIL");
  assert.ok(!/same amount|constant/i.test(w.why), `offsets that differ were called constant: ${w.why}`);
});

test("a delegation signed by a key the agent published verifies, with or without a kid", async () => {
  // 5.2 step 1: "Find the key in the Personal Agent's `jwks_uri` named by the delegation's
  // `kid`, and verify the delegation's signature with it."
  //
  // The sentence says `kid` NAMES the key, with no requirement word, and the authors' own
  // signer omits `kid` whenever the root key has none, which is every key its generateKey()
  // makes. Measured. So a check that failed a delegation for a missing `kid` would fail the
  // code of the people who wrote the specification, and tests/reference.test.mjs would catch
  // it. Match by the `kid` member, then by thumbprint, then by any key whose type fits the alg.
  const ref = await import("../reference/jose.ts");
  const ISS = "https://agent.example/agent.json";
  const operator = await ref.generateKey(), key = await ref.generateKey();
  const kid = await ref.thumbprint(operator.publicJwk);

  for (const [what, header] of [["no kid, as their signer writes it", {}],
                                ["a kid that is the thumbprint", { kid }],
                                ["a kid the key set carries as a member", { kid: "k1" }]]) {
    const dlg = await ref.signDelegation({ root: operator, delegated: key.publicJwk, iss: ISS, ...header });
    const published = header.kid === "k1"
      ? [{ ...operator.publicJwk, kid: "k1" }]
      : [{ ...operator.publicJwk, kid }];
    const r = await f.request(keys, { dlgCompact: dlg, claims: { iss: ISS } });
    r.issuerKeys = { outcome: "ok", iss: ISS, jwksUri: "https://agent.example/jwks.json",
                     keys: published, kids: published.map(k => k.kid), source: "fetch",
                     fetchedAt: Math.floor(Date.now() / 1000), ageSeconds: 0 };
    const v = grade([r], f.ctx).find(x => x.id === "delegation.signature");
    assert.equal(v.verdict, "PASS", `${what}: ${v.verdict} ${v.why}`);
    assert.match(v.why, /jwks\.json/, `${what}: the pass does not say where the key came from`);
  }
});

test("a delegation nobody published is a failure, which is the forgery this closes", async () => {
  // Today a Session JWT is verified against whatever key its delegation names, and the
  // delegation itself is taken at its word, so a stranger can mint one claiming any client_id.
  const ref = await import("../reference/jose.ts");
  const ISS = "https://agent.example/agent.json";
  const real = await ref.generateKey(), forged = await ref.generateKey(), key = await ref.generateKey();
  const dlg = await ref.signDelegation({ root: forged, delegated: key.publicJwk, iss: ISS });
  const r = await f.request(keys, { dlgCompact: dlg, claims: { iss: ISS } });
  r.issuerKeys = { outcome: "ok", iss: ISS, jwksUri: "https://agent.example/jwks.json",
                   keys: [{ ...real.publicJwk, kid: "k1" }], kids: ["k1"], source: "fetch",
                   fetchedAt: 1000, ageSeconds: 0 };
  const v = grade([r], f.ctx).find(x => x.id === "delegation.signature");
  assert.equal(v.verdict, "FAIL", `${v.verdict}: ${v.why}`);
  assert.match(v.evidence.join(" "), /k1|no key/, v.evidence.join(" "));
});

test("whose fault the fetch was decides whether the rule fails or abstains", async () => {
  const ISS = "https://agent.example/agent.json";
  const cases = [
    ["agent", "FAIL", null],
    ["server", "INCONCLUSIVE", "unreached"],
    ["grader", "INCONCLUSIVE", "grader"],
  ];
  for (const [outcome, verdict, cause] of cases) {
    const r = await f.request(keys, { claims: { iss: ISS } });
    r.issuerKeys = { outcome, iss: ISS, detail: `the ${outcome} said so`, keys: [], kids: [] };
    const v = grade([r], f.ctx).find(x => x.id === "delegation.signature");
    assert.equal(v.verdict, verdict, `${outcome}: ${v.verdict} ${v.why}`);
    if (cause) assert.equal(v.cause, cause, outcome);
    // the reason reaches the builder either as the headline or as the evidence beside it
    const said = v.why + " " + (v.evidence ?? []).join(" ");
    assert.match(said, /the .* said so/, `${outcome}: the verdict does not carry the reason: ${said}`);
  }
  // and with nothing attached at all, meaning this grader never looked, it abstains as our
  // own limit rather than failing anybody. The fixture attaches a fetched key set by default,
  // because that is the ordinary case, so this asks for the other one explicitly.
  const bare = await f.request(keys, { claims: { iss: ISS }, noIssuerKeys: true });
  const v = grade([bare], f.ctx).find(x => x.id === "delegation.signature");
  assert.equal(v.verdict, "INCONCLUSIVE");
  assert.equal(v.cause, "grader");
});

test("a verdict that depended on a cached fetch says so, with its age", async () => {
  // A FAIL decided on a cache a builder cannot see cannot be argued with, which is the same
  // principle the iat window follows by naming its own numbers.
  const ref = await import("../reference/jose.ts");
  const ISS = "https://agent.example/agent.json";
  const operator = await ref.generateKey(), key = await ref.generateKey();
  const dlg = await ref.signDelegation({ root: operator, delegated: key.publicJwk, iss: ISS });
  const r = await f.request(keys, { dlgCompact: dlg, claims: { iss: ISS } });
  r.issuerKeys = { outcome: "ok", iss: ISS, jwksUri: "https://agent.example/jwks.json",
                   keys: [{ ...operator.publicJwk, kid: "k1" }], kids: ["k1"],
                   source: "cache", fetchedAt: 1000, ageSeconds: 41 };
  const v = grade([r], f.ctx).find(x => x.id === "delegation.signature");
  assert.equal(v.verdict, "PASS", v.why);
  assert.match(v.why, /cached/i, `the verdict hides that it used a cache: ${v.why}`);
  assert.match(v.why, /41/, `the verdict hides the age of the cache: ${v.why}`);
});

test("an iss that is not an HTTPS URL is its own failure, with section 3's sentence", async () => {
  // Section 3: "Every URL this protocol defines or exchanges MUST be an HTTPS URL ... Companies
  // MUST reject one from a Personal Agent." It is decidable with no network, it is the
  // precondition of the fetch, and it needs its own quote: "find the key in the jwks_uri" is
  // the wrong sentence for a scheme defect.
  for (const [iss, verdict] of [["http://agent.example/agent.json", "FAIL"],
                                ["ftp://agent.example/a", "FAIL"],
                                ["not-a-url", "FAIL"],
                                ["https://agent.example/agent.json", "PASS"]]) {
    const r = await f.request(keys, { claims: { iss } });
    const v = grade([r], f.ctx).find(x => x.id === "session.iss-https");
    assert.equal(v.verdict, verdict, `${iss}: ${v.verdict} ${v.why}`);
  }
  // and delegation.signature stands aside for it rather than reporting the same thing twice
  const r = await f.request(keys, { claims: { iss: "http://agent.example/agent.json" } });
  const v = grade([r], f.ctx).find(x => x.id === "delegation.signature");
  assert.equal(v.verdict, "INCONCLUSIVE", `${v.verdict}: ${v.why}`);
  assert.match(v.why, /iss-https/, v.why);
});
