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

test("a conforming agent passes every check it can reach, and the rest are declared", async () => {
  // The control: if a conforming log does not pass, every FAIL below is meaningless. It used to
  // require a PASS from every rule, which held while every rule was about a request an agent
  // sends. A rule about what an agent does AFTER a refusal cannot be reached by traffic that is
  // never refused, so those are declared in breaches.mjs with a reason, and the declaration is
  // itself checked: a listed rule must really be unreached, and the cause must be the agent not
  // reaching it rather than this grader failing to judge.
  const { CONFORMING_UNREACHED } = await import("./breaches.mjs");
  const out = grade(conforming, f.ctx);
  const ids = out.map(r => r.id);
  for (const id of Object.keys(CONFORMING_UNREACHED)) {
    assert.ok(ids.includes(id), `the list names a rule that does not exist: ${id}`);
    assert.ok(String(CONFORMING_UNREACHED[id]).length > 40, `the reason given for ${id} says nothing`);
  }
  const notPass = out.filter(r => r.verdict !== "PASS" && !CONFORMING_UNREACHED[r.id]);
  assert.deepEqual(notPass.map(r => `${r.id}: ${r.verdict} ${r.why}`), [],
    "a conforming log did not pass a rule it reaches");
  for (const id of Object.keys(CONFORMING_UNREACHED)) {
    const v = out.find(r => r.id === id);
    assert.equal(v.verdict, "INCONCLUSIVE", `${id} is declared unreachable by conforming traffic and yet reached a verdict`);
    assert.equal(v.cause, "unreached", `${id} abstained as this grader's own limit, which is not what the list claims`);
  }
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

test("session.not-on-documents abstains for an agent that never sent a Session at all", async () => {
  // Found by a run that fetched poppy.json and nothing else, sent no Session JWT, and was
  // PASSED by this rule. The pass was free. An agent with no Session JWT
  // anywhere has not reached the point the rule governs, which is the choice of where to send
  // one, and this file's own header says INCONCLUSIVE means exactly that. A rule that `curl`
  // passes tells a builder their agent keeps Session JWTs off documents when nothing checked.
  const log = [
    { seq: 1, at: 1, method: "GET", path: "/.well-known/poppy.json", url: "https://shop.example/.well-known/poppy.json",
      headers: {}, mustNotCarry: true, isResource: false, isPage: false,
      sessionHeaderCount: 0, classifiedAs: "a discovery document (5.2)" },
    { seq: 2, at: 2, method: "GET", path: "/poppy/openapi.json", url: "https://shop.example/poppy/openapi.json",
      headers: {}, mustNotCarry: true, isResource: false, isPage: false,
      sessionHeaderCount: 0, classifiedAs: "a description document (5.2)" },
  ];
  const v = grade(log, f.ctx).find(x => x.id === "session.not-on-documents");
  assert.equal(v.verdict, "INCONCLUSIVE",
    `an agent that sent no Session JWT anywhere was given a PASS on where it sends them: ${v.why}`);
  assert.equal(v.cause, "unreached", "this is the agent not reaching the rule, not the grader failing to judge");
});

test("an undecodable Session header sent to a document is still the breach", async () => {
  // The control for the abstention above, and it was added because a mutation proved the
  // comment beside that guard was unprotected: switching the test from "any Session header" to
  // "a decodable Session JWT" broke nothing. 5.2 forbids sending a Company's Session JWT to
  // these destinations; an agent that sends unparseable bytes in that header has still sent
  // something there, and excusing it would mean the worse agent escapes the rule.
  const log = [
    { seq: 1, at: 1, method: "GET", path: "/.well-known/poppy.json", url: "https://shop.example/.well-known/poppy.json",
      headers: { "poppy-session": "not-a-jwt" }, mustNotCarry: true, isResource: false, isPage: false,
      sessionHeaderCount: 1, sessionHeaderDecodable: false, classifiedAs: "a discovery document (5.2)" },
  ];
  const v = grade(log, f.ctx).find(x => x.id === "session.not-on-documents");
  assert.equal(v.verdict, "FAIL",
    `a Session header was sent to a document and the rule said ${v.verdict}: ${v.why}`);
});

// 8.3's request IDs. Added after a conversation POST with no top-level `id` passed every rule
// here: a real 1.0 MUST that no rule of ours named, so a builder would have been told nothing
// was wrong.
test("a conversation POST with no request id fails, and a retry with the same id does not", async () => {
  const post = (over = {}) => ({
    seq: 1, at: 1, method: "POST", path: "/poppy/conversations", url: "https://shop.example/poppy/conversations",
    headers: {}, isResource: true, sessionHeaderCount: 1, conversationRoute: "start",
    body: JSON.stringify({ message: { text: "hello" } }), ...over });

  const missing = grade([post()], f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(missing.verdict, "FAIL", `a POST with no id was not caught: ${missing?.why}`);

  const withId = grade([post({ body: JSON.stringify({ id: "r1", message: { text: "hello" } }) })], f.ctx)
    .find(x => x.id === "conversation.request-id");
  assert.equal(withId.verdict, "PASS", `a conforming POST was failed: ${withId.why}`);

  // 8.3: "To retry a request, the Personal Agent sends it again to the same path with the same
  // ID." So a repeated id with the same path and body is required behaviour, not a breach.
  const retry = [post({ seq: 1, at: 1, body: JSON.stringify({ id: "r1", message: { text: "hi" } }) }),
                 post({ seq: 2, at: 2, body: JSON.stringify({ id: "r1", message: { text: "hi" } }) })];
  const retried = grade(retry, f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(retried.verdict, "PASS", `a legitimate retry was failed: ${retried.why}`);

  // But the same id on a different body, from ONE User, is the uniqueness breach the MUST names.
  // These records carry a real Session JWT, because the User is what the sentence is about and a
  // request with no Session leaves it unknowable: a fixture without one would be asserting the
  // old, wrong behaviour of comparing ids globally.
  const keys = await f.agentKeys();
  const sub = "user-one";
  const reused = [
    await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                            sub, body: JSON.stringify({ id: "r1", message: { text: "one" } }) }),
    await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                            sub, body: JSON.stringify({ id: "r1", message: { text: "two" } }) }),
  ];
  const clash = grade(reused, f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(clash.verdict, "FAIL", `an id reused for a different request was not caught: ${clash.why}`);

  // And nothing to judge when the agent never talked to the Company Agent.
  const none = grade([post({ conversationRoute: null, method: "GET" })], f.ctx)
    .find(x => x.id === "conversation.request-id");
  assert.equal(none.verdict, "INCONCLUSIVE");
  assert.equal(none.cause, "unreached");
});

// The ways this rule accused a conforming agent, every one of them found by an adversarial
// review rather than by the suite. A wrong rule in a public grader costs more than a missing
// one, so each is a named test.
test("the request id rule does not accuse an agent whose body this grader could not read", async () => {
  const post = (over = {}) => ({
    seq: 1, at: 1, method: "POST", path: "/poppy/conversations", url: "https://shop.example/poppy/conversations",
    headers: {}, isResource: true, sessionHeaderCount: 1, conversationRoute: "start", bodyComplete: true,
    body: JSON.stringify({ id: "r1", message: { text: "hello" } }), ...over });
  const verdict = (log) => grade(log, f.ctx).find(x => x.id === "conversation.request-id");

  // A 300 KB message is cut at the body cap, so the id it really sent is not in what we kept.
  const truncated = verdict([post({ body: '{"id":"r1","mes', bodyTruncated: true })]);
  assert.notEqual(truncated.verdict, "FAIL",
    `a truncated body was reported as a missing id: ${truncated.why}`);
  assert.equal(truncated.cause, "grader", "this is our cap, so the abstention is ours and not the agent's");

  // A socket that went away mid upload is not a protocol breach either.
  const aborted = verdict([post({ body: '{"id":"r1","mes', bodyComplete: false })]);
  assert.notEqual(aborted.verdict, "FAIL", `an aborted body was reported as a missing id: ${aborted.why}`);
});

test("request ids are unique for the User, not across Users", async () => {
  // 8.3: "which MUST make it unique for the User across all its requests". Two Users of one
  // agent may each number their own requests from one, and the rule compared ids globally.
  const keys = await f.agentKeys();
  const one = await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                                      sub: "user-A", body: JSON.stringify({ id: "r1", message: { text: "one" } }) });
  const two = await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                                      sub: "user-B", body: JSON.stringify({ id: "r1", message: { text: "two" } }) });
  const v = grade([one, two], f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(v.verdict, "PASS", `two Users reusing an id were accused of reusing it: ${v.why}`);
});

test("a retry is still a retry when its body is serialised differently", async () => {
  // 8.3 says a retry repeats the path and the ID, and says nothing about member order. The rule
  // compared raw bytes, so an agent that rebuilt the same JSON was accused of reusing an id for
  // a different request. This grader was stricter than its own Company, which compares the
  // parsed body.
  // A real Session on both, and one User, or the uniqueness half never runs and this test would
  // prove nothing about how bodies are compared. A mutation caught exactly that: switching the
  // comparison back to raw bytes broke no test while these records had no Session.
  const keys = await f.agentKeys();
  const sub = "user-one";
  const log = [
    await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                            sub, body: '{"id":"r1","message":{"text":"hi"}}' }),
    await f.request(keys, { method: "POST", path: "/poppy/conversations", conversationRoute: "start",
                            sub, body: '{"message":{"text":"hi"},"id":"r1"}' }),
  ];
  const v = grade(log, f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(v.verdict, "PASS", `a re-serialised retry was treated as a different request: ${v.why}`);
  assert.match(v.why, /compared per User/, "the uniqueness half did not actually run, so this proves nothing");
});

test("a target this grader refused to classify is not judged by the request id rule either", async () => {
  // The record says in words that no rule examined it, because the path we would judge is not
  // provably the path the Company serves. A rule that filtered on the conversation route alone
  // judged it anyway, which made the report contradict itself.
  const v = grade([{ seq: 1, at: 1, method: "POST", path: "/poppy/conversations",
                     url: "https://shop.example/poppy/conversations", headers: {}, bodyComplete: true,
                     isResource: false, unsafeTarget: true, conversationRoute: "start",
                     sessionHeaderCount: 1, body: JSON.stringify({ message: { text: "x" } }),
                     classifiedAs: "the target has dot segments or a backslash: examined by no rule" }], f.ctx)
    .find(x => x.id === "conversation.request-id");
  assert.equal(v.verdict, "INCONCLUSIVE",
    `a request the record says no rule examined was judged anyway: ${v.verdict} ${v.why}`);
});

test("when this grader cannot tell whose request it is, it does not judge uniqueness for the User", async () => {
  // 8.3's uniqueness is per User, and the User comes from the Session JWT. A conversation POST
  // with no Session header leaves that unknowable, and guessing that two such requests belong to
  // one User is how this rule would accuse an agent of reusing an id across Users. Sending no
  // Session header there is itself a breach, and session.header-sent is the rule that says so:
  // this one judges its own sentence and abstains where it cannot.
  const post = (body, seq) => ({
    seq, at: seq, method: "POST", path: "/poppy/conversations", url: "https://shop.example/poppy/conversations",
    headers: {}, isResource: true, sessionHeaderCount: 0, conversationRoute: "start", bodyComplete: true, body });
  const v = grade([post(JSON.stringify({ id: "r1", message: { text: "one" } }), 1),
                   post(JSON.stringify({ id: "r1", message: { text: "two" } }), 2)], f.ctx)
    .find(x => x.id === "conversation.request-id");
  assert.notEqual(v.verdict, "FAIL",
    `two requests of unknown Users were accused of sharing an id: ${v.why}`);
});

test("the request id rule judges conversation routes and nothing else", async () => {
  // Proved necessary by a mutation: deleting the conversation-route filter broke no test at all,
  // so the scope the rule's own comment claims was unprotected. An API operation a Company lists
  // has its own body, and requiring an `id` there would be a rule nobody wrote.
  const keys = await f.agentKeys();
  const apiPost = await f.request(keys, { method: "POST", path: "/poppy/orders",
                                          body: JSON.stringify({ item: "x" }) });
  const v = grade([apiPost], f.ctx).find(x => x.id === "conversation.request-id");
  assert.equal(v.verdict, "INCONCLUSIVE",
    `a POST to a listed API was judged against 8.3's request ids: ${v.verdict} ${v.why}`);
  assert.match(v.why, /conversation route/i);
});

// 8.2's id format. The gap the README named: our own Company answers `invalid_request` for an id
// outside the allowed alphabet while no rule faulted it, so a report could show a refused request
// beside a rule that found nothing wrong with it. That disagreement between a status code and a
// verdict is the thing this grader exists to prevent.
test("a request id outside the alphabet 8.2 allows is caught, and a long one too", async () => {
  const keys = await f.agentKeys();
  const withId = async (id) => f.request(keys, {
    method: "POST", path: "/poppy/conversations", conversationRoute: "start", sub: "user-one",
    body: JSON.stringify({ id, message: { text: "hello" } }) });
  const verdict = async (id) =>
    grade([await withId(id)], f.ctx).find(x => x.id === "conversation.id-format");

  assert.equal((await verdict("req_1-A_b2")).verdict, "PASS", "letters, digits, - and _ are the alphabet");
  assert.equal((await verdict("msg 1/2")).verdict, "FAIL", "a space and a slash are not in the alphabet");
  assert.equal((await verdict("a".repeat(257))).verdict, "FAIL", "8.2 allows 1 to 256 characters");
  assert.equal((await verdict("a".repeat(256))).verdict, "PASS", "256 is allowed, so the bound is inclusive");

  // A missing id belongs to the other rule, and two rules accusing one request for one mistake
  // would double count it.
  const noId = await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                       conversationRoute: "start", sub: "user-one",
                                       body: JSON.stringify({ message: { text: "hello" } }) });
  const v = grade([noId], f.ctx).find(x => x.id === "conversation.id-format");
  assert.equal(v.verdict, "INCONCLUSIVE", `a missing id was faulted twice: ${v.why}`);
});

test("this Company never refuses a request id that its own rules accept", async () => {
  // The disagreement, as a test rather than as a hope. Whatever the Company's own conversation
  // handler rejects as a malformed id, the rule must fault too, or a builder sees a 400 beside a
  // clean verdict and cannot tell which of the two to believe.
  const { conversationRouteOf } = await import("../record.mjs");
  const keys = await f.agentKeys();
  for (const id of ["msg 1/2", "a".repeat(257), "has+plus", "has=pad", ""]) {
    const rec = await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                        conversationRoute: "start", sub: "user-one",
                                        body: JSON.stringify({ id, message: { text: "x" } }) });
    const verdicts = grade([rec], f.ctx);
    const faulted = verdicts.some(v => v.verdict === "FAIL"
      && (v.id === "conversation.id-format" || v.id === "conversation.request-id"));
    assert.ok(faulted, `this Company refuses the id ${JSON.stringify(id)} and no rule faults it`);
  }
});

test("one mistake in a request id is one FAIL, not two", async () => {
  // `conversation.id-format` says in its own comment that a missing id is left to
  // `conversation.request-id`, so one mistake is not counted twice. It was counted twice anyway:
  // an id of 123, or "", is PRESENT, so the format rule judged it and failed it under 8.2 while
  // the request id rule failed the same body under 8.3. A report showing two defects where a
  // builder made one overstates the fault and makes the count of failures untrustworthy.
  const keys = await f.agentKeys();
  for (const bad of [123, "", null, { nested: true }]) {
    const rec = await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                        conversationRoute: "start", sub: "user-one",
                                        // an author, so the id is the ONLY mistake in this body
                                        body: JSON.stringify({ id: bad, message: { author: { type: "agent" }, text: "x" } }) });
    const failed = grade([rec], f.ctx).filter(v => v.verdict === "FAIL" && v.id.startsWith("conversation."));
    assert.deepEqual(failed.map(v => v.id), ["conversation.request-id"],
      `id ${JSON.stringify(bad)} was faulted by ${failed.length} rules: ${failed.map(v => v.id).join(", ")}`);
  }
  // And a usable id with characters 8.2 forbids is the format rule's own business, alone.
  const wrongAlphabet = await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                                conversationRoute: "start", sub: "user-one",
                                                body: JSON.stringify({ id: "msg 1/2", message: { author: { type: "agent" }, text: "x" } }) });
  const failed = grade([wrongAlphabet], f.ctx).filter(v => v.verdict === "FAIL" && v.id.startsWith("conversation."));
  assert.deepEqual(failed.map(v => v.id), ["conversation.id-format"]);
});

// 8.4 and 8.8, the message itself. The top of the coverage map: this Company already answers
// `invalid_request` for a message with no content while no rule faulted it, and it accepts a
// message that never says whether a person or an AI is speaking, which is the one disclosure the
// protocol asks an agent to make.
const convPost = async (keys, body, over = {}) => f.request(keys, {
  method: "POST", path: "/poppy/conversations", conversationRoute: "start", sub: "user-one",
  body: JSON.stringify(body), ...over });

test("a message with no content is faulted, and every kind of content is accepted", async () => {
  const keys = await f.agentKeys();
  const verdict = async (message) => {
    const rec = await convPost(keys, { id: "r1", message });
    return grade([rec], f.ctx).find(x => x.id === "conversation.message-content");
  };
  assert.equal((await verdict({ author: { type: "agent" } })).verdict, "FAIL",
    "a message with none of text, data, context or extensions must be faulted");
  for (const content of [{ text: "hello" }, { data: { a: 1 } }, { context: { locale: "en-US" } },
                         { extensions: { "x": {} } }])
    assert.equal((await verdict({ author: { type: "agent" }, ...content })).verdict, "PASS",
      `8.4 allows ${Object.keys(content)[0]} alone`);
  // An empty string is content the agent chose to send. 8.4 asks for one of the four fields to be
  // there, and says nothing about what is in it, so this rule says nothing either.
  assert.equal((await verdict({ author: { type: "agent" }, text: "" })).verdict, "PASS",
    "8.4 asks for the field, not for what is in it");
});

test("a message that never says whether a person or an AI is speaking is faulted", async () => {
  const keys = await f.agentKeys();
  const verdict = async (message) => {
    const rec = await convPost(keys, { id: "r1", message });
    return grade([rec], f.ctx).find(x => x.id === "conversation.message-author");
  };
  assert.equal((await verdict({ text: "hello" })).verdict, "FAIL", "no author at all");
  assert.equal((await verdict({ text: "hello", author: {} })).verdict, "FAIL", "an author with no type");
  assert.equal((await verdict({ text: "hello", author: { type: "robot" } })).verdict, "FAIL",
    "8.8 defines two values and robot is not one of them");
  for (const type of ["agent", "human"])
    assert.equal((await verdict({ text: "hello", author: { type } })).verdict, "PASS", type);
  // And it must say plainly what it cannot know: a Company never sees the User's own words, so
  // whether `human` was the truthful choice is not decidable from the wire.
  const ok = await verdict({ text: "hello", author: { type: "human" } });
  assert.match(ok.why, /cannot|not decidable|never sees/i,
    `the verdict must admit it cannot judge which value is truthful: ${ok.why}`);
});

test("neither message rule accuses an agent over a request this grader could not read", async () => {
  // The four ways the 8.3 rule accused conforming agents, applied to these two before they ship.
  const keys = await f.agentKeys();
  const ids = ["conversation.message-content", "conversation.message-author"];
  const cases = {
    "a body cut at our cap": { body: '{"id":"r1","mes', bodyTruncated: true },
    "a body that never arrived": { body: '{"id":"r1","mes', bodyComplete: false },
    // The case that actually distinguishes the guard, found by a mutation that survived without
    // it: a body that PARSES and is still not the whole request. A socket can drop after a
    // complete JSON body arrived but before the request ended, and the kept bytes are then valid
    // JSON missing nothing visible. Judged, that message looks like one with no author.
    "a parseable body that is not the whole request":
      { body: JSON.stringify({ id: "r1", message: { text: "x" } }), bodyComplete: false },
    "a parseable body cut at the cap":
      { body: JSON.stringify({ id: "r1", message: { text: "x" } }), bodyTruncated: true },
    "a target we refused to classify": { unsafeTarget: true, isResource: false,
                                         body: JSON.stringify({ id: "r1", message: { text: "x" } }) },
  };
  for (const [what, over] of Object.entries(cases)) {
    const rec = await convPost(keys, { id: "r1", message: { text: "x" } }, over);
    for (const id of ids) {
      const v = grade([rec], f.ctx).find(x => x.id === id);
      assert.notEqual(v.verdict, "FAIL", `${id} accused an agent over ${what}: ${v.why}`);
    }
  }
  // A conversation route that carries no message is not a message with something missing.
  const close = await f.request(keys, { method: "POST", path: "/poppy/conversations/c_1/close",
                                        conversationRoute: "close", sub: "user-one",
                                        body: JSON.stringify({ id: "r9" }) });
  for (const id of ids) {
    const v = grade([close], f.ctx).find(x => x.id === id);
    assert.equal(v.verdict, "INCONCLUSIVE", `${id} faulted a route that carries no message: ${v.why}`);
  }
  // And a POST to a listed API is not a conversation at all.
  const api = await f.request(keys, { method: "POST", path: "/poppy/orders",
                                      body: JSON.stringify({ item: "x" }) });
  for (const id of ids)
    assert.equal(grade([api], f.ctx).find(x => x.id === id).verdict, "INCONCLUSIVE");
});

// Section 7, the retry rule. Item 2 of the coverage map. A refusal is only useful if the agent
// acts on it, and a retry loop after a 400 is a classic client bug.
test("an agent that resends a request it was told to stop sending is faulted", async () => {
  // 8.3 defines a retry as the same path with the same request id, and that is the only identity
  // this rule uses. See the test below for the false positive that taught it.
  const keys = await f.agentKeys();
  const refusedBy = (rule) => ({ rejection: { rule, error: "invalid_session" },
                                 response: { status: 400, error: "invalid_session" } });
  const bodyWith = (id) => JSON.stringify({ id, message: { author: { type: "agent" }, text: "x" } });
  const post = async (over = {}) => f.request(keys, {
    method: "POST", path: "/poppy/conversations", conversationRoute: "start", sub: "user-one",
    body: bodyWith("r1"), ...over });
  const verdict = (log) => grade(log, f.ctx).find(x => x.id === "session.stops-after-refusal");

  const first = await post({ seq: 1, at: 1, ...refusedBy("session.alg") });
  const again = await post({ seq: 2, at: 2, ...refusedBy("session.alg") });
  assert.equal(verdict([first, again]).verdict, "FAIL",
    "the same path and id, refused again by the same rule, is the breach section 7 names");

  // Refused once and not resent.
  assert.equal(verdict([first]).verdict, "PASS");

  // A different request id is a different request, not a retry of the first.
  const other = await post({ seq: 2, at: 2, body: bodyWith("r2"), ...refusedBy("session.alg") });
  assert.equal(verdict([first, other]).verdict, "PASS", "a different request id is not a retry");

  // The same request refused by a DIFFERENT rule means the agent changed something, which is
  // exactly what section 7 asks of it.
  const fixedOne = await post({ seq: 2, at: 2, ...refusedBy("session.aud") });
  assert.equal(verdict([first, fixedOne]).verdict, "PASS",
    "an agent that fixed one cause and tripped another did what it was told");

  // And a resend that was accepted proves nothing about the agent.
  const accepted = await post({ seq: 2, at: 2, response: { status: 201, error: null } });
  assert.equal(verdict([first, accepted]).verdict, "PASS");
});
test("the retry rule abstains unless this Company actually refused something under a rule", async () => {
  const keys = await f.agentKeys();
  const verdict = (log) => grade(log, f.ctx).find(x => x.id === "session.stops-after-refusal");

  // Nothing refused: the agent was never told to stop, so there is nothing to judge.
  const clean = await f.request(keys, { path: "/poppy/orders", sub: "user-one", seq: 1, at: 1 });
  const none = verdict([clean]);
  assert.equal(none.verdict, "INCONCLUSIVE");
  assert.equal(none.cause, "unreached");

  // A refusal of OURS is not the agent being told to stop. The conversation state guard answers
  // 400 invalid_session when this grader could not verify a delegation for its own reasons, and
  // that answer carries no rule, so it must not start this rule's clock: an agent resending after
  // our failure would otherwise be faulted for our problem.
  const ours = await f.request(keys, { path: "/poppy/conversations", method: "POST", seq: 1, at: 1,
                                       conversationRoute: "start", sub: "user-one",
                                       body: JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "x" } }),
                                       response: { status: 400, error: "invalid_session" } });
  const resent = await f.request(keys, { path: "/poppy/conversations", method: "POST", seq: 2, at: 2,
                                         conversationRoute: "start", sub: "user-one",
                                         body: JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "x" } }),
                                         response: { status: 400, error: "invalid_session" } });
  const v = verdict([ours, resent]);
  assert.equal(v.verdict, "INCONCLUSIVE",
    `an agent was faulted for resending after a refusal that was ours: ${v.why}`);
});

test("two different requests to one bodyless path are not a retry of each other", async () => {
  // A FALSE POSITIVE this rule shipped with, found by running the control against the authors own
  // validator an hour after deploying it. Their validator sends many DIFFERENT breaching probes to
  // the same `GET /poppy/orders`, each with its own deliberately broken Session JWT and no body at
  // all. Compared by method, URL and body, those probes are indistinguishable from one another, so
  // the rule called them retries and faulted an agent that had retried nothing.
  //
  // On the wire, "the same request sent again" is not decidable for a request with no body: a
  // conforming retry and a second unrelated probe look alike, because a retry legitimately carries
  // a fresh Session JWT. The protocol supplies the only reliable identity, in 8.3: "To retry a
  // request, the Personal Agent sends it again to the same path with the same ID." So the rule
  // judges requests that carry a request id, and says nothing about the rest.
  const keys = await f.agentKeys();
  const refusedBy = (rule) => ({ rejection: { rule, error: "invalid_session" },
                                 response: { status: 400, error: "invalid_session" } });
  const probe = (seq) => f.request(keys, { path: "/poppy/orders", sub: "user-one", seq, at: seq,
                                           ...refusedBy("session.signature") });
  const v = grade([await probe(1), await probe(2)], f.ctx)
    .find(x => x.id === "session.stops-after-refusal");
  assert.notEqual(v.verdict, "FAIL",
    `two bodyless probes to one path were called a retry: ${v.why}`);

  // And the breach it does fault: the same path with the same request id, refused twice over.
  const body = JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "x" } });
  const post = (seq) => f.request(keys, { method: "POST", path: "/poppy/conversations", seq, at: seq,
                                          conversationRoute: "start", sub: "user-one", body,
                                          ...refusedBy("session.alg") });
  const real = grade([await post(1), await post(2)], f.ctx)
    .find(x => x.id === "session.stops-after-refusal");
  assert.equal(real.verdict, "FAIL",
    `a request resent with the same id after a refusal is the breach: ${real.why}`);
});

// 3.2, sign-in at a Company that has switched it off. Item 3 of the coverage map. This Company
// sets `auth.disabled` and lists `refresh_token` as the only grant, so a non-refresh grant here is
// an agent trying to start a sign-in the Company offers nobody. It already answers
// `unsupported_grant_type` for one while no rule faulted it.
const tokenPost = async (keys, params, over = {}) => f.request(keys, {
  method: "POST", path: "/poppy/token", noSession: true, sub: "user-one",
  body: new URLSearchParams(params).toString(),
  headers: { "content-type": "application/x-www-form-urlencoded" },
  isResource: false, ...over });

test("a sign-in grant at a Company that offers no sign-in is faulted, and a refresh is not", async () => {
  const keys = await f.agentKeys();
  const disabled = { ...f.ctx, authDisabled: true };
  const verdict = async (params) => {
    const rec = await tokenPost(keys, params);
    return grade([rec], disabled).find(x => x.id === "signin.not-when-disabled");
  };
  for (const grant of ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code",
                       "https://personalagentprotocol.org/grant/mediated-sign-in"])
    assert.equal((await verdict({ grant_type: grant, client_id: "x" })).verdict, "FAIL",
      `${grant} is one of the sign-ins 3.2 forbids here`);

  // 3.2 keeps refresh and revocation working: "Refresh tokens the Company issued earlier keep
  // working until it revokes them."
  assert.equal((await verdict({ grant_type: "refresh_token", refresh_token: "t" })).verdict, "PASS",
    "a refresh is explicitly allowed at a Company with sign-in switched off");

  // A revocation carries no grant_type, so it is not a token request to judge.
  const revoke = await tokenPost(keys, { token: "t" }, { path: "/poppy/revoke" });
  assert.equal(grade([revoke], disabled).find(x => x.id === "signin.not-when-disabled").verdict,
               "INCONCLUSIVE", "a revocation is not a sign-in attempt");
});

test("the sign-in rule says nothing unless it knows the Company offers no sign-in", async () => {
  const keys = await f.agentKeys();
  const signIn = await tokenPost(keys, { grant_type: "authorization_code", client_id: "x" });
  const id = "signin.not-when-disabled";

  // A Company that DOES offer sign-in: the sentence does not bind there, so this is not a verdict
  // about the agent at all.
  const offers = grade([signIn], { ...f.ctx, authDisabled: false }).find(x => x.id === id);
  assert.equal(offers.verdict, "INCONCLUSIVE", `an agent was faulted at a Company that offers sign-in: ${offers.why}`);
  assert.equal(offers.cause, "grader");

  // And a log judged without being told either way must not guess. The context is built here
  // rather than borrowed from the fixture, which now says the Company offers no sign-in: a test
  // that relies on a fixture leaving a field out breaks the moment the fixture gains it.
  const untold = grade([signIn], { identifier: f.ctx.identifier, domain: f.ctx.domain })
    .find(x => x.id === id);
  assert.equal(untold.verdict, "INCONCLUSIVE", `this grader guessed: ${untold.why}`);
  assert.equal(untold.cause, "grader");

  // A JSON body that merely contains the words must not be read as a token request.
  const api = await f.request(keys, { method: "POST", path: "/poppy/orders",
                                      body: JSON.stringify({ note: "grant_type=authorization_code" }) });
  assert.equal(grade([api], { ...f.ctx, authDisabled: true }).find(x => x.id === id).verdict,
               "INCONCLUSIVE", "a JSON API body is not a form-encoded token request");

  // The case that actually discriminates, found by a mutation that survived without it: a body
  // that WOULD parse as a form, on a request that is not form encoded. RFC 6749 makes a token
  // request form encoded, so the content type is part of what makes a grant a grant, and a rule
  // that read any body would fault an API call whose text happens to look like one.
  const looksLikeOne = await f.request(keys, { method: "POST", path: "/poppy/orders",
                                               headers: { "content-type": "application/json" },
                                               body: "grant_type=authorization_code&code=x" });
  const v = grade([looksLikeOne], { ...f.ctx, authDisabled: true }).find(x => x.id === id);
  assert.equal(v.verdict, "INCONCLUSIVE",
    `a request that is not form encoded was read as a token request: ${v.why}`);
});

// 5.2, one delegated key per User, WITHIN one Company. Item 4 of the coverage map. The pairwise
// rule compares keys ACROSS the two Companies, so an agent that cached one delegation and signed
// for every User with it passed as long as each Company saw one User. That is the laziest
// implementation there is.
test("one delegated key signing for two Users at one Company is faulted", async () => {
  const keys = await f.agentKeys();
  const id = "delegation.key-per-user";
  const dlgCompact = await f.delegation(keys);          // one delegation, so one delegated key

  // Two Users at this Company, both signed with the same delegated key.
  const shared = [
    await f.request(keys, { dlgCompact, sid: "s1", sub: "user-A", seq: 1, at: 1 }),
    await f.request(keys, { dlgCompact, sid: "s2", sub: "user-B", seq: 2, at: 2 }),
  ];
  const v = grade(shared, f.ctx).find(x => x.id === id);
  assert.equal(v.verdict, "FAIL", `one key signed for two Users and was not faulted: ${v.why}`);

  // The same User over several Sessions with one key is exactly what the sentence allows.
  const oneUser = [
    await f.request(keys, { dlgCompact, sid: "s1", sub: "user-A", seq: 1, at: 1 }),
    await f.request(keys, { dlgCompact, sid: "s2", sub: "user-A", seq: 2, at: 2 }),
  ];
  assert.equal(grade(oneUser, f.ctx).find(x => x.id === id).verdict, "PASS",
    "one key for one User across Sessions is what 5.2 asks for");

  // Two Users, each with its own delegated key, is also right.
  const otherKeys = await f.agentKeys();
  const proper = [
    await f.request(keys, { dlgCompact, sid: "s1", sub: "user-A", seq: 1, at: 1 }),
    await f.request(otherKeys, { dlgCompact: await f.delegation(otherKeys), sid: "s2", sub: "user-B", seq: 2, at: 2 }),
  ];
  assert.equal(grade(proper, f.ctx).find(x => x.id === id).verdict, "PASS",
    "a key per User is the shape the sentence describes");
});

test("the key-per-user rule abstains rather than guessing from what it cannot read", async () => {
  const keys = await f.agentKeys();
  const id = "delegation.key-per-user";
  // One request cannot show a key serving two Users.
  const one = await f.request(keys, { sub: "user-A", seq: 1, at: 1 });
  const v = grade([one], f.ctx).find(x => x.id === id);
  assert.equal(v.verdict, "PASS", `a single request is not a breach: ${v.why}`);

  // A Session JWT with no sub leaves the User unknown, and claims-present is the rule that
  // reports that. This one must not invent a User to compare. The discriminating case, found by a
  // mutation that survived without it, is a shared key where one request names a User and another
  // names none: treating the absence as a User makes that key look like it serves two.
  const dlgCompact = await f.delegation(keys);
  const named = await f.request(keys, { dlgCompact, sid: "s1", sub: "user-A", seq: 1, at: 1 });
  const unnamed = await f.request(keys, { dlgCompact, sid: "s2", claims: { sub: undefined }, seq: 2, at: 2 });
  const v2 = grade([named, unnamed], f.ctx).find(x => x.id === id);
  assert.equal(v2.verdict, "PASS",
    `a request with no sub was counted as a second User of the same key: ${v2.why}`);

  // And an empty log says nothing.
  assert.equal(grade([], f.ctx).find(x => x.id === id).verdict, "INCONCLUSIVE");
});

// 8.4's context fields. Item 5 of the coverage map, the first of three small rules.
test("the context fields are judged by format, and only as far as the runtime can decide", async () => {
  const keys = await f.agentKeys();
  const id = "conversation.context-fields";
  const withContext = async (context) => f.request(keys, {
    method: "POST", path: "/poppy/conversations", conversationRoute: "start", sub: "user-one",
    body: JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "x", context } }) });
  const verdict = async (context) => grade([await withContext(context)], f.ctx).find(x => x.id === id);

  assert.equal((await verdict({ locale: "en-US", time_zone: "America/Los_Angeles", user_available: true })).verdict,
               "PASS", "the shapes 8.4 gives as examples must pass");
  assert.equal((await verdict({ locale: "en" })).verdict, "PASS", "a bare language is a language tag");
  assert.equal((await verdict({ locale: "en_US" })).verdict, "FAIL", "an underscore is not RFC 5646");
  assert.equal((await verdict({ time_zone: "America/LosAngeles" })).verdict, "FAIL", "a typo in a zone name");
  assert.equal((await verdict({ user_available: "yes" })).verdict, "FAIL", "8.4 says true or false, not a string");
  assert.equal((await verdict({ user_available: false })).verdict, "PASS");
  assert.equal((await verdict({ locale: 5 })).verdict, "FAIL", "a number is not a language tag");

  // The limit, stated in the verdict rather than hidden: a legacy abbreviation is not an IANA name,
  // and this runtime accepts it. Deciding that would mean shipping a zone database, and the
  // alternatives are worse: the canonical list this runtime offers omits UTC and Asia/Kolkata, and
  // PST canonicalises exactly like the legitimate alias US/Pacific.
  const abbreviation = await verdict({ time_zone: "PST" });
  assert.equal(abbreviation.verdict, "PASS", "an abbreviation passes, because this cannot tell it from an alias");
  assert.match(abbreviation.why, /abbreviation|cannot tell|as far as/i,
    `the verdict must say what it did not check: ${abbreviation.why}`);

  // Nothing to judge when the facts are not shared, and other members are not this rule's business.
  assert.equal((await verdict({ something_else: 1 })).verdict, "INCONCLUSIVE");
  const noContext = await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                            conversationRoute: "start", sub: "user-one",
                                            body: JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "x" } }) });
  assert.equal(grade([noContext], f.ctx).find(x => x.id === id).verdict, "INCONCLUSIVE");
});
