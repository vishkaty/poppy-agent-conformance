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
import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { randomUUID } from "node:crypto";
import { CHECKS, PAIRWISE, grade, gradePair } from "../checks.mjs";
import * as f from "./fixture.mjs";

// Two genuinely different Companies, which is what makes a pairwise verdict meaningful.
const CTX_A = { identifier: "https://shop.example/poppy", domain: "shop.example" };
const CTX_B = { identifier: "https://other-shop.example/poppy", domain: "other-shop.example" };

const keys = await f.agentKeys();
const conforming = await f.conformingLog(keys);

// One breach per check. Each returns a log that must fail exactly that check.
const BREACH = {
  "session.header-sent":        async () => [await f.request(keys, { noSession: true })],
  "session.typ":                async () => [await f.request(keys, { sesTyp: "JWT" })],
  "session.alg": async () => {
    // Signed with RS256, which 5.2 forbids: "alg MUST be ES256". Built with a real RSA key
    // rather than by editing the header, so the JWT is one an agent could actually send.
    const rsa = await generateKeyPair("RS256", { extractable: true });
    const dlg = await f.delegation(keys);
    const jwt = await new SignJWT({
      iss: f.CLIENT_ID, aud: f.IDENTIFIER, sid: "s", sub: "u",
      htm: "GET", htu: "https://shop.example/poppy/orders",
      iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
    }).setProtectedHeader({ alg: "RS256", typ: "poppy-session+jwt", poppy_dlg: dlg })
      .sign(rsa.privateKey);
    const r = await f.request(keys, {});
    r.headers["poppy-session"] = jwt;
    return [r];
  },
  "session.aud":                async () => [await f.request(keys, { aud: "https://elsewhere.example/poppy" })],
  "session.htm-htu":            async () => [await f.request(keys, { htu: "https://shop.example/poppy/elsewhere" })],
  "session.iat-window":         async () => [await f.request(keys, { iat: Math.floor(Date.now() / 1000) - 600 })],
  "session.claims-present":     async () => [await f.request(keys, { drop: ["jti"] })],
  "session.sub-stable": async () => {
    const sid = "sid-fixed", dlgCompact = await f.delegation(keys);
    return [await f.request(keys, { sid, sub: "user-a", dlgCompact }),
            await f.request(keys, { sid, sub: "user-b", dlgCompact })];
  },
  "session.jti-unique": async () => {
    // One jti signing two DIFFERENT requests, which cannot be a retry. An identical resend
    // is deliberately not a FAIL: 5.3 leaves rejecting a reused jti to the Company.
    const jti = "reused-" + randomUUID();
    return [await f.request(keys, { jti, path: "/poppy/orders" }),
            await f.request(keys, { jti, path: "/poppy/orders/2" })];
  },
  "delegation.typ":             async () => [await f.request(keys, { dlg: { typ: "JWT" } })],
  "delegation.exp-24h": async () => {
    const iat = Math.floor(Date.now() / 1000);
    return [await f.request(keys, { dlg: { iat, exp: iat + 86400 + 60 } })];
  },
  "delegation.no-identifiers": async () => {
    // the delegation naming the User ID, which 5.2 forbids outright
    const sub = "user-leaked-" + randomUUID();
    const dlgCompact = await f.delegation(keys, { payload: { note: sub } });
    return [await f.request(keys, { sub, dlgCompact })];
  },
  "version.constant":           async () => [await f.request(keys, { version: null })],
  "session.signature": async () => {
    const r = await f.request(keys, {});
    const parts = r.headers["poppy-session"].split(".");
    parts[2] = "A".repeat(parts[2].length);        // the signature destroyed
    r.headers["poppy-session"] = parts.join(".");
    return [r];
  },
  "delegation.no-private-key": async () => {
    const priv = await exportJWK(keys.delegated.privateKey);   // carries `d`
    return [await f.request(keys, { dlgCompact: await f.delegation(keys, { payload: { cnf: { jwk: priv } } }) })];
  },
  "delegation.not-expired": async () => {
    const now = Math.floor(Date.now() / 1000);
    return [await f.request(keys, { dlgCompact: await f.delegation(keys, { iat: now - 7200, exp: now - 3600 }), at: now, iat: now })];
  },
  "delegation.iss-matches": async () =>
    [await f.request(keys, { dlgCompact: await f.delegation(keys, { payload: { iss: "https://other.example/agent.json" } }) })],
  "session.ath": async () => [await f.request(keys, { token: "tok-x", ath: "not-the-hash" })],
  "delegation.present": async () => [await f.request(keys, { noDlg: true })],
  "delegation.alg": async () => {
    const rsa = await generateKeyPair("RS256", { extractable: true });
    const now = Math.floor(Date.now() / 1000);
    const dlg = await new SignJWT({ iss: f.CLIENT_ID, iat: now, exp: now + 3600,
      jti: randomUUID(), cnf: { jwk: keys.jwk } })
      .setProtectedHeader({ alg: "RS256", typ: "poppy-delegation+jwt" }).sign(rsa.privateKey);
    return [await f.request(keys, { dlgCompact: dlg })];
  },
  "session.not-on-documents": async () => {
    // The agent sending its Session JWT to poppy.json, which 5.2 forbids outright.
    const r = await f.request(keys, { path: "/.well-known/poppy.json" });
    r.isResource = false; r.mustNotCarry = true;
    r.classifiedAs = "a discovery or description document, or an OAuth endpoint (5.2)";
    r.sessionHeaderCount = 1;
    return [r];
  },
  "session.header-single": async () => {
    // What the recorder produces for two Poppy-Session headers: the value removed, because
    // a joined pair is not a JWT, and the duplication flagged so the right rule fails.
    const r = await f.request(keys, {});
    delete r.headers["poppy-session"];
    r.sessionHeaderDuplicated = true;
    return [r];
  },
};

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
