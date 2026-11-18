// What this Company REFUSES, as opposed to what it reports.
//
// 5.3: "A failed Session check returns HTTP 400 with {"error": "invalid_session"}... Session
// errors use 400 rather than 401 so that OAuth libraries, which treat a 401 as a problem with
// the access token, don't discard a valid token."
//
// A wrong FAIL in a report is this instrument's most expensive output. A wrong REJECTION is
// worse: the agent cannot proceed at all and will conclude the Company is broken. So the
// enforced set is the same check implementations the report uses, filtered to an explicit
// list, and the first four tests here exist only to prove that nothing conforming is refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS, grade } from "../checks.mjs";
import { enforce, ENFORCED, ENFORCE_EXCLUDED, tokenChallenge } from "../enforce.mjs";
import { BREACH, keys, conforming } from "./breaches.mjs";
import * as f from "./fixture.mjs";

const ref = await import("../reference/jose.ts");
const CLIENT = "https://agent.example/agent.json";

test("no request of a conforming agent is refused", async () => {
  // The fixture's conforming log, request by request, because enforcement decides per request.
  const refused = conforming
    .filter(r => r.isResource)
    .map(r => ({ r, d: enforce(r, f.ctx) }))
    .filter(x => x.d)
    .map(x => `${x.r.method} ${x.r.path}: ${x.d.rule} ${x.d.body.error}`);
  assert.deepEqual(refused, [], refused.join("\n"));
});

test("no traffic built by the authors own signing code is refused", async () => {
  // The control that matters most. If this Company refuses traffic minted by the people who
  // wrote the specification, this Company is wrong and not the traffic.
  const ctx = { identifier: "https://shop.example/poppy", domain: "shop.example" };
  const operator = await ref.generateKey();
  const key = await ref.generateKey();
  const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk, iss: CLIENT });
  const sid = ref.randomId(16), sub = ref.randomId(16);
  const refused = [];
  for (const path of ["/poppy/orders", "/poppy/orders/1", "/poppy/conversations"]) {
    const url = `https://shop.example${path}`;
    const method = path.endsWith("conversations") ? "POST" : "GET";
    const jwt = await ref.signSessionJwt({ key, delegation, iss: CLIENT, aud: ctx.identifier,
                                           sid, sub, method, url });
    const r = { host: "shop.example", method, path, url, at: ref.nowSeconds(),
                isResource: true, isPage: false, mustNotCarry: false, bodyComplete: true,
                sessionHeaderCount: 1, sessionHeaderDecodable: true, sessionHeaderDuplicated: false,
                headers: { "poppy-session": jwt, "poppy-version": "1.0" }, body: "" };
    const d = enforce(r, ctx);
    if (d) refused.push(`${method} ${path}: ${d.rule} ${d.body.error} ${d.body.error_description ?? ""}`);
  }
  assert.deepEqual(refused, [], refused.join("\n"));
});

test("no traffic this project once wrongly failed is refused", async () => {
  // Every case in false-fails.test.mjs is traffic 1.0 permits that an earlier version of these
  // checks reported as FAIL. Under enforcement each would have been a closed door.
  const permitted = [
    await f.request(keys, { sub: "7" }),                                        // a one character User ID
    await f.request(keys, { path: "/poppy/orders/%7Eid", htu: "https://shop.example/poppy/orders/~id" }),
    await f.request(keys, { sesTyp: "application/poppy-session+jwt" }),
    await f.request(keys, { dlg: { typ: "application/poppy-delegation+jwt" } }),
    await f.request(keys, { version: "1.7" }),                                  // a later minor version
  ];
  const refused = permitted.map(r => ({ r, d: enforce(r, f.ctx) })).filter(x => x.d)
    .map(x => `${x.r.path}: ${x.d.rule} ${x.d.body.error_description ?? x.d.body.error}`);
  assert.deepEqual(refused, [], refused.join("\n"));
});

test("a request that is not a destination is never refused", async () => {
  // 5.2: documents and OAuth endpoints do not carry the header, and 5.3 lets an endpoint that
  // uses no Session claims handle a request without verifying one. Refusing a document would
  // break discovery for every agent.
  const doc = { ...await f.request(keys, { sesTyp: "JWT" }), isResource: false, mustNotCarry: true };
  const page = { ...await f.request(keys, { sesTyp: "JWT" }), isResource: false, isPage: true };
  const nothing = { ...await f.request(keys, { sesTyp: "JWT" }), isResource: false };
  for (const [what, r] of [["a document", doc], ["a website page", page], ["not a destination", nothing]])
    assert.equal(enforce(r, f.ctx), null, `${what} was refused`);
});

test("every enforced breach is refused with the error 1.0 names for it", async () => {
  // A breach can legitimately trip an earlier rule: a JWT signed RS256 fails both
  // session.alg and session.signature. So the contract is not "names its own rule" but
  // "names the FIRST enforced rule that actually fails on this request", which is the
  // precedence contract itself, and the description must be that rule's own sentence.
  const wanted = { "version.sent": ["version_unsupported", 400] };
  for (const id of ENFORCED) {
    const log = await BREACH[id]();
    const last = log[log.length - 1];
    const d = enforce(last, f.ctx);
    assert.ok(d, `${id}: its own breach was not refused`);

    const failing = grade([last], f.ctx).filter(v => v.verdict === "FAIL").map(v => v.id);
    assert.ok(failing.includes(id), `${id}: its own breach does not fail it on one request`);
    const first = ENFORCED.find(x => failing.includes(x));
    assert.equal(d.rule, first,
      `${id}: refused naming ${d.rule} while the first failing enforced rule is ${first} (failing: ${failing.join(", ")})`);

    const [error, status] = wanted[d.rule] ?? ["invalid_session", 400];
    assert.equal(d.body.error, error, `${id}: refused with ${d.body.error}`);
    assert.equal(d.status, status, `${id}: answered ${d.status}`);
    assert.match(d.body.error_description ?? "", new RegExp(d.rule.replace(".", "\\.")),
      `${id}: the description does not name the rule it refused on`);
  }
});

test("a refusal never contains a JWT, a signature or a token", async () => {
  // The description is the report's own `why`, and the report is redacted for a reason.
  const log = await BREACH["session.signature"]();
  const d = enforce(log[0], f.ctx);
  assert.ok(d);
  const text = JSON.stringify(d);
  assert.ok(!/eyJ[A-Za-z0-9_-]{10,}/.test(text), `a compact JWT reached the refusal: ${text}`);
  for (const part of String(log[0].headers["poppy-session"]).split("."))
    if (part.length > 12) assert.ok(!text.includes(part), "a JWT part reached the refusal");
});

test("session_ended is never emitted, because this Company ends no Session", async () => {
  // Section 7 gives invalid_session and session_ended OPPOSITE instructions: invalid_session
  // says "A new Session doesn't fix it: the Personal Agent stops sending the request until it
  // fixes the cause", session_ended says "starts a new Session and sends the request again,
  // once". Emitting the wrong one sends a conforming agent into a loop.
  const seen = new Set();
  for (const id of ENFORCED) {
    const log = await BREACH[id]();
    const d = enforce(log[log.length - 1], f.ctx);
    if (d) seen.add(d.body.error);
  }
  assert.ok(!seen.has("session_ended"), "a verification failure was reported as an ended Session");
  assert.deepEqual([...seen].sort(), ["invalid_session", "version_unsupported"]);
});

test("precedence follows the order 5.3 verifies in, so the agent is told the right thing to fix", async () => {
  // A request whose Session fails AND whose version is missing must be told invalid_session,
  // not version_unsupported: 3.4's recovery is to refetch poppy.json and start a new Session,
  // which would not fix a bad delegation and would loop.
  const r = await f.request(keys, { noDlg: true, version: null });
  const d = enforce(r, f.ctx);
  assert.equal(d.body.error, "invalid_session", `told to ${d.body.error}`);
  assert.equal(d.rule, "delegation.present", `named ${d.rule}`);
});

test("every check is enforced or excluded with a reason", () => {
  const ids = CHECKS.map(c => c.id);
  for (const id of ENFORCED) assert.ok(ids.includes(id), `ENFORCED names a check that does not exist: ${id}`);
  for (const id of Object.keys(ENFORCE_EXCLUDED)) assert.ok(ids.includes(id), `ENFORCE_EXCLUDED names a check that does not exist: ${id}`);
  for (const id of ids)
    assert.ok(ENFORCED.includes(id) || ENFORCE_EXCLUDED[id],
      `${id} is neither enforced nor excluded with a reason`);
  for (const [id, why] of Object.entries(ENFORCE_EXCLUDED))
    assert.ok(String(why).length > 40, `the reason given for not enforcing ${id} says nothing`);
  assert.deepEqual([...new Set(ENFORCED)], ENFORCED, "a rule is enforced twice");
});

test("an access token this Company never issued is an OAuth error, not a Session error", async () => {
  // Section 7: invalid_token is 401 and lives in WWW-Authenticate. 4.5: "A service that gets a
  // token not issued for it returns invalid_token with resource_metadata in its challenge".
  // This Company issues no token at all, so every Authorization header is such a token.
  const c = tokenChallenge("https://shop.example");
  assert.equal(c.status, 401);
  assert.match(c.headers["www-authenticate"], /^Bearer /);
  assert.match(c.headers["www-authenticate"], /error="invalid_token"/);
  assert.match(c.headers["www-authenticate"], /resource_metadata="https:\/\/shop\.example\/\.well-known\/oauth-protected-resource"/);
  assert.equal(c.body.error, "invalid_token");
});
