// A conforming agent must never be told it is broken.
//
// Every case here is traffic that published 1.0 permits, which an earlier version of
// checks.mjs reported as FAIL. They are regression tests for the worst thing a grader can
// do: this project's record is that two of the four defects it once found in its own agent
// runner were its own rules failing an agent that followed the document, and a builder who
// receives a wrong FAIL has no way to argue.
//
// Each test names the 1.0 sentence that makes the traffic legitimate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { grade, gradePair } from "../checks.mjs";
import * as f from "./fixture.mjs";

const keys = await f.agentKeys();
const only = (log, id, ctx = f.ctx) => grade(log, ctx).find(x => x.id === id);

test("a one-character User ID is not a privacy breach", async () => {
  // 5.1 requires a User ID to be "stable" and "opaque" and sets no minimum length, so "7"
  // conforms. The old substring search over the whole delegation payload matched it inside
  // the random base64url of cnf.jwk, and failed 40 of 40 runs with fresh keys.
  let failed = 0;
  for (let i = 0; i < 30; i++) {
    const k = await f.agentKeys();
    const r = await f.request(k, { sub: "7" });
    if (only([r], "delegation.no-identifiers", f.ctx).verdict === "FAIL") failed++;
  }
  assert.equal(failed, 0, `a conforming one-character User ID was accused ${failed}/30 times`);
});

test("the delegation's own iss is required, not a leak", async () => {
  // 5.2, Delegated keys: "`iss` is the Personal Agent's `client_id`." The old check searched
  // the whole payload, so an agent_id that appeared inside its own client_id URL was
  // reported as a leak of the Agent ID.
  const r = await f.request(keys, { agent_id: "agent", sub: "user-" + randomUUID() });
  const v = only([r], "delegation.no-identifiers");
  assert.notEqual(v.verdict, "FAIL",
    `agent_id "agent" inside client_id ${f.CLIENT_ID} was reported as a leak: ${v.why}`);
});

test("a Company domain that is a substring of the agent's host is not a leak", async () => {
  // Company domain `example`, agent at https://agent.example/agent.json. The delegation
  // must carry that client_id, so a substring search accuses every such pair.
  const r = await f.request(keys, {});
  const v = only([r], "delegation.no-identifiers", { identifier: "https://example/poppy", domain: "example" });
  assert.notEqual(v.verdict, "FAIL", `a substring domain match was reported as a leak: ${v.why}`);
});

test("two parallel Sessions may declare different protocol versions", async () => {
  // 3.4 binds the version to a Session: "The Personal Agent MUST send the same values on
  // every request in a Session, and starts a new Session to change them." Section 5 permits
  // "several Sessions for the same User, for example for tasks running in parallel", and 3.4
  // recovery has the agent choose another version and start a new Session.
  const a = await f.request(keys, { sid: "sid-a", version: "1.0" });
  const b = await f.request(keys, { sid: "sid-b", version: "1.1" });
  const v = only([a, b], "version.constant");
  assert.notEqual(v.verdict, "FAIL",
    `two Sessions on different versions were reported as a change within one: ${v.why}`);
});

test("htu with an explicit default port is the same URI", async () => {
  // 5.3 points at RFC 9449 §4.3, which applies RFC 3986 normalization before comparing.
  // §6.2.3 makes https://host:443/p and https://host/p equivalent.
  const r = await f.request(keys, { htu: "https://shop.example:443/poppy/orders", path: "/poppy/orders" });
  const v = only([r], "session.htm-htu");
  assert.notEqual(v.verdict, "FAIL", `an explicit :443 was reported as a mismatch: ${v.why}`);
});

test("htu with an uppercase host is the same URI", async () => {
  // RFC 3986 §6.2.2.1: the host is case-insensitive.
  const r = await f.request(keys, { htu: "https://SHOP.example/poppy/orders", path: "/poppy/orders" });
  const v = only([r], "session.htm-htu");
  assert.notEqual(v.verdict, "FAIL", `an uppercase host was reported as a mismatch: ${v.why}`);
});

test("two Companies sharing one issuer are one Company, so a shared User ID is required", async () => {
  // 3.2: "Several domains MAY have the same issuer, such as a Company with a domain for each
  // country, and they are then one Company: the same User IDs (5.1), Sessions, and refresh
  // tokens apply to all of them." Accusing an agent here would invert the rule.
  const sub = "user-shared", dlgCompact = await f.delegation(keys);
  const a = [await f.request(keys, { sub, dlgCompact })];
  const b = [await f.request(keys, { sub, dlgCompact })];
  const same = { identifier: f.IDENTIFIER, domain: f.DOMAIN };
  for (const v of gradePair(a, b, same, same))
    assert.equal(v.verdict, "INCONCLUSIVE",
      `${v.id} judged two Companies that share an identifier: ${v.why}`);
});

test("an identical resend is not reported as a replay", async () => {
  // 8.3 makes a retry of the identical request a safe, intended operation, and 5.3 leaves
  // rejecting a reused jti to the Company ("A Company MAY reject a reused jti"). A builder
  // whose client retries on a connection reset must not be told they forged a signature.
  const jti = "resent-" + randomUUID();
  const a = await f.request(keys, { jti, path: "/poppy/orders" });
  const b = { ...a };                       // the same request again, byte for byte
  const v = only([a, b], "session.jti-unique");
  assert.notEqual(v.verdict, "FAIL", `an identical resend was called a replay: ${v.why}`);
});

test("an upload that was reset and then retried identically is not a replay", async () => {
  // 8.3 makes retrying the identical request a safe, intended operation, and server.mjs
  // records a request whose socket was reset with the bytes it managed to read and
  // `bodyComplete: false`. Comparing that partial body against the complete one made the
  // two look like different requests signed by one jti, which is exactly the definition
  // this check uses for a replay. A conforming agent on a flaky network got a FAIL.
  const jti = randomUUID();
  const aborted = await f.request(keys, { method: "POST", path: "/poppy/conversations", jti, body: '{"mes' });
  aborted.bodyComplete = false;
  const retried = await f.request(keys, { method: "POST", path: "/poppy/conversations", jti,
                                          body: '{"message":{"content":[]}}' });
  const v = only([aborted, retried], "session.jti-unique");
  // Not a FAIL is the point. It abstains rather than passing, because excluding the
  // incomplete request leaves one request to compare and one request cannot show reuse:
  // a pass there would be a claim about nothing.
  assert.notEqual(v.verdict, "FAIL", `${v.verdict}: ${v.why}`);
  assert.match(v.why, /never fully received/i,
    "the verdict must say why a request was left out, or the abstention is unexplained");
});

test("a replay onto a genuinely different request is still a FAIL when one body is incomplete", async () => {
  // The control for the test above. Excusing every incomplete record would turn a real
  // replay into a pass, which is the trade this project refuses: an exclusion must be
  // narrow enough that the breach it was built for still fails.
  const jti = randomUUID();
  const aborted = await f.request(keys, { method: "POST", path: "/poppy/conversations", jti, body: '{"a' });
  aborted.bodyComplete = false;
  const other = await f.request(keys, { method: "GET", path: "/poppy/orders", jti });
  const elsewhere = await f.request(keys, { method: "GET", path: "/poppy/invoices", jti });
  const v = only([aborted, other, elsewhere], "session.jti-unique");
  assert.equal(v.verdict, "FAIL", `${v.verdict}: ${v.why}`);
});

test("htu that differs only in percent encoding is not a mismatch", async () => {
  // 5.3 step 2: "htm and htu match the request as RFC 9449 §4.3 describes for DPoP proofs".
  // RFC 9449 §4.3 says the server SHOULD apply syntax-based normalization before comparing,
  // which is RFC 3986 §6.2.2: percent-encoded octets of unreserved characters are decoded,
  // and the hex digits of the rest are compared case-insensitively. An agent whose library
  // writes `~` where a proxy writes `%7E`, or lowercase hex where ours is uppercase, was
  // failed for a difference the referenced RFC says is none.
  const cases = [
    ["%7E decoded to ~", "/poppy/orders/%7Eid", "https://shop.example/poppy/orders/~id"],
    ["~ left as ~", "/poppy/orders/~id", "https://shop.example/poppy/orders/%7Eid"],
    ["hex case", "/poppy/orders/%2Fx", "https://shop.example/poppy/orders/%2fx"],
    ["unreserved alpha", "/poppy/orders/%41", "https://shop.example/poppy/orders/A"],
  ];
  for (const [what, path, htu] of cases) {
    const v = only([await f.request(keys, { path, htu })], "session.htm-htu");
    assert.equal(v.verdict, "PASS", `${what}: ${v.verdict} ${v.why}`);
  }
  // and the control: a genuinely different path still fails
  const bad = only([await f.request(keys, { path: "/poppy/orders", htu: "https://shop.example/poppy/elsewhere" })],
                   "session.htm-htu");
  assert.equal(bad.verdict, "FAIL", "a real htu mismatch stopped failing");
});

test("a typ naming the same media type the long way is not a failure", async () => {
  // 5.2: "`typ` MUST be `poppy-session+jwt`... (RFC 8725 §3.11)". RFC 8725 builds on RFC 7515
  // §4.1.9, where a `typ` with no slash is treated as though `application/` were prepended and
  // media type names are case-insensitive, so `application/poppy-session+jwt` names exactly
  // the same type. Failing it would be failing an agent over a spelling. The pass says the
  // spelling differed, because a stricter Company may compare the literal.
  for (const spelling of ["application/poppy-session+jwt", "POPPY-SESSION+JWT"]) {
    const v = only([await f.request(keys, { sesTyp: spelling })], "session.typ");
    assert.equal(v.verdict, "PASS", `${spelling}: ${v.verdict} ${v.why}`);
    assert.match(v.why, /spelling|literal|exactly/i, `${spelling}: the pass does not mention the spelling`);
  }
  for (const spelling of ["application/poppy-delegation+jwt", "POPPY-DELEGATION+JWT"]) {
    const v = only([await f.request(keys, { dlg: { typ: spelling } })], "delegation.typ");
    assert.equal(v.verdict, "PASS", `${spelling}: ${v.verdict} ${v.why}`);
  }
  // controls: a genuinely different type still fails on both
  assert.equal(only([await f.request(keys, { sesTyp: "JWT" })], "session.typ").verdict, "FAIL");
  assert.equal(only([await f.request(keys, { dlg: { typ: "JWT" } })], "delegation.typ").verdict, "FAIL");
});
