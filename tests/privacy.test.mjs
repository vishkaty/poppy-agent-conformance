// What the log on disk is allowed to hold.
//
// The recorder is a reverse proxy in front of somebody's real Company, and its log sits on their
// machine for weeks. "Nothing leaves your machine" is true and not sufficient: the file itself was
// a full capture of the traffic, including shopper bodies on every API call. Redaction lived only
// in the report, so the report was careful and the file was not.
//
// The rules read a body in exactly three places: a conversation route of 8.2 (the request id of
// 8.3, the message of 8.4 and 8.8, the context of 8.4), a token request at this Company's own
// authorization server (the `grant_type` 3.2 turns on), and the shape comparison in
// session.jti-unique, which only needs to know whether two bodies differ. The first two are kept.
// Everything else keeps its sha256 over every byte that arrived, and its length, and nothing more.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { recordOf, readBody, bodyIsKept } from "../record.mjs";
import { discoveryFor, templatesOfOpenapi, openapiFor, authServerEndpointsFor, DEFAULT_OPERATIONS } from "../discovery.mjs";
import { CHECKS } from "../checks.mjs";
import * as f from "./fixture.mjs";

const ORIGIN = "https://shop.example";
// The default document describes only GET operations, so a POST with a body would classify as
// "not a destination" and the test would prove nothing about a destination's body.
const OPS = [...DEFAULT_OPERATIONS, { method: "POST", path: "/poppy/orders", summary: "Place one" }];
const CFG = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
              apiOperations: templatesOfOpenapi(openapiFor(ORIGIN, OPS), ORIGIN),
              authServerEndpoints: authServerEndpointsFor(ORIGIN) };

const SECRET = "jane.doe@example.com-4111111111111111";

// Drives the real capture path: recordOf classifies, readBody fills the body in.
function captured(method, target, body, headers = {}) {
  const rec = recordOf({ method, url: target, headers: { host: "shop.example", ...headers } }, CFG, { at: 1 });
  const chunks = [Buffer.from(body, "utf8")];
  const req = { on(ev, fn) { if (ev === "data") chunks.forEach(fn); if (ev === "end") fn(); return req; } };
  readBody(req, rec, 256 * 1024, () => {});
  return rec;
}

test("a shopper body on an ordinary API call is not written to the log", () => {
  const rec = captured("POST", "/poppy/orders", JSON.stringify({ email: SECRET }));
  assert.equal(rec.isResource, true, "the fixture must really be a listed destination");
  assert.ok(!JSON.stringify(rec).includes(SECRET),
    "no rule reads this body, so the log must not hold it");
  // What survives is enough to tell two bodies apart and to say how big it was.
  assert.equal(rec.bodySha256, createHash("sha256").update(JSON.stringify({ email: SECRET })).digest("hex"));
  assert.ok(rec.bodyBytes > 0, "the length is kept");
  assert.equal(rec.bodyKept, false, "and the record says plainly that the text was dropped");
});

test("a conversation body IS kept, because four rules read it", () => {
  const body = JSON.stringify({ id: "r1", message: { author: { type: "human" }, text: SECRET } });
  const rec = captured("POST", "/poppy/conversations", body, { "content-type": "application/json" });
  assert.equal(rec.conversationRoute, "create", "the fixture must really be a conversation route");
  assert.ok(JSON.stringify(rec).includes(SECRET), "8.4 and 8.8 are judged on this body");
  assert.equal(rec.bodyKept, true);
});

test("a token request at this Company's own authorization server IS kept", () => {
  const rec = captured("POST", "/poppy/token", "grant_type=refresh_token&refresh_token=rt",
                       { "content-type": "application/x-www-form-urlencoded" });
  assert.equal(rec.isAuthServer, true);
  assert.equal(rec.bodyKept, true, "3.2 is judged on the grant in this body");
});

test("the policy is one function, so a rule and the capture cannot disagree about it", () => {
  // If a rule starts reading a body the capture drops, the rule silently abstains forever. The
  // policy is therefore stated once and asserted against the places the rules actually read.
  assert.equal(bodyIsKept({ conversationRoute: "create" }), true);
  assert.equal(bodyIsKept({ isAuthServer: true }), true);
  assert.equal(bodyIsKept({ isResource: true }), false);
  assert.equal(bodyIsKept({}), false);
});

test("session.jti-unique still tells two bodies apart when neither body was kept", async () => {
  // It compared the body TEXT, so dropping the text would have made every unkept body look
  // identical and masked a real replay. It compares the hash over every byte that arrived now,
  // which also fixes a second defect: two bodies identical in their first 256 KB used to look
  // like one request even when the rest differed.
  const keys = await f.agentKeys();
  const rule = CHECKS.find(c => c.id === "session.jti-unique");
  const mk = async (bodyText) => f.request(keys, {
    method: "POST", path: "/poppy/orders", jti: "j1", sub: "user-one",
    body: "", bodyKept: false, bodySha256: createHash("sha256").update(bodyText).digest("hex"),
    seq: bodyText.length });
  const differing = [await mk("one"), await mk("two-different")];
  assert.equal(rule.run(differing, f.ctx).verdict, "FAIL",
    "one jti signed two different requests, which is a replay");
  const same = [await mk("same"), { ...(await mk("same")), seq: 99 }];
  assert.notEqual(rule.run(same, f.ctx).verdict, "FAIL",
    "an identical resend is for the Company to reject, not a replay");
});
