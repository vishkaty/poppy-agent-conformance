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

test("an access token sent in Authorization is not written to the log, and ath is still judged", async () => {
  // The rules that read Authorization need presence, the scheme, and sha256 of the token: that is
  // exactly what 5.2's `ath` is. The log kept the raw bearer token, which is a credential sitting
  // on a shop's disk for weeks. Capture now stores { scheme, sha256, length } beside the headers
  // and removes the value; session.ath compares the hash it already computes against the stored
  // one, so a wrong ath still fails and a right one still passes.
  const token = "tok-" + createHash("sha256").update("secret").digest("base64url").slice(0, 20);
  const rec = captured("GET", "/poppy/orders", "", { authorization: `DPoP ${token}` });
  assert.ok(!JSON.stringify(rec).includes(token), "the token value must not be in the record");
  assert.equal(rec.authorization?.scheme, "DPoP");
  assert.equal(rec.authorization?.sha256, createHash("sha256").update(token).digest("base64url"));
  assert.equal(rec.headers.authorization, "DPoP [sha256]", "the header keeps its presence and scheme, not its secret");

  const keys = await f.agentKeys();
  const rule = CHECKS.find(c => c.id === "session.ath");
  const right = await f.request(keys, { token, ath: createHash("sha256").update(token).digest("base64url") });
  const wrong = await f.request(keys, { token, ath: "not-the-hash" });
  assert.equal(rule.run([right], f.ctx).verdict, "PASS", "a correct ath still passes from the stored hash");
  assert.equal(rule.run([wrong], f.ctx).verdict, "FAIL", "a wrong ath still fails");
  assert.ok(!JSON.stringify(right).includes(token), "and the fixture carries no raw token either");
});

test("the source tag is salted from the log header, so it is unguessable and still deterministic", async () => {
  // In a recorded run the salt was the empty string, so the tag was sha256 of the address and the
  // eight hex characters inverted over the whole IPv4 space by table lookup: a shopper address was
  // recoverable from any report the operator forwarded. The salt is random per log FILE and lives
  // in the header, which keeps judge a pure function of the file: the same log judges to the same
  // tags every time, and two different logs give different tags for the same address.
  const { judge, openRunFile, appendRecord, readRun } = await import("../recorder.mjs");
  const { mkdtempSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const keys = await f.agentKeys();
  const discovery = { protocol_version: "1.0", organization: { domain: "shop.example" },
                      auth: { issuer: "https://shop.example/poppy", disabled: true } };
  const ADDRESS = "203.0.113.77";

  const write = () => {
    const dir = mkdtempSync(join(tmpdir(), "poppy-salt-"));
    const path = join(dir, "run.jsonl");
    const file = openRunFile(path, { origin: "https://shop.example", discovery });
    return { path, file };
  };
  const one = write(), two = write();
  for (const { file } of [one, two])
    appendRecord(file, { ...(await f.request(keys, { sub: "u", seq: 1 })), remoteAddress: ADDRESS });

  const header = JSON.parse(readFileSync(one.path, "utf8").split("\n")[0]);
  assert.match(String(header.addressSalt ?? ""), /^[0-9a-f]{32,}$/, "the header carries a random salt");

  const tagOf = (p) => judge([readRun(p)], { graderCommit: "t" }).report.requests[0].source;
  assert.notEqual(tagOf(one.path), createHash("sha256").update(ADDRESS).digest("hex").slice(0, 8),
    "the tag must not be the bare hash of the address");
  assert.equal(tagOf(one.path), tagOf(one.path), "the same file judges to the same tag every time");
  assert.notEqual(tagOf(one.path), tagOf(two.path), "two logs give different tags for one address");
});
