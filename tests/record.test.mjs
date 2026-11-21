// The recorder decides which rules apply, so a mistake here makes every verdict wrong in a
// way no check can notice.
//
// The fixture is deliberately HOSTILE: the OpenAPI document sits at the origin root, as the
// specification's own example does, so every forbidden document shares a prefix with a
// declared destination. An earlier fixture put the API under /poppy/api/, which happened
// not to overlap anything, and all eleven tests passed while classify() marked
// poppy.json, the OpenAPI document, the token endpoint, the OAuth metadata and the browser
// session page as Session destinations. The tests proved the fixture's geometry, not the
// rule. Measured, all five.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, publicUrl, sessionHeaderOf, recordOf } from "../record.mjs";

// Overlapping on purpose, and close to the layout in section 3's own example.
const DISCOVERY = {
  protocol_version: "1.0",
  organization: { name: "Shop", domain: "shop.example" },
  auth: { issuer: "https://shop.example/poppy" },
  supported_versions: { "0.4": "https://shop.example/poppy/0.4.json" },
  agent: { protocols: [
    { type: "poppy", endpoint: "https://shop.example/poppy/conversations", description: "d" },
    // A non-poppy entry. The UCP extension says its endpoint is a PROFILE document and its
    // requests "follow UCP's Ask bindings and section 4 of this page, not spec 8.2-8.13",
    // so it is not an 8.2 route base and the profile itself carries no header.
    { type: "ucp", endpoint: "https://shop.example/.well-known/ucp", description: "d" },
  ] },
  apis: [
    { type: "openapi", url: "https://shop.example/openapi.json", description: "d" },
    { type: "mcp", url: "https://shop.example/poppy/mcp", description: "d" },
  ],
  web: { browser_session_endpoint: "https://shop.example/poppy/browser-session" },
  tasks: { endpoint: "https://shop.example/poppy/tasks" },
};
const CFG = {
  origin: "https://shop.example",
  discovery: DISCOVERY,
  // The operations the listed OpenAPI describes, compiled at startup from its servers and
  // paths. Templates, not a prefix: a prefix cannot express "the request URLs its listed
  // APIs describe" and marks the document beside them.
  apiOperations: [
    { method: "GET", template: "/v1/orders" },
    { method: "GET", template: "/v1/orders/{id}" },
    { method: "POST", template: "/v1/orders" },
  ],
  authServerEndpoints: [
    "https://shop.example/poppy/token",
    "https://shop.example/poppy/authorize",
    "https://shop.example/poppy/revoke",
  ],
};
const R = (u, m = "GET") => classify(u, m, CFG);
const S = u => "https://shop.example" + u;

test("the six routes of 8.2 carry the header, with their own methods", () => {
  for (const [m, u] of [["POST", "/poppy/conversations"],
                        ["POST", "/poppy/conversations/c_1/messages"],
                        ["GET",  "/poppy/conversations/c_1/events"],
                        ["POST", "/poppy/conversations/c_1/handoff"],
                        ["POST", "/poppy/conversations/c_1/handoff/cancel"],
                        ["POST", "/poppy/conversations/c_1/close"]])
    assert.equal(R(S(u), m).isResource, true, `${m} ${u}`);
});

test("a path under the conversation endpoint that 8.2 does not define is not a route", () => {
  // 1.0 lists six routes and no bare GET {endpoint}/{id}. Accepting anything under the
  // endpoint invents destinations the specification does not define.
  assert.equal(R(S("/poppy/conversations/c_1")).isResource, false);
  assert.equal(R(S("/poppy/conversations/c_1/anything"), "POST").isResource, false);
});

test("an operation a listed OpenAPI describes carries it; the document beside it does not", () => {
  assert.equal(R(S("/v1/orders")).isResource, true);
  assert.equal(R(S("/v1/orders/o_9")).isResource, true, "a templated id segment");
  assert.equal(R(S("/openapi.json")).isResource, false, "5.2 excludes description documents");
});

test("an operation is a method and a path, not a path alone", () => {
  assert.equal(R(S("/v1/orders"), "DELETE").isResource, false, "DELETE /v1/orders is not described");
});

test("an mcp url is the endpoint itself, and nothing beneath it", () => {
  assert.equal(R(S("/poppy/mcp"), "POST").isResource, true);
  assert.equal(R(S("/poppy/mcp/anything"), "POST").isResource, false);
});

test("browser authorization carries it; the page the browser loads does not", () => {
  assert.equal(R(S("/poppy/browser-session/authorize"), "POST").isResource, true);
  assert.equal(R(S("/poppy/browser-session")).isResource, false);
});

test("tasks is one request, and artifacts under it are documents", () => {
  // Section 9 defines GET {tasks.endpoint}. 9.4 resolves skill URLs against it, and the
  // guides say to fetch public documents without the header, so a skill under that path
  // must not be a destination.
  assert.equal(R(S("/poppy/tasks")).isResource, true);
  assert.equal(R(S("/poppy/tasks/skills/manage-bookings/SKILL.md")).isResource, false);
});

test("every document 5.2 forbids is recorded as such, even sharing a prefix with a destination", () => {
  // The whole point of the hostile fixture. 5.2: "Discovery and description documents and
  // OAuth endpoints don't carry this header."
  for (const u of ["/.well-known/poppy.json", "/openapi.json", "/.well-known/ucp",
                   "/poppy/0.4.json", "/poppy/token", "/poppy/authorize", "/poppy/revoke",
                   "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource"]) {
    const v = R(S(u));
    assert.equal(v.isResource, false, `${u} was marked a destination`);
    assert.equal(v.mustNotCarry, true, `${u} was not recorded as a document that must not carry the header`);
    assert.equal(v.isPage, false, `${u} was recorded as a website page, which 5.2 carves out`);
  }
});

test("a non-poppy protocol entry is not an 8.2 route base", () => {
  const v = R(S("/.well-known/ucp"));
  assert.equal(v.isResource, false);
  assert.equal(v.mustNotCarry, true);
});

test("sharing a hostname does not make a URL a destination", () => {
  for (const u of ["/anything", "/poppy/not-listed", "/poppy/conversationsX", "/v1/ordersX"])
    assert.equal(R(S(u)).isResource, false, u);
});

test("a segment boundary is respected", () => {
  // /poppy/api-docs must not match a destination whose path is /poppy/api.
  const cfg = { ...CFG, apiOperations: [{ method: "GET", template: "/poppy/api" }] };
  assert.equal(classify(S("/poppy/api-docs"), "GET", cfg).isResource, false);
  assert.equal(classify(S("/poppy/api"), "GET", cfg).isResource, true);
});

test("a destination configured on another origin never matches our paths", () => {
  // The guides' own layout puts a conversation endpoint at another provider. Comparing the
  // path alone marked our own matching path as that destination.
  const cfg = { ...CFG, discovery: { ...DISCOVERY,
    agent: { protocols: [{ type: "poppy", endpoint: "https://chat.provider.example/shops/a/conversations" }] } } };
  assert.equal(classify(S("/shops/a/conversations"), "POST", cfg).isResource, false);
});

test("a website page is a page, and another host is neither", () => {
  const page = R(S("/products/1"));
  assert.equal(page.isResource, false);
  assert.equal(page.isPage, true);
  const other = R("https://elsewhere.example/v1/orders");
  assert.equal(other.isResource, false);
  assert.equal(other.isPage, false);
});

test("the url is built from the configured origin, never from the Host header", () => {
  assert.equal(publicUrl("https://shop.example", "/v1/orders?cursor=1"), "https://shop.example/v1/orders?cursor=1");
});

test("an absolute-form target for our own authority is accepted", () => {
  // RFC 9112: "A server MUST accept the absolute-form in requests". Concatenating it
  // produced https://shop.example/https://shop.example/v1/orders, which classified as a
  // page and then failed htm-htu against a conforming agent.
  assert.equal(publicUrl("https://shop.example", "https://shop.example/v1/orders"), "https://shop.example/v1/orders");
});

test("an absolute-form target for another authority is recorded, not silently excluded", () => {
  const rec = recordOf({ method: "GET", url: "https://evil.example/v1/orders", headers: {} }, CFG);
  assert.equal(rec.misdirected, true, "a request for another authority was not flagged");
  assert.equal(rec.isResource, false);
  assert.equal(rec.isPage, false, "and must not be labelled a page of our website");
});

test("two Session headers are counted, and the value is kept so header-sent stays true", () => {
  // Deleting the value made session.header-sent say "carried no Session header", which is
  // untrue when two were sent, and reproduced the self-contradiction it was meant to stop.
  const one = sessionHeaderOf({ "poppy-session": "a.b.c" });
  assert.equal(one.count, 1);
  const two = sessionHeaderOf({ "poppy-session": "a.b.c, d.e.f" });
  assert.equal(two.count, 2);
  assert.ok(two.value, "the raw value must be kept so header-sent does not lie");
  assert.equal(two.decodable, false);
});

test("an undecodable single header is recorded as such, not as absent", () => {
  const rec = recordOf({ method: "GET", url: "/v1/orders", headers: { "poppy-session": "not-a-jwt" } }, CFG);
  assert.equal(rec.sessionHeaderCount, 1);
  assert.equal(rec.sessionHeaderDecodable, false);
});

test("at is Unix seconds, and the caller may supply the arrival time", () => {
  const at = 1700000000;
  const rec = recordOf({ method: "GET", url: "/v1/orders", headers: {} }, CFG, { at });
  assert.equal(rec.at, at, "the server must be able to stamp arrival time, not call time");
  const now = recordOf({ method: "GET", url: "/v1/orders", headers: {} }, CFG);
  assert.ok(Math.abs(now.at - Math.floor(Date.now() / 1000)) <= 2);
});

test("a body that was never sent is distinguished from an empty one", () => {
  // 8.2: "Every POST has a JSON body with a request id", so a later check needs to tell
  // "no body" from "empty body". `body ?? ""` hid the difference.
  const none = recordOf({ method: "GET", url: "/v1/orders", headers: {} }, CFG);
  assert.equal(none.body, null);
  const empty = recordOf({ method: "POST", url: "/poppy/conversations", headers: { "content-length": "0" } }, CFG, { body: "" });
  assert.equal(empty.body, "");
});

// The body reader, extracted so a recorder outside a Company captures a body the same way the
// Company does. Its own tests live here because it belongs to the record, not to the server,
// and because the branch that matters is the one that only happens when a client goes away.
test("readBody keeps the bytes it saw when the request never ends", async () => {
  // The abort branch is the whole reason this is worth a test of its own. A reader that only
  // handles `end` loses the request entirely, and a grader that loses requests cannot say it
  // recorded what it judged. The hash must cover what arrived, and the record must say it is
  // incomplete rather than look like an empty body.
  const { readBody } = await import("../record.mjs");
  const { EventEmitter } = await import("node:events");
  const req = new EventEmitter();
  const record = {};
  let doneCalled = 0;
  readBody(req, record, 1_000_000, () => { doneCalled++; });

  req.emit("data", Buffer.from('{"mes'));
  req.emit("aborted");
  req.emit("error", new Error("socket reset"));

  const { createHash } = await import("node:crypto");
  assert.equal(record.bodyComplete, false, "an aborted body must not look complete");
  assert.equal(record.bodyBytes, 5);
  assert.equal(record.bodySha256, createHash("sha256").update('{"mes').digest("hex"),
    "the hash must cover the bytes that arrived, not the bytes that were kept");
  assert.equal(doneCalled, 0, "nothing should answer a request whose body never arrived");
});

test("readBody truncates what it keeps and hashes what it got", async () => {
  // The two halves disagree on purpose: `body` is capped so a report cannot be filled with
  // someone's upload, while the hash is over everything, so an oversize body is still
  // identifiable. A reader that hashed only the kept bytes would make those two agree and the
  // flag meaningless.
  const { readBody } = await import("../record.mjs");
  const { EventEmitter } = await import("node:events");
  const { createHash } = await import("node:crypto");
  const req = new EventEmitter();
  const record = {};
  let done = false;
  readBody(req, record, 4, () => { done = true; });

  req.emit("data", Buffer.from("abcd"));
  req.emit("data", Buffer.from("efgh"));
  req.emit("end");

  assert.equal(done, true);
  assert.equal(record.body, "abcd", "the kept body must stop at the cap");
  assert.equal(record.bodyTruncated, true);
  assert.equal(record.bodyBytes, 8);
  assert.equal(record.bodyComplete, true);
  assert.equal(record.bodySha256, createHash("sha256").update("abcdefgh").digest("hex"));
});

test("a listed API path reached with a method the document does not describe is not a web page", async () => {
  // Found when a POST reached a path the OpenAPI lists only for GET: the record called it "a website page, where 5.2 makes the header a SHOULD". It is not a
  // page. 5.2 counts "the request URLs its listed APIs describe", and this method is not
  // described, so no rule should treat it as a destination; but calling a JSON API path a web
  // page tells a builder the header was optional there for a reason that does not exist, and it
  // puts the request in the one bucket where a missing Session can never be a failure.
  const got = classify("https://shop.example/v1/orders", "DELETE", CFG);
  assert.equal(got.isPage, false, `a DELETE to a listed GET path was classified as a page: ${got.why}`);
  assert.equal(got.isResource, false, "the document does not describe this method, so it is not a destination");
  assert.equal(got.mustNotCarry, false);
  assert.match(got.why, /method/i, `the record must say what is actually going on: ${got.why}`);
});
