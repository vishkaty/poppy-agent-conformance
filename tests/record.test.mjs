// The recorder decides which rules apply at all, so a mistake here makes every verdict
// wrong in a way no check can detect.
//
// Two of these were measured against an earlier recorder in this project's private tree:
// `at` was milliseconds stamped after the response ended, so every request fell outside the
// iat window, and `url` was the path only, so the htu comparison silently skipped and a
// wrong htu passed. The second is the worse one: a check that cannot fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, publicUrl, sessionHeaderOf, recordOf } from "../record.mjs";

// A Company's own poppy.json, which 5.2 makes the authority on what carries the header:
// "The destinations come from the Company's poppy.json".
const DISCOVERY = {
  protocol_version: "1.0",
  organization: { name: "Shop", domain: "shop.example" },
  auth: { issuer: "https://shop.example/poppy" },
  agent: { protocols: [{ type: "poppy", endpoint: "https://shop.example/poppy/conversations", description: "d" }] },
  apis: [
    { type: "openapi", url: "https://shop.example/poppy/openapi.json", description: "d" },
    { type: "mcp", url: "https://shop.example/poppy/mcp", description: "d" },
  ],
  web: { browser_session_endpoint: "https://shop.example/poppy/browser-session" },
  tasks: { endpoint: "https://shop.example/poppy/tasks" },
};
// Request URLs the OpenAPI document describes, resolved from its servers and paths at
// startup. 5.2 counts "the request URLs its listed APIs describe", which is not the
// document itself.
const API_PREFIXES = ["https://shop.example/poppy/api/"];
const CFG = { origin: "https://shop.example", discovery: DISCOVERY, apiPrefixes: API_PREFIXES };

const r = u => classify(u, CFG);

test("a listed API's request URLs carry the header", () => {
  assert.equal(r("https://shop.example/poppy/api/orders").isResource, true);
  assert.equal(r("https://shop.example/poppy/mcp").isResource, true, "an mcp url IS the endpoint");
});

test("conversation routes under the selected protocol endpoint carry it", () => {
  // 8.2's routes live beneath agent.protocols[].endpoint.
  for (const u of ["https://shop.example/poppy/conversations",
                   "https://shop.example/poppy/conversations/c_1",
                   "https://shop.example/poppy/conversations/c_1/messages",
                   "https://shop.example/poppy/conversations/c_1/events"])
    assert.equal(r(u).isResource, true, u);
});

test("browser authorization carries it, but the page the browser loads does not", () => {
  // Section 6: the agent authorizes at {browser_session_endpoint}/authorize. The page itself
  // is loaded by a browser, which never sends the header.
  assert.equal(r("https://shop.example/poppy/browser-session/authorize").isResource, true);
  assert.equal(r("https://shop.example/poppy/browser-session").isResource, false);
});

test("tasks carries it", () => {
  assert.equal(r("https://shop.example/poppy/tasks").isResource, true);
});

test("discovery, description documents and OAuth endpoints do NOT carry it", () => {
  // 5.2 verbatim: "Discovery and description documents and OAuth endpoints don't carry this
  // header." Marking any of these as a resource would fail a conforming agent for obeying
  // the rule.
  for (const u of ["https://shop.example/.well-known/poppy.json",
                   "https://shop.example/.well-known/oauth-authorization-server",
                   "https://shop.example/.well-known/oauth-protected-resource",
                   "https://shop.example/poppy/openapi.json",
                   "https://shop.example/poppy/token",
                   "https://shop.example/poppy/authorize",
                   "https://shop.example/poppy/revoke"])
    assert.equal(r(u).isResource, false, u);
});

test("sharing a hostname does not make a URL a destination", () => {
  // 5.2 verbatim: "Sharing a hostname with one of these URLs doesn't make another URL a
  // Session destination." A host-based heuristic would mark all of these.
  for (const u of ["https://shop.example/anything",
                   "https://shop.example/poppy/not-listed",
                   "https://shop.example/poppy/conversationsX"])
    assert.equal(r(u).isResource, false, u);
});

test("a website page on organization.domain is a page, not a resource", () => {
  // 5.2 makes the header a SHOULD there, so its absence can never be a FAIL. Recording it
  // as a resource would turn a SHOULD into a MUST.
  const v = r("https://shop.example/products/1");
  assert.equal(v.isResource, false);
  assert.equal(v.isPage, true);
});

test("another host is neither", () => {
  const v = r("https://elsewhere.example/poppy/api/orders");
  assert.equal(v.isResource, false);
  assert.equal(v.isPage, false);
});

test("the url is built from the configured origin, never from the Host header", () => {
  // The guides: "Behind proxies and load balancers, compare htu with the public URL the
  // personal agent used. Build it from your configured public origin, not from the Host
  // header your server receives." Behind a tunnel the origin sees plain HTTP on a loopback
  // port, so a Host-derived URL would never match a conforming htu.
  assert.equal(publicUrl("https://shop.example", "/poppy/api/orders?cursor=1"),
               "https://shop.example/poppy/api/orders?cursor=1");
  assert.equal(publicUrl("https://shop.example", "/poppy/api/orders"),
               "https://shop.example/poppy/api/orders");
});

test("two Session headers are detected, not silently joined", () => {
  // Node joins repeated unknown headers with ", ", which produces one undecodable string.
  // Left alone that reads as "no Session header was sent" on every claim check while
  // header-sent passes, a self-contradicting report.
  const one = sessionHeaderOf({ "poppy-session": "a.b.c" });
  assert.deepEqual(one, { value: "a.b.c", duplicated: false });
  const two = sessionHeaderOf({ "poppy-session": "a.b.c, d.e.f" });
  assert.equal(two.duplicated, true, "a joined pair of headers was not detected");
  assert.equal(two.value, undefined, "a duplicated header must not be decoded as if it were one");
});

test("at is Unix seconds, taken when the request arrives", () => {
  const req = { method: "GET", url: "/poppy/api/orders", headers: { "poppy-version": "1.0" } };
  const before = Math.floor(Date.now() / 1000);
  const rec = recordOf(req, CFG);
  assert.ok(rec.at >= before && rec.at <= before + 2, `at was ${rec.at}, not Unix seconds now`);
  assert.equal(rec.url, "https://shop.example/poppy/api/orders");
  assert.equal(rec.isResource, true);
  assert.equal(rec.method, "GET");
});
