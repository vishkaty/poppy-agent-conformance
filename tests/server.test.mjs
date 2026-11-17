// The server feeds the recorder, and the two mistakes it can make are invisible to every
// check above it: stamping the wrong time, and never recording a request at all.
//
// A request that is not recorded is a request no rule examines, which reads as conformance.
// So these tests use a real socket and assert the awkward shapes, not the happy path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import { createGrader, validateConfig } from "../server.mjs";

const DISCOVERY = {
  protocol_version: "1.0",
  organization: { name: "Shop", domain: "127.0.0.1" },
  agent: { protocols: [{ type: "poppy", endpoint: "http://127.0.0.1/poppy/conversations", description: "d" }] },
  apis: [{ type: "openapi", url: "http://127.0.0.1/openapi.json", description: "d" }],
  tasks: { endpoint: "http://127.0.0.1/poppy/tasks" },
};
const base = port => `http://127.0.0.1:${port}`;

async function withGrader(fn, over = {}) {
  const g = createGrader({ origin: "http://127.0.0.1", discovery: DISCOVERY,
                           apiOperations: [{ method: "GET", template: "/v1/orders" },
                                           { method: "POST", template: "/v1/orders" }],
                           ...over });
  const port = await g.listen(0);
  // the configured origin must match the port actually served, or every htu comparison is
  // wrong for the deployment and not for the agent
  g.setOrigin(base(port));
  try { return await fn(g, port); } finally { await g.close(); }
}

test("a GET with no body records body null, not an empty string", async () => {
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`);
    const r = g.records.at(-1);
    assert.equal(r.body, null, "a request that sent no body must not look like one that sent an empty body");
    assert.equal(r.bodyComplete, true);
    assert.equal(r.isResource, true);
  });
});

test("a POST with an empty body records an empty string", async () => {
  // 8.2: "Every POST has a JSON body with a request id", so a later check needs to tell a
  // missing body from an empty one.
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`, { method: "POST", body: "" });
    const r = g.records.at(-1);
    assert.equal(r.body, "");
  });
});

test("a POST body is captured verbatim and marked complete", async () => {
  await withGrader(async (g, port) => {
    const body = JSON.stringify({ id: "req_1", message: { text: "hello" } });
    await fetch(`${base(port)}/v1/orders`, { method: "POST", body, headers: { "content-type": "application/json" } });
    const r = g.records.at(-1);
    assert.equal(r.body, body);
    assert.equal(r.bodyComplete, true);
  });
});

test("at is the arrival time, not the time the response finished", async () => {
  // The defect this exists to stop: a long poll on an events route would otherwise add its
  // own duration as apparent clock skew and fail a conforming agent on the iat window.
  await withGrader(async (g, port) => {
    const t0 = Math.floor(Date.now() / 1000);
    await fetch(`${base(port)}/poppy/conversations/c_1/events?wait=3`);
    const r = g.records.at(-1);
    const t1 = Math.floor(Date.now() / 1000);
    assert.ok(t1 - t0 >= 2, `the response did not actually take time, so this proves nothing (took ${t1 - t0}s)`);
    assert.ok(r.at - t0 <= 1, `at was ${r.at - t0}s after the request began, so it was stamped late`);
  }, { delayMs: 2500 });
});

test("a request whose body never arrives is still recorded, as incomplete", async () => {
  // Promising a body and then hanging up. Without this the record never exists and the
  // request is examined by no rule, which reads as conformance.
  await withGrader(async (g, port) => {
    await new Promise(resolve => {
      const s = connect(port, "127.0.0.1", () => {
        s.write("POST /v1/orders HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 50\r\n\r\n{\"partial\":");
        setTimeout(() => { s.destroy(); resolve(); }, 250);
      });
      s.on("error", resolve);
    });
    await new Promise(r => setTimeout(r, 150));
    const r = g.records.find(x => x.path === "/v1/orders" && x.method === "POST");
    assert.ok(r, "an aborted request was never recorded");
    assert.equal(r.bodyComplete, false, "an incomplete body must say so");
  });
});

test("a request Node rejects before the handler is still recorded", async () => {
  // Node answers a malformed request line itself and emits no request event, so without a
  // clientError listener these are invisible. A grader that cannot see them cannot say it
  // saw everything.
  await withGrader(async (g, port) => {
    await new Promise(resolve => {
      const s = connect(port, "127.0.0.1", () => {
        s.write("GET /v1/orders HTTP/1.1\r\nHost: 127.0.0.1\r\nBad Header: x\r\n\r\n");
        setTimeout(() => { s.destroy(); resolve(); }, 250);
      });
      s.on("error", resolve);
    });
    await new Promise(r => setTimeout(r, 150));
    const rejected = g.records.filter(x => x.rejected);
    assert.ok(rejected.length >= 1, "a request Node rejected was not recorded");
    assert.ok(rejected[0].code, "the rejection must name its reason");
  });
});

test("an oversize body is truncated, flagged, and hashed in full", async () => {
  // Truncating silently would break the replay comparison, which reads the body. The hash
  // keeps the comparison honest when the stored bytes are cut.
  await withGrader(async (g, port) => {
    const body = "x".repeat(5000);
    await fetch(`${base(port)}/v1/orders`, { method: "POST", body });
    const r = g.records.at(-1);
    assert.equal(r.bodyTruncated, true);
    assert.ok(r.body.length < body.length);
    assert.equal(r.bodySha256.length, 64, "the full body must still be identifiable");
  }, { maxBodyBytes: 1000 });
});

test("the config is refused when the origin is not a bare origin", () => {
  for (const origin of ["https://shop.example/base", "https://shop.example/", "HTTPS://SHOP.example"])
    assert.throws(() => validateConfig({ origin, discovery: DISCOVERY }), /origin/i, origin);
});

test("the config is refused when a listed endpoint carries a query or fragment", () => {
  assert.throws(() => validateConfig({
    origin: "https://shop.example", discovery: { ...DISCOVERY,
      tasks: { endpoint: "https://shop.example/poppy/tasks?v=1" } } }), /query or fragment/i);
});

test("a destination on another origin is reported, because no rule can examine it", () => {
  // The spec's own example puts conversations and the MCP server on other hosts. A grader
  // that silently cannot see them would report a partial run as a complete one.
  const warnings = validateConfig({
    origin: "https://shop.example",
    discovery: { ...DISCOVERY,
      agent: { protocols: [{ type: "poppy", endpoint: "https://api.example.com/conversations" }] } },
  });
  assert.ok(warnings.some(w => /api\.example\.com/.test(w)),
    `a destination this grader cannot see was not reported: ${JSON.stringify(warnings)}`);
});
