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

test("a target with dot segments is refused and recorded, not served under one path and classified under another", async () => {
  // Node hands the raw target to the server while new URL() resolves dot segments, so
  // /poppy/conversations/../token is served as one path and classified as another. That
  // disagreement is how a request reaches a destination while being judged as something
  // else, so it is refused rather than reconciled.
  await withGrader(async (g, port) => {
    await new Promise(resolve => {
      const s = connect(port, "127.0.0.1", () => {
        s.write("GET /poppy/conversations/../token HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        setTimeout(() => { s.destroy(); resolve(); }, 250);
      });
      s.on("error", resolve);
    });
    await new Promise(r => setTimeout(r, 150));
    const r = g.records.find(x => String(x.rawTarget ?? "").includes(".."));
    assert.ok(r, "a dot-segment target was not recorded");
    assert.equal(r.refused, true, "a dot-segment target must be refused, not served");
    assert.equal(r.isResource, false);
  });
});

test("a backslash in the target is refused the same way", async () => {
  await withGrader(async (g, port) => {
    await new Promise(resolve => {
      const s = connect(port, "127.0.0.1", () => {
        s.write("GET /poppy\\\\conversations HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        setTimeout(() => { s.destroy(); resolve(); }, 250);
      });
      s.on("error", resolve);
    });
    await new Promise(r => setTimeout(r, 150));
    const r = g.records.find(x => String(x.rawTarget ?? "").includes("\\"));
    assert.ok(r && r.refused, "a backslash target was not refused and recorded");
  });
});

test("a normal target is not refused", async () => {
  // The control: if everything were refused, the two tests above would prove nothing.
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`);
    assert.notEqual(g.records.at(-1).refused, true);
  });
});

test("the three documents agree after the origin is known", async () => {
  // 3.2 makes the agent check that the issuer metadata's issuer matches poppy.json's
  // "character for character" and refuse the document otherwise. A discovery snapshot taken
  // before the public origin was known disagreed with the metadata computed from it, so a
  // conforming agent would refuse the grader and the grader would record nothing, reporting
  // every rule as not reached. That reads as the builder's fault.
  await withGrader(async (g, port) => {
    const origin = `http://127.0.0.1:${port}`;
    const j = async p => (await fetch(origin + p)).json();
    const doc = await j("/.well-known/poppy.json");
    const prm = await j("/.well-known/oauth-protected-resource");
    const asm = await j("/.well-known/oauth-authorization-server/poppy");
    const host = new URL(origin).host;
    assert.equal(asm.issuer, doc.auth.issuer, "the issuer metadata must match poppy.json character for character");
    assert.ok(asm.protected_resources.includes(`${new URL(origin).protocol}//${host}`),
      `protected_resources ${JSON.stringify(asm.protected_resources)} does not name the domain`);
    assert.equal(prm.resource, `${new URL(origin).protocol}//${host}`);
    assert.equal(doc.organization.domain, host, "3.1: domain is the host that serves the document, with its port");
  }, { discovery: undefined });
});

test("a record carries where the request came from, so foreign traffic can be seen", async () => {
  // The report renders a salted `source` per request and the one thing it is for is letting a
  // builder see that a request in their run came from somewhere other than their agent: a
  // scanner probing a fresh hostname, or a previous builder's agent still polling. Nothing
  // populated the field, so every request in every production report read `source: null` and
  // the mechanism was decorative.
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`);
    const r = g.records.at(-1);
    assert.equal(typeof r.remoteAddress, "string", "no record of where the request came from");
    assert.match(r.remoteAddress, /127\.0\.0\.1|::1|::ffff:127/, `got ${r.remoteAddress}`);
  });
});

test("behind a proxy the forwarded client address is preferred over the socket", async () => {
  // Every request behind the tunnel arrives from the tunnel process, so the socket address is
  // one constant and distinguishes nothing. Cloudflare sets cf-connecting-ip; the standard
  // Forwarded and X-Forwarded-For are accepted too, leftmost value.
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`, { headers: { "cf-connecting-ip": "203.0.113.7" } });
    assert.equal(g.records.at(-1).remoteAddress, "203.0.113.7");
    await fetch(`${base(port)}/v1/orders`, { headers: { "x-forwarded-for": "203.0.113.9, 198.51.100.1" } });
    assert.equal(g.records.at(-1).remoteAddress, "203.0.113.9", "the leftmost forwarded value is the client");
    await fetch(`${base(port)}/v1/orders`, { headers: { forwarded: 'for="203.0.113.11";proto=https' } });
    assert.equal(g.records.at(-1).remoteAddress, "203.0.113.11");
  }, { trustForwardedFor: true });
});

test("a forwarded header is ignored unless the deployment says to trust it", async () => {
  // Otherwise an agent could split its own traffic into any number of apparent sources by
  // sending a header, which is the one thing this field is used to show.
  await withGrader(async (g, port) => {
    await fetch(`${base(port)}/v1/orders`, { headers: { "x-forwarded-for": "203.0.113.9" } });
    assert.notEqual(g.records.at(-1).remoteAddress, "203.0.113.9",
      "a client-supplied address was believed with nothing in front to overwrite it");
  });
});

test("every endpoint the classifier reads is also checked against the control-plane prefix", async () => {
  // The first version of this guard walked its own shorter list, so a feedback endpoint, an
  // OAuth endpoint or a version document under the prefix was swallowed by the control plane
  // and examined by no rule, which reads as conformance.
  const cases = {
    "feedbackEndpoint": { feedbackEndpoint: "http://127.0.0.1:8/grader/feedback" },
    "authServerEndpoints": { authServerEndpoints: ["http://127.0.0.1:8/grader/token"] },
    "extensionEndpoints": { extensionEndpoints: ["http://127.0.0.1:8/grader/ops"] },
    "supported_versions": { discovery: { ...DISCOVERY, supported_versions: { "1.0": "http://127.0.0.1:8/grader/v1" } } },
  };
  for (const [what, over] of Object.entries(cases))
    assert.throws(() => validateConfig({ origin: "http://127.0.0.1:8", discovery: DISCOVERY,
                                         controlPrefix: "/grader/", ...over }),
      /control-plane prefix/, `${what} under the control-plane prefix was accepted`);
  // and the control: the same endpoints elsewhere are fine
  assert.doesNotThrow(() => validateConfig({ origin: "http://127.0.0.1:8", discovery: DISCOVERY,
    controlPrefix: "/grader/", feedbackEndpoint: "http://127.0.0.1:8/poppy/feedback" }));
});

test("a test agent identity can be hosted, and its private key never is", async () => {
  // The authors' own Company validator is the independent control on this Company, and it
  // only runs past discovery when its test agent's `agent.json` and `jwks.json` are reachable
  // over HTTPS. This serves exactly those two files from a directory and nothing else.
  //
  // The guard that matters: `keygen` writes `private-key.jwk` into the same directory. A
  // static file map would have published the signing key of the identity it is testing with.
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "poppy-identity-"));
  writeFileSync(join(dir, "agent.json"), JSON.stringify({ client_id: "x", jwks_uri: "y" }));
  writeFileSync(join(dir, "jwks.json"), JSON.stringify({ keys: [] }));
  writeFileSync(join(dir, "private-key.jwk"), JSON.stringify({ kty: "EC", d: "SECRET-KEY-MATERIAL" }));
  writeFileSync(join(dir, "config.json"), JSON.stringify({ client_id: "x" }));

  await withGrader(async (g, port) => {
    const at = p => fetch(`${base(port)}/test-agent/${p}`);
    const agent = await at("agent.json");
    assert.equal(agent.status, 200);
    assert.match(agent.headers.get("content-type"), /json/);
    assert.deepEqual(await agent.json(), { client_id: "x", jwks_uri: "y" });
    assert.equal((await at("jwks.json")).status, 200);

    for (const forbidden of ["private-key.jwk", "config.json", "private-key-rsa.jwk",
                             "../agent.json", "..%2fagent.json"]) {
      const res = await at(forbidden);
      assert.equal(res.status, 404, `${forbidden} was served`);
      assert.ok(!(await res.text()).includes("SECRET-KEY-MATERIAL"),
        `${forbidden} leaked private key material`);
    }
  }, { testAgentIdentity: dir });
});

test("a hosted identity prefix may not collide with the control plane or a destination", async () => {
  assert.throws(() => validateConfig({ origin: "http://127.0.0.1:8", discovery: DISCOVERY,
    controlPrefix: "/grader/", testAgentIdentity: "/tmp", testAgentPrefix: "/grader/id" }),
    /control-plane prefix/);
});
