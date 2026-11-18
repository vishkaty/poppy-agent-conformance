// Fetching the keys a delegation claims to be signed by.
//
// 5.3 step 1: "Fetches the client metadata from `iss` without following redirects, as the CIMD
// draft (§5) requires, and the public keys from its `jwks_uri` (4.1), following the address
// checks in section 3."
//
// The network is injected in every test here. Not for speed: this is the one part of the
// grader that connects to a host a stranger named, and each refusal has to be exercised. Tests
// use HOSTNAMES rather than address literals, because this project's recorded failure is an
// SSRF pin that never ran since every fixture was a literal.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createIssuerKeys } from "../issuer-keys.mjs";

const ref = await import("../reference/jose.ts");
const ISS = "https://agent.example/agent.json";
const JWKS = "https://agent.example/jwks.json";

// A fake network. `routes` maps a URL to a response, `addresses` maps a hostname to what DNS
// would return. Both record what they were asked, so a test can assert that no second request
// was made where none should be.
function net({ routes = {}, addresses = { "agent.example": ["93.184.216.34"] } } = {}) {
  const asked = [], looked = [], connectedTo = [];
  const lookup = (host) => { looked.push(host); return addresses[host] ?? []; };
  const fetch = async (url, opts) => {
    asked.push(url);
    if (opts?.connectTo) connectedTo.push(opts.connectTo);
    const r = routes[url];
    if (!r) throw Object.assign(new Error("ECONNREFUSED"), { cause: { code: "ECONNREFUSED" } });
    if (typeof r === "function") return r();
    return { status: r.status ?? 200, headers: new Map(Object.entries(r.headers ?? {})),
             text: async () => r.body ?? "", redirected: !!r.redirected };
  };
  return { fetch, lookup, asked, looked, connectedTo };
}

async function identity() {
  const operator = await ref.generateKey();
  const key = await ref.generateKey();
  const kid = await ref.thumbprint(operator.publicJwk);
  const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk, iss: ISS });
  return { operator, key, kid, delegation };
}

const good = (id, over = {}) => ({
  [ISS]: { body: JSON.stringify({ client_id: ISS, jwks_uri: JWKS, ...over.metadata }) },
  [JWKS]: { body: JSON.stringify({ keys: [{ ...id.operator.publicJwk, kid: id.kid }] }), ...over.jwks },
  ...over.routes,
});

test("the ordinary case: both documents fetched once, keys returned, and the result says so", async () => {
  const id = await identity();
  const n = net({ routes: good(id) });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "ok", `${got.outcome}: ${got.detail}`);
  assert.equal(got.jwksUri, JWKS);
  assert.equal(got.keys.length, 1);
  assert.deepEqual(got.kids, [id.kid]);
  assert.equal(got.source, "fetch");
  assert.equal(got.fetchedAt, 1000);
  assert.deepEqual(n.asked, [ISS, JWKS], `asked ${n.asked.join(", ")}`);
  // the address was checked, and the connection was pinned to the address that was checked
  assert.deepEqual(n.looked, ["agent.example", "agent.example"]);
  assert.deepEqual(n.connectedTo, ["93.184.216.34", "93.184.216.34"],
    "the fetch was not pinned to the address that was checked, so DNS could change under it");
});

test("a second request inside the cache window does not fetch again, and says it was cached", async () => {
  // 5.2: "A resource sees many Session JWTs with the same delegation, so it MAY cache a
  // verified delegation until it expires." A fetch per request would be unacceptable, and a
  // verdict that depended on a cached fetch has to say so or it cannot be argued with.
  const id = await identity();
  const n = net({ routes: good(id) });
  let clock = 1000;
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => clock });
  await keys.forIssuer(ISS);
  clock = 1030;
  const again = await keys.forIssuer(ISS);
  assert.equal(again.outcome, "ok");
  assert.equal(again.source, "cache");
  assert.equal(again.ageSeconds, 30, "the age of the cached fetch is not reported");
  assert.deepEqual(n.asked, [ISS, JWKS], "it fetched again inside the window");
});

test("an address a stranger could aim us at is refused, and nothing is fetched", async () => {
  // Section 3, and the reason the whole classifier exists. The hostname resolves to the
  // metadata service address, which is the attack this refuses.
  const id = await identity();
  const n = net({ routes: good(id), addresses: { "agent.example": ["169.254.169.254"] } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "agent", `${got.outcome}: ${got.detail}`);
  assert.match(got.detail, /link-local/, got.detail);
  assert.deepEqual(n.asked, [], "it connected anyway");
});

test("one bad address among several refuses the whole fetch", async () => {
  // A host that resolves to a public address AND an internal one is the rebinding shape. Every
  // address is checked, not the first.
  const id = await identity();
  const n = net({ routes: good(id), addresses: { "agent.example": ["93.184.216.34", "10.0.0.5"] } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "agent");
  assert.match(got.detail, /private/, got.detail);
  assert.deepEqual(n.asked, []);
});

test("a redirect at the client metadata is the agent's defect, and is not followed", async () => {
  // 5.3 step 1 fetches "without following redirects, as the CIMD draft (§5) requires", and 4.1
  // says "`client_id` MUST equal the URL the document was fetched from", so a document behind
  // a redirect is not this client's document.
  const id = await identity();
  const n = net({ routes: { ...good(id), [ISS]: { status: 302, headers: { location: "https://elsewhere.example/a" }, redirected: true } } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "agent", got.detail);
  assert.match(got.detail, /redirect/i, got.detail);
  assert.ok(!n.asked.includes("https://elsewhere.example/a"), "it followed the redirect");
});

test("what the agent's own server said decides whose fault it is", async () => {
  // The line is bytes. A status code is their server speaking, so 404 and 410 are the agent's
  // defect: the document is not there and no Company could verify them. A 401, 403, 429 or 5xx
  // is something a builder can change, and a bot rule in front of a metadata host must never
  // close the door, so those are unreached rather than a failure.
  const id = await identity();
  for (const [status, outcome] of [[404, "agent"], [410, "agent"],
                                   [401, "server"], [403, "server"], [429, "server"],
                                   [500, "server"], [503, "server"]]) {
    const n = net({ routes: { ...good(id), [ISS]: { status, body: "" } } });
    const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
    const got = await keys.forIssuer(ISS);
    assert.equal(got.outcome, outcome, `${status} was called ${got.outcome}: ${got.detail}`);
    assert.match(got.detail, new RegExp(String(status)), got.detail);
  }
});

test("a transport failure is our fault and never the builder's", async () => {
  const n = net({ routes: {} });                      // every fetch throws ECONNREFUSED
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "grader", `${got.outcome}: ${got.detail}`);
  assert.match(got.detail, /ECONNREFUSED/);
});

test("a host that does not resolve is our fault, because we cannot tell our resolver from their zone", async () => {
  const n = net({ routes: {}, addresses: {} });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "grader", `${got.outcome}: ${got.detail}`);
  assert.match(got.detail, /resolve/i, got.detail);
});

test("a document that is not this client's, or has no usable jwks_uri, is the agent's defect", async () => {
  const id = await identity();
  const cases = [
    ["client_id names another URL", { metadata: { client_id: "https://other.example/agent.json" } }, /client_id/],
    ["no jwks_uri", { metadata: { jwks_uri: undefined } }, /jwks_uri/],
    ["a jwks_uri that is not https", { metadata: { jwks_uri: "http://agent.example/jwks.json" } }, /HTTPS|https/],
  ];
  for (const [what, over, expect] of cases) {
    const routes = good(id);
    routes[ISS] = { body: JSON.stringify({ client_id: ISS, jwks_uri: JWKS, ...over.metadata }) };
    if (over.metadata && "jwks_uri" in over.metadata && over.metadata.jwks_uri === undefined)
      routes[ISS] = { body: JSON.stringify({ client_id: ISS }) };
    const n = net({ routes });
    const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
    const got = await keys.forIssuer(ISS);
    assert.equal(got.outcome, "agent", `${what}: ${got.outcome} ${got.detail}`);
    assert.match(got.detail, expect, `${what}: ${got.detail}`);
  }
  // not JSON at all
  const n = net({ routes: { ...good(id), [ISS]: { body: "<html>nope" } } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  assert.equal((await keys.forIssuer(ISS)).outcome, "agent");
});

test("a response larger than this grader reads is not the builder's failure", async () => {
  const id = await identity();
  const n = net({ routes: { ...good(id), [JWKS]: { body: "x".repeat(200_000) } } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000, maxBytes: 100_000 });
  const got = await keys.forIssuer(ISS);
  assert.equal(got.outcome, "grader", `${got.outcome}: ${got.detail}`);
  assert.match(got.detail, /larger/i, got.detail);
});

test("a failed fetch is not retried on every request, and the refusal says when it was tried", async () => {
  // The guides: "Refetch each `jwks_uri` at most once per interval, such as 30 seconds, and
  // count failed fetches too. Otherwise a stream of bad assertions can flood the personal
  // agent's server." A grader must not become that flood.
  const n = net({ routes: {} });
  let clock = 1000;
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => clock, refetchSeconds: 30 });
  await keys.forIssuer(ISS);
  const tried = n.asked.length;
  clock = 1010;
  const again = await keys.forIssuer(ISS);
  assert.equal(n.asked.length, tried, "it retried inside the interval");
  assert.equal(again.outcome, "grader");
  assert.match(again.detail, /1000|10s ago|earlier/i, `the refusal does not say when it was tried: ${again.detail}`);
  clock = 1041;
  await keys.forIssuer(ISS);
  assert.ok(n.asked.length > tried, "it never retried after the interval");
});

test("the fetch budget for one run is bounded, and says so when it is spent", async () => {
  // Anyone holding a lease can name a different iss on every request. Without a budget, that
  // is this grader making an unbounded number of outbound connections on demand.
  const id = await identity();
  const n = net({ routes: good(id), addresses: { "agent.example": ["93.184.216.34"] } });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000, budget: 2 });
  for (const host of ["a", "b", "c"]) {
    const url = `https://agent.example/${host}.json`;
    n.routes = good(id);
    await keys.forIssuer(url);
  }
  const spent = await keys.forIssuer("https://agent.example/d.json");
  assert.equal(spent.outcome, "grader");
  assert.match(spent.detail, /budget/i, spent.detail);
});

test("a url this grader will not connect to is decided without any lookup", async () => {
  const n = net({ routes: {} });
  const keys = createIssuerKeys({ fetch: n.fetch, lookup: n.lookup, now: () => 1000 });
  for (const [iss, outcome] of [["http://agent.example/a.json", "agent"],
                                ["https://agent.example:8443/a.json", "grader"],
                                ["https://user:pw@agent.example/a.json", "agent"],
                                ["not a url", "agent"]]) {
    const got = await keys.forIssuer(iss);
    assert.equal(got.outcome, outcome, `${iss}: ${got.outcome} ${got.detail}`);
  }
  assert.deepEqual(n.looked, [], "it resolved a URL it was never going to connect to");
  assert.deepEqual(n.asked, []);
});
