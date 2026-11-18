// The run model: how a builder starts a run, drives their agent, and reads the result.
//
// A run is an exclusive lease over both Companies. Chosen over attributing each request to a
// run by the `iss` of its Session JWT, because the headline failure this grader exists to
// catch is a request carrying NO Session JWT, which has no iss to attribute by: charging
// another builder's bare request to this run would be a wrong FAIL, and a wrong FAIL is the
// most expensive output this instrument can produce.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRig } from "../rig.mjs";
import { discoveryFor } from "../discovery.mjs";

const COMPANIES = () => [
  { origin: "http://127.0.0.1", apiOperations: [{ method: "GET", template: "/v1/orders" }] },
  { origin: "http://127.0.0.1", apiOperations: [{ method: "GET", template: "/v1/orders" }] },
];

async function rig({ origins = p => `http://127.0.0.1:${p}`, canaryPublicBase, ...over } = {}) {
  const r = createRig({ companies: COMPANIES(), ...over });
  let ports;
  try {
    ports = await r.listen();
    r.setOrigins(ports.map(origins));
    if (canaryPublicBase) r.setCanaryPublicBase(ports.map(canaryPublicBase));
  } catch (err) { await r.close(); throw err; }
  return { r, ports, base: origins(ports[0]), second: origins(ports[1]) };
}

test("a run is leased, and a second request while it is held is refused without naming the holder", async () => {
  const { r, base } = await rig();
  try {
    const a = await fetch(`${base}/grader/runs`, { method: "POST" });
    const text = await a.text();
    assert.equal(a.status, 201, text);
    const run = JSON.parse(text);
    assert.match(run.token, /^[A-Za-z0-9_-]{22}$/, `token was ${run.token}`);
    assert.ok(run.report.endsWith(run.token), `report url was ${run.report}`);
    assert.equal(run.companies.length, 2, "a builder must be told both origins to point the agent at");
    assert.ok(Number.isInteger(run.expires_in));

    const b = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(b.status, 409);
    const busy = await b.json();
    assert.equal(busy.error, "busy");
    assert.ok(Number.isInteger(busy.retry_after_seconds));
    assert.ok(!JSON.stringify(busy).includes(run.token), "the refusal leaks the holder's token");

    await fetch(`${base}/grader/runs/${run.token}/end`, { method: "POST" });
    assert.equal((await fetch(`${base}/grader/runs`, { method: "POST" })).status, 201,
      "the lease must be grantable again once ended");
  } finally { await r.close(); }
});

test("an expired lease is grantable again, and the abandoned run is still readable", async () => {
  // A builder who closes the tab must not hold the grader for ever. The clock is injected so
  // this proves the boundary itself: live AT the expiry second, dead one second later.
  let clock = 1_700_000_000;
  const { r, base } = await rig({ leaseSeconds: 60, now: () => clock });
  try {
    const first = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    clock += 60;
    assert.equal((await fetch(`${base}/grader/runs`, { method: "POST" })).status, 409,
      "the lease died at its last valid second");
    clock += 1;
    assert.equal((await fetch(`${base}/grader/runs`, { method: "POST" })).status, 201,
      "an expired lease still blocked a new run");
    const rep = await fetch(`${base}/grader/report/${first.token}.json`);
    assert.equal(rep.status, 200, "the abandoned run's report was discarded with its lease");
    assert.equal((await rep.json()).run.frozen, true, "an expired run must be frozen, not still open");
  } finally { await r.close(); }
});

test("requests to both Companies during a lease are recorded; control-plane requests never are", async () => {
  const { r, base, second } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    await fetch(`${second}/v1/orders`);
    await fetch(`${base}/grader/report/${token}.json`);                    // control plane
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.requests.length, 2, "a request to the second Company was not recorded");
    assert.ok(!rep.requests.some(q => String(q.url ?? q.path).includes("/grader")),
      `a control-plane request was recorded: ${rep.requests.map(q => q.url).join(" ")}`);
  } finally { await r.close(); }
});

test("a request with no lease is graded by nothing, and neither is the grader's own canary", async () => {
  const { r, base } = await rig();
  try {
    await fetch(`${base}/v1/orders`);                                      // before any run
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.requests.length, 0,
      `requests from before the lease were attributed to this run: ${rep.requests.map(q => q.url).join(" ")}`);
  } finally { await r.close(); }
});

test("ending a run freezes it, and later requests are absent", async () => {
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    await fetch(`${base}/grader/runs/${token}/end`, { method: "POST" });
    await fetch(`${base}/v1/orders`);                                      // after the freeze
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.requests.length, 1, "a request after the freeze changed a frozen report");
    assert.equal(rep.run.frozen, true);
  } finally { await r.close(); }
});

test("requests beyond the per-run limit are counted and said so, not silently dropped", async () => {
  // Absence must never read as conformance. An agent that sends a million requests gets a
  // bounded report that states what it stopped examining.
  const { r, base } = await rig({ maxRequestsPerCompany: 2 });
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    for (let i = 0; i < 4; i++) await fetch(`${base}/v1/orders`);
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.requests.length, 2, "the per-run limit was not applied");
    assert.equal(rep.about.recordedNotJudged.beyondLimit, 2,
      "requests past the limit were dropped without the report saying how many");
  } finally { await r.close(); }
});

test("a wrong token is indistinguishable from an unknown path", async () => {
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const wrong = token.slice(0, -1) + (token.at(-1) === "A" ? "B" : "A");
    const a = await fetch(`${base}/grader/report/${wrong}`);
    const b = await fetch(`${base}/grader/nothing-here`);
    assert.equal(a.status, 404);
    assert.equal(b.status, 404);
    assert.equal(await a.text(), await b.text(), "a wrong token is distinguishable from an unknown path");
    assert.deepEqual([...a.headers].filter(([k]) => k !== "date"),
                     [...b.headers].filter(([k]) => k !== "date"),
                     "the headers distinguish a wrong token from an unknown path");
  } finally { await r.close(); }
});

test("the report is served as HTML and JSON, with headers that keep it private", async () => {
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    const html = await fetch(`${base}/grader/report/${token}`);
    const json = await fetch(`${base}/grader/report/${token}.json`);
    assert.match(html.headers.get("content-type"), /text\/html/);
    assert.match(json.headers.get("content-type"), /application\/json/);
    for (const [name, res] of [["html", html], ["json", json]]) {
      assert.match(res.headers.get("cache-control") ?? "", /no-store/, name);
      assert.equal(res.headers.get("referrer-policy"), "no-referrer",
        `${name}: a specification link on the page would otherwise carry the token in the Referer`);
      assert.match(res.headers.get("x-robots-tag") ?? "", /noindex/, name);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff", name);
      assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/, name);
    }
    const body = await html.text();
    assert.ok(!body.includes(token), "the report page contains its own token");
  } finally { await r.close(); }
});

test("the token is never written to any console stream", async () => {
  // A token in a log is a report anybody holding the log can read.
  //
  // An earlier version of this test cleared the captured output after proving the capture
  // worked, which wiped the very line a token logged at grant time would have written. A
  // mutation that logged the token survived it. So the capture is installed BEFORE the first
  // request, is never cleared, and the control is a sentinel rather than the token itself.
  const out = [];
  const real = { log: console.log, error: console.error, warn: console.warn, info: console.info,
                 debug: console.debug, stdout: process.stdout.write, stderr: process.stderr.write };
  const grab = (...a) => { out.push(a.map(String).join(" ")); };
  console.log = console.error = console.warn = console.info = console.debug = grab;
  // Passed THROUGH, not swallowed: the test runner emits its own results through
  // process.stdout.write, and an earlier version of this stub ate the line reporting whether
  // this very test had passed. It then appeared to run 20 of 21 tests with nothing red.
  process.stdout.write = (c, ...rest) => { out.push(String(c)); return real.stdout.call(process.stdout, c, ...rest); };
  process.stderr.write = (c, ...rest) => { out.push(String(c)); return real.stderr.call(process.stderr, c, ...rest); };
  let r, token;
  try {
    console.log("capture-control-sentinel");
    ({ r } = await rig());
    const base = r.origins[0];
    const made = await fetch(`${base}/grader/runs`, { method: "POST" });
    const body = await made.json();
    token = body.token;
    const a = await fetch(`${base}/v1/orders`);
    const b = await fetch(`${base}/grader/runs/${token}/end`, { method: "POST" });
    const c = await fetch(`${base}/grader/report/${token}`);
    Object.assign(console, real); process.stdout.write = real.stdout; process.stderr.write = real.stderr;
    assert.equal(made.status, 201);
    assert.equal(b.status, 200, "the run did not end, so the paths below were never exercised");
    assert.equal(c.status, 200, "the report was never served, so nothing could have logged it");
    // A bare request to a destination is refused now, which is the point of enforcement:
    // 5.3 makes it invalid_session, and the request is still recorded and judged.
    assert.equal(a.status, 400, `a bare request to a destination answered ${a.status}`);
    assert.match(token ?? "", /^[A-Za-z0-9_-]{22}$/, "no token, so the search below would pass for free");
    assert.ok(out.some(l => l.includes("capture-control-sentinel")),
      "the console capture does not work, so this test proves nothing");
    const leaked = out.filter(l => l.includes(token));
    assert.deepEqual(leaked, [], `the token was written to a console stream: ${leaked.join(" | ")}`);
  } finally {
    Object.assign(console, real); process.stdout.write = real.stdout; process.stderr.write = real.stderr;
    if (r) await r.close();
  }
});

test("a run is attributed by its own mark, not by what happens to be in memory", async () => {
  // The first version of this guard was redundant: requests outside a live run were never
  // retained AND the records were destroyed at the freeze, so the mark could be deleted with
  // no test noticing. A guard no test can kill is either dead or untested, so the freeze now
  // keeps the run's own records and drops only earlier ones, which makes the mark the thing
  // that decides and this test the thing that proves it.
  const { r, base } = await rig();
  try {
    const first = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    await fetch(`${base}/grader/runs/${first.token}/end`, { method: "POST" });
    const second = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    const a = await (await fetch(`${base}/grader/report/${first.token}.json`)).json();
    const b = await (await fetch(`${base}/grader/report/${second.token}.json`)).json();
    assert.equal(a.requests.length, 1, "the first run lost or gained a request");
    assert.equal(b.requests.length, 1,
      `the second run was charged ${b.requests.length} requests, so one builder's traffic reached another's report`);
  } finally { await r.close(); }
});

test("the canary gate refuses to grade when the grader's own configuration is wrong", async () => {
  // The guard against the worst outcome: our deployment turns every htu into a FAIL and the
  // report says so in red with the builder's own jti beside it. Before granting a lease the
  // rig drives its own Companies with traffic minted by the authors' signing code, building
  // htu from the origin in the PUBLISHED document while the grader compares it against the
  // CONFIGURED one, so a disagreement between those two is caught here and not blamed on
  // the builder. Anything other than PASS counts, because the quieter failure is a check
  // that stops reaching anything and returns INCONCLUSIVE for ever.
  // Every endpoint is on the origin actually served, so the canary reaches everything it
  // means to; only the issuer the document publishes is wrong. That is the shape of a real
  // deployment mistake, and it must be caught by a RULE verdict rather than by the reach
  // count, which is why this asserts which rule.
  const wrongIssuer = c => ({ ...c, discovery: (o) => ({ ...discoveryFor(o),
                              auth: { issuer: "https://elsewhere.example/poppy" } }) });
  const bad = await rig({ companies: COMPANIES().map(wrongIssuer) });
  try {
    const res = await fetch(`${bad.base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a misconfigured grader graded a builder anyway");
    const body = await res.json();
    assert.equal(body.error, "grader_control_failed");
    assert.equal(body.rule, "session.htm-htu", `the gate fired on ${body.rule}: ${body.why}`);
    assert.equal(body.verdict, "FAIL");
  } finally { await bad.r.close(); }

  const good = await rig();
  try {
    assert.equal((await fetch(`${good.base}/grader/runs`, { method: "POST" })).status, 201,
      "a correctly configured grader refused to grade");
  } finally { await good.r.close(); }
});

test("every rule is either expected to pass the canary or excluded with a reason", async () => {
  // A canary whose expected set is empty passes for free, which is this project's commonest
  // recorded defect wearing a new hat. This also makes the next check added to checks.mjs
  // impossible to forget: it must be put in one list or the other deliberately.
  const { CANARY_RULES, CANARY_EXCLUDED } = await import("../rig.mjs");
  const { CHECKS, PAIRWISE } = await import("../checks.mjs");
  const all = [...CHECKS, ...PAIRWISE].map(c => c.id);
  assert.ok(CANARY_RULES.length >= 5, `the canary expects only ${CANARY_RULES.length} rules to pass`);
  for (const id of CANARY_RULES) assert.ok(all.includes(id), `the canary expects a rule that does not exist: ${id}`);
  for (const id of Object.keys(CANARY_EXCLUDED)) assert.ok(all.includes(id), `a rule excluded from the canary does not exist: ${id}`);
  for (const id of all)
    assert.ok(CANARY_RULES.includes(id) || CANARY_EXCLUDED[id],
      `${id} is neither expected to pass the canary nor excluded from it with a reason`);
  for (const [id, why] of Object.entries(CANARY_EXCLUDED))
    assert.ok(String(why).length > 40, `the exclusion of ${id} does not say why`);
  assert.deepEqual([...new Set(CANARY_RULES)], CANARY_RULES, "a rule is listed twice");
});

test("a destination under the control-plane prefix is refused, not silently shadowed", async () => {
  // The control plane shares a listener with the first Company, so a configured endpoint
  // under /grader/ would be answered by the control plane and examined by no rule.
  assert.throws(() => createRig({ companies: [
    { origin: "http://127.0.0.1:1", discovery: () => ({ ...discoveryFor("http://127.0.0.1:1"),
        tasks: { endpoint: "http://127.0.0.1:1/grader/tasks" } }) },
    { origin: "http://127.0.0.1:2" },
  ] }), /grader/, "a destination under the control-plane prefix was accepted");
});

// ---------------------------------------------------------------------------------------
// The canary gate, after a refutation found the loopback-only version self-confirming.
//
// Building htu from the published document and comparing it against the configured origin
// sounds like an independent control, but the published document IS derived from the
// configured origin, so in production both sides are one variable and the gate was blind to
// the deployment mistake that matters most: a hostname that does not route to this listener.
// The public leg below is the fix, and these are its tests.
// ---------------------------------------------------------------------------------------

test("the gate sends a leg through the public hostname and checks it arrives here", async () => {
  // localhost is not a loopback literal, so it exercises the public leg over DNS we control.
  const { r, base } = await rig({ origins: p => `http://localhost:${p}` });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 201, await res.text());
  } finally { await r.close(); }
});

test("a hostname routed to the wrong listener is caught, which loopback alone cannot see", async () => {
  // Swapped tunnel ingress: the configuration of each Company is correct and its documents
  // agree with themselves, but the public hostname of the first arrives at the second. Every
  // request a builder sends would be judged against the other Company's identifier and the
  // report would be red for our mistake.
  const { r, base, ports } = await rig({ origins: p => `http://localhost:${p}` });
  try {
    r.setCanaryPublicBase(ports.map(() => `http://localhost:${ports[1]}`));
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a swapped ingress was not caught");
    const body = await res.json();
    assert.equal(body.rule, "canary.public-route");
    assert.match(body.why, /did not arrive/i);
  } finally { await r.close(); }
});

test("a public hostname that reaches nothing is caught", async () => {
  const { r, base, ports } = await rig({ origins: p => `http://localhost:${p}` });
  try {
    r.setCanaryPublicBase([`http://127.0.0.1:1`, `http://localhost:${ports[1]}`]);
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a dead public hostname was not caught");
    assert.equal((await res.json()).rule, "canary.public-route");
  } finally { await r.close(); }
});

test("the gate counts what its own traffic reached, so a narrowed canary cannot pass quietly", async () => {
  // With no OpenAPI operations compiled, the canary's API requests are not destinations at
  // all. Every rule it still reaches can pass while the canary examines a fraction of what
  // it believes it does, which is the quiet failure this whole gate exists to prevent.
  const { r, base } = await rig({ companies: COMPANIES().map(c => ({ ...c, apiOperations: [] })) });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a canary that reached fewer destinations than it sent was accepted");
    assert.equal((await res.json()).rule, "canary.reach");
  } finally { await r.close(); }
});

test("a rule the canary cannot reach fails the gate as loudly as one that fails", async () => {
  // The quieter failure in this project's history is a check that stops reaching anything
  // and returns INCONCLUSIVE for ever. session.ath is excluded from the canary precisely
  // because this grader issues no access tokens, so demanding it is a true INCONCLUSIVE.
  const { r, base } = await rig({ canaryRules: ["session.header-sent", "session.ath"] });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a rule the canary never reached did not fail the gate");
    const body = await res.json();
    assert.equal(body.rule, "session.ath");
    assert.equal(body.verdict, "INCONCLUSIVE", `the gate reported ${body.verdict}`);
  } finally { await r.close(); }
});

test("a canary that throws refuses to grade, it does not grant the lease", async () => {
  // The control must never be able to opt out of itself. Node strips the authors' types only
  // behind a flag, so a grader started without it reaches exactly this path.
  const { r, base } = await rig({ canaryModule: "./does-not-exist.ts" });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a canary that threw granted the lease anyway");
    const body = await res.json();
    assert.equal(body.rule, "canary.drive");
    assert.equal(body.verdict, "ERROR");
  } finally { await r.close(); }
});

test("a public hostname that arrives with a rewritten Host is caught", async () => {
  // The public URL this grader compares htu against is its configured origin. If the thing in
  // front of it rewrites Host, the URL a builder reaches is not the URL we judge against, and
  // every htu would be wrong for our reason.
  const { r, base, ports } = await rig({ origins: p => `http://localhost:${p}` });
  try {
    r.setCanaryPublicBase(ports.map(p => `http://127.0.0.1:${p}`));
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a rewritten Host was not caught");
    const body = await res.json();
    assert.equal(body.rule, "canary.public-route");
    assert.match(body.why, /arrived with Host/);
  } finally { await r.close(); }
});

test("a canary request that arrives but is not a destination is counted as a shortfall", async () => {
  // The conversation endpoint is published on another origin, so the POST the canary sends
  // is recorded and classified as nothing. The rules it would have exercised are then
  // examined by neither the canary nor, later, a real agent.
  const elsewhere = c => ({ ...c, discovery: (o) => {
    const d = discoveryFor(o);
    return { ...d, agent: { protocols: [{ ...d.agent.protocols[0],
             endpoint: "https://elsewhere.example/poppy/conversations" }] } };
  } });
  const { r, base } = await rig({ companies: COMPANIES().map(elsewhere) });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a canary request that reached no rule was accepted");
    const body = await res.json();
    assert.equal(body.rule, "canary.reach");
    assert.match(body.why, /classified as destinations/);
  } finally { await r.close(); }
});

test("the report says how many requests arrived before the lease", async () => {
  // The likeliest wrong verdict in this design: an agent fetches poppy.json on startup and
  // caches it, so by the time the builder leases, the one request that could have judged
  // "a Session JWT must not go to a discovery document" has already happened. The rule then
  // abstains and tells the builder to do discovery, which they did. Stating the count is
  // what lets them see why.
  const { r, base } = await rig();
  try {
    await fetch(`${base}/.well-known/poppy.json`);
    await fetch(`${base}/v1/orders`);
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.about.recordedNotJudged.beforeLease, 2,
      "requests that arrived before the lease were excluded without the report saying so");
    assert.match(JSON.stringify(rep.about), /before this run/i,
      "nothing on the page explains what that count means");
  } finally { await r.close(); }
});

test("the report says when traffic in a run came from more than one source", async () => {
  // A previous builder's agent still long polling, or a scanner probing a fresh hostname,
  // lands in whoever holds the lease. Lease attribution cannot prevent that, so the report
  // has to make it visible: a bare request from somewhere else would otherwise be a FAIL on
  // "every request to a listed destination carries a Session JWT" with no way to argue.
  const { r, base } = await rig({ companies: COMPANIES().map(c => ({ ...c, trustForwardedFor: true })) });
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`, { headers: { "x-forwarded-for": "203.0.113.4" } });
    await fetch(`${base}/v1/orders`, { headers: { "x-forwarded-for": "198.51.100.9" } });
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.summary.sources, 2, "the report did not notice two sources");
    const html = await (await fetch(`${base}/grader/report/${token}`)).text();
    assert.match(html, /two different sources|2 different sources/i,
      "the page does not say the traffic came from more than one source");
    assert.ok(!html.includes("203.0.113.4"), "the page shows a raw client address");
  } finally { await r.close(); }
});

test("ending a run twice answers the same thing, and does not look like a lost run", async () => {
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const a = await fetch(`${base}/grader/runs/${token}/end`, { method: "POST" });
    const b = await fetch(`${base}/grader/runs/${token}/end`, { method: "POST" });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200, "a retried end looked like a wrong token");
    assert.deepEqual(await a.json(), await b.json());
  } finally { await r.close(); }
});

test("every control-plane path is kept out of the run, not just the report", async () => {
  // The POST that creates the lease is below the mark by construction, so testing only that
  // one proves nothing about the others.
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    await fetch(`${base}/grader/runs`, { method: "POST" });              // 409 while held
    await fetch(`${base}/grader/health`);
    await fetch(`${base}/grader/report/${token}.json`);
    await fetch(`${base}/grader/runs/${token}/end`, { method: "POST" });
    const rep = await (await fetch(`${base}/grader/report/${token}.json`)).json();
    assert.equal(rep.requests.length, 1,
      `a control-plane request was charged to the run: ${rep.requests.map(q => q.url).join(" ")}`);
  } finally { await r.close(); }
});

test("a wrong token is indistinguishable on every path that takes one", async () => {
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const wrong = token.slice(0, -1) + (token.at(-1) === "A" ? "B" : "A");
    const unknownGet = await fetch(`${base}/grader/nothing-here`);
    const unknownPost = await fetch(`${base}/grader/nothing-here`, { method: "POST" });
    const cases = [
      ["html", await fetch(`${base}/grader/report/${wrong}`)],
      ["json", await fetch(`${base}/grader/report/${wrong}.json`)],
      ["short", await fetch(`${base}/grader/report/tooshort`)],
      ["alphabet", await fetch(`${base}/grader/report/${"!".repeat(22)}`)],
    ];
    const want = await unknownGet.text();
    for (const [what, res] of cases) {
      assert.equal(res.status, 404, what);
      assert.equal(await res.text(), want, `${what}: a wrong token is distinguishable by its body`);
    }
    const endWrong = await fetch(`${base}/grader/runs/${wrong}/end`, { method: "POST" });
    assert.equal(endWrong.status, 404);
    assert.equal(await endWrong.text(), await unknownPost.text(),
      "a wrong token on the end path is distinguishable");
  } finally { await r.close(); }
});

test("the report actually contains the run, and neither output carries the token", async () => {
  // A page with the right headers and no content would pass a test that only checks headers.
  const { r, base } = await rig();
  try {
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    await fetch(`${base}/v1/orders`);
    const html = await (await fetch(`${base}/grader/report/${token}`)).text();
    const jsonText = await (await fetch(`${base}/grader/report/${token}.json`)).text();
    assert.match(html, /\/v1\/orders/, "the page does not show the request that was recorded");
    assert.match(html, /session\.header-sent/, "the page does not show the rules");
    assert.ok(!html.includes(token), "the page contains its own token");
    assert.ok(!jsonText.includes(token), "the JSON contains its own token");
  } finally { await r.close(); }
});

test("health says what a 404 cannot: which process this is and since when", async () => {
  // Reports live in memory, so a restart makes every token 404 with the same bytes as a
  // typo. Without this a builder cannot tell the two apart.
  const { r, base } = await rig();
  try {
    const res = await fetch(`${base}/grader/health`);
    assert.equal(res.status, 200);
    const h = await res.json();
    assert.ok(Number.isInteger(h.started_at), "no process start time");
    assert.equal(h.protocol_version, "1.0");
    assert.equal(h.lease_held, false);
    const { token } = await (await fetch(`${base}/grader/runs`, { method: "POST" })).json();
    const after = await (await fetch(`${base}/grader/health`)).json();
    assert.equal(after.lease_held, true);
    assert.ok(!JSON.stringify(after).includes(token), "health leaks the holder's token");
  } finally { await r.close(); }
});

test("the gate refuses to grade when its own conforming traffic is answered with an error", async () => {
  // Enforcement makes this the sharpest failure mode this deployment has. If our own
  // configuration refuses traffic the protocol authors' code built, every builder would be
  // stopped at their first request and told their Session was invalid. The rule verdicts are
  // one guard; the HTTP status is a second and a blunter one, because it catches an answer no
  // rule covers: a 405 from a method mismatch, a 404 from a destination we do not serve, a
  // 500 from our own code.
  const { firstRefusedLeg } = await import("../rig.mjs");
  assert.equal(firstRefusedLeg([{ status: 200, path: "/a" }, { status: 201, path: "/b" }]), null);
  assert.equal(firstRefusedLeg([]), null);
  const bad = firstRefusedLeg([{ status: 200, path: "/a" }, { status: 400, path: "/poppy/orders", error: "invalid_session" }]);
  assert.ok(bad, "a 400 on the grader's own conforming traffic was accepted");
  assert.equal(bad.status, 400);
  assert.equal(bad.path, "/poppy/orders");
  for (const status of [301, 400, 401, 403, 404, 405, 409, 500, 503])
    assert.ok(firstRefusedLeg([{ status, path: "/x" }]), `${status} was treated as success`);
});

test("a deployment that refuses the authors own traffic grades nobody", async () => {
  // End to end, with a Company whose published issuer is on another origin, so the htu the
  // canary signs cannot match the URL the grader compares it against and enforcement refuses
  // every leg. Before the status guard this answered 503 for the rule verdict; now it answers
  // for the refusal itself, which is the more useful sentence.
  const wrongIssuer = c => ({ ...c, discovery: (o) => ({ ...discoveryFor(o),
                              auth: { issuer: "https://elsewhere.example/poppy" } }) });
  const { r, base } = await rig({ companies: COMPANIES().map(wrongIssuer) });
  try {
    const res = await fetch(`${base}/grader/runs`, { method: "POST" });
    assert.equal(res.status, 503, "a grader that refuses conforming traffic graded a builder");
    const body = await res.json();
    assert.equal(body.error, "grader_control_failed");
    assert.match(body.rule, /^canary\.refused$|^session\./, `fired on ${body.rule}`);
  } finally { await r.close(); }
});
