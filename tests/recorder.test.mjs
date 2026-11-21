// The recorder: a reverse proxy a builder runs in front of their OWN Company, so an agent can
// be judged without its traffic ever reaching anyone else. Everything a verdict depends on has
// to arrive here exactly as it would arrive at the Company, which is why these tests are about
// fidelity rather than about features: a recorder that quietly normalises a header, rebuilds a
// URL from Host, or buffers a body makes every verdict a statement about the recorder.
//
// The one test that carries the whole design is "the two capture paths agree": the same bytes
// sent to a Company and to a recorder must produce records equal on every field a check reads.
// Without it this file proves the recorder is self-consistent, which is not the claim.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { connect } from "node:net";
import { createRecorder } from "../recorder.mjs";
import { discoveryFor, openapiFor, DEFAULT_OPERATIONS, operationsToTemplates } from "../discovery.mjs";

// A stub Company. It records what it received so a test can compare the two sides.
async function upstream(handler = (req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); }) {
  const seen = [];
  const srv = createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, headers: { ...req.headers }, rawHeaders: req.rawHeaders.slice() });
    handler(req, res, seen[seen.length - 1]);
  });
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  // closeAllConnections, because a stub that holds a stream open keeps close() pending and the
  // test hangs instead of failing. That cost a 300 second run to work out.
  return { seen, port: srv.address().port,
           close: () => new Promise(r => { srv.closeAllConnections?.(); srv.close(() => r()); }) };
}

function cfgFor(origin, upstreamPort) {
  return {
    origin,
    upstream: `http://127.0.0.1:${upstreamPort}`,
    discovery: discoveryFor(origin),
    apiOperations: operationsToTemplates(DEFAULT_OPERATIONS),
  };
}

// Raw socket, so a test can send what a client library will not: duplicate headers, an
// unsafe target, a body with no content-length.
function raw(port, text) {
  return new Promise((resolve, reject) => {
    const s = connect(port, "127.0.0.1", () => s.write(text));
    let out = "";
    s.on("data", d => { out += d; });
    s.on("end", () => resolve(out));
    s.on("error", reject);
    setTimeout(() => { try { s.end(); } catch {} }, 400);
  });
}

test("a recorded request reaches the Company and is recorded as a destination", async () => {
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`);
    assert.equal(res.status, 200, "the Company's answer must reach the agent");
    await res.body?.cancel();
    assert.equal(up.seen.length, 1, "the Company did not receive the request");
    assert.equal(up.seen[0].url, "/poppy/orders");
    assert.equal(r.records.length, 1, "the request was not recorded");
    const rec = r.records[0];
    assert.equal(rec.method, "GET");
    assert.equal(rec.url, "https://api.shop.example/poppy/orders",
      "the recorded URL must be built from the configured public origin");
    assert.equal(rec.isResource, true, "a listed API operation must classify as a destination");
    assert.equal(rec.body, null, "a GET has no body and must not be recorded as an empty one");
    assert.equal(rec.rejection, undefined, "the recorder refuses nothing, so it must claim no refusal");
  } finally { await r.close(); await up.close(); }
});

test("duplicate Poppy-Session headers survive the recorder, in both directions", async () => {
  // 5.2 is about what the agent put on the wire. `req.headers` has already joined duplicates
  // with ", " and cannot be un-joined, so forwarding that object would hand the Company one
  // header where the agent sent two: the breach would vanish on its way to the Company AND the
  // Company's own answer would stop being an answer to the real request.
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    await raw(port, "GET /poppy/orders HTTP/1.1\r\nHost: api.shop.example\r\n"
      + "Poppy-Session: aaa.bbb.ccc\r\nPoppy-Session: ddd.eee.fff\r\nConnection: close\r\n\r\n");
    assert.equal(up.seen.length, 1, "the Company did not receive the request");
    const lines = [];
    for (let i = 0; i < up.seen[0].rawHeaders.length; i += 2)
      if (String(up.seen[0].rawHeaders[i]).toLowerCase() === "poppy-session") lines.push(up.seen[0].rawHeaders[i + 1]);
    assert.deepEqual(lines, ["aaa.bbb.ccc", "ddd.eee.fff"],
      "the Company received a different number of Session headers than the agent sent");
    assert.equal(r.records[0].sessionHeaderCount, 2);
    assert.equal(r.records[0].sessionHeaderDuplicated, true);
  } finally { await r.close(); await up.close(); }
});

test("the Host the agent sent reaches the Company, and the record is built from the origin", async () => {
  // Two halves of one rule. The Company must see the Host it would have seen, because its own
  // routing and its own htu comparison depend on it; and the RECORD must use the configured
  // public origin, never Host, because behind any terminator the host a process sees is not the
  // URL the agent signed. README and the protocol guides both say so in those words.
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    await raw(port, "GET /poppy/orders HTTP/1.1\r\nHost: api.shop.example\r\nConnection: close\r\n\r\n");
    assert.equal(up.seen[0].headers.host, "api.shop.example",
      "the recorder rewrote Host, so the Company answered a request the agent never made");
    assert.equal(r.records[0].url, "https://api.shop.example/poppy/orders");
    assert.equal(r.records[0].host, "api.shop.example");
  } finally { await r.close(); await up.close(); }
});

test("an oversize body is forwarded whole and recorded truncated, hashed in full", async () => {
  // The record is capped so a report cannot be filled with somebody's upload; the Company must
  // still receive every byte, or the recorder has changed the request it is judging. A recorder
  // that buffered to the cap and forwarded that would corrupt uploads silently.
  const { createHash } = await import("node:crypto");
  const big = "x".repeat(300_000);
  let upstreamHash = null;
  const up = await upstream((req, res) => {
    const h = createHash("sha256");
    req.on("data", c => h.update(c));
    req.on("end", () => { upstreamHash = h.digest("hex"); res.writeHead(200); res.end("{}"); });
  });
  const r = createRecorder({ ...cfgFor("https://api.shop.example", up.port), maxBodyBytes: 1024 });
  const port = await r.listen(0, "127.0.0.1");
  try {
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`,
      { method: "POST", body: big, headers: { "content-type": "application/json" } });
    await res.body?.cancel();
    assert.equal(upstreamHash, createHash("sha256").update(big).digest("hex"),
      "the Company did not receive the bytes the agent sent");
    const rec = r.records[0];
    assert.equal(rec.bodyTruncated, true);
    // The cap is enforced per whole chunk, which is what the Company does: a chunk that would
    // cross the cap is dropped rather than cut, so with a cap below one chunk nothing is kept.
    // Asserting an exact kept length here would be asserting the socket's chunking.
    assert.ok(rec.body.length <= 1024, `the kept body passed the cap: ${rec.body.length}`);
    assert.equal(rec.bodyBytes, 300_000);
    assert.equal(rec.bodySha256, createHash("sha256").update(big).digest("hex"),
      "the hash must identify the whole body even when the kept copy is cut");
  } finally { await r.close(); await up.close(); }
});

test("`at` is when the request arrived, not when the Company answered", async () => {
  // `session.iat-window` compares the agent's `iat` against this. Stamping it in the upstream
  // response callback would add the Company's own latency to every agent's clock and fail a
  // conforming agent behind a slow Company.
  // Three seconds, not one. At 1500ms a stamp taken in the response callback could still land
  // inside "before + 1" and the mutation that moves it there survived the full run: the guard
  // was passing by luck. The gap has to be wider than the tolerance to prove anything.
  const up = await upstream((req, res) => {
    setTimeout(() => { res.writeHead(200); res.end("{}"); }, 3000);
  });
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    const before = Math.floor(Date.now() / 1000);
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`);
    await res.body?.cancel();
    const after = Math.floor(Date.now() / 1000);
    assert.ok(after - before >= 2, "the upstream did not actually delay, so this proves nothing");
    assert.ok(r.records[0].at <= before + 1,
      `at ${r.records[0].at} looks like the response time, not the arrival time (${before}..${after})`);
  } finally { await r.close(); await up.close(); }
});

test("an unsafe target is forwarded, flagged, and claimed by no rule", async () => {
  // The hosted Company refuses a target with dot segments or a backslash, because it serves one
  // path and classifies another and the two must not disagree. A recorder is not the Company:
  // the builder's Company decides what to do with it. So the request goes through, and the
  // record says plainly that no rule examined it rather than classifying a URL whose meaning
  // the two sides may read differently.
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    await raw(port, "GET /poppy/conversations/../token HTTP/1.1\r\nHost: api.shop.example\r\nConnection: close\r\n\r\n");
    assert.equal(up.seen.length, 1, "the builder's Company must decide this, so it must see it");
    assert.equal(up.seen[0].url, "/poppy/conversations/../token", "the target was rewritten on the way");
    const rec = r.records[0];
    assert.equal(rec.unsafeTarget, true);
    assert.equal(rec.isResource, false, "a target whose meaning is ambiguous must not be judged as a destination");
    assert.equal(rec.rejection, undefined, "nothing refused it, so nothing may claim it was refused");
    assert.match(rec.classifiedAs ?? "", /dot segment|backslash/i,
      "the record must say why no rule examined it");
  } finally { await r.close(); await up.close(); }
});

test("a Company that cannot be reached still leaves the agent's request in the log", async () => {
  // The agent's request is evidence whether or not the Company answered. Losing it would make
  // a dev box with a stopped Company look like an agent that sent nothing.
  const r = createRecorder(cfgFor("https://api.shop.example", 1));   // nothing listens on port 1
  const port = await r.listen(0, "127.0.0.1");
  try {
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`);
    assert.equal(res.status, 502);
    assert.equal((await res.json()).error, "recorder_upstream_unreachable");
    assert.equal(r.records.length, 1, "the request was lost because the Company was down");
    assert.equal(r.records[0].response?.status, 502);
  } finally { await r.close(); }
});

test("the Company's own refusal is recorded as the Company's, never as this grader's", async () => {
  // `rejection` means "this Company refused under rule X" and the report prints it that way.
  // The recorder refuses nothing, so writing an upstream 400 into that field would make a
  // report claim a refusal that never happened here, and credit a rule that never ran.
  const up = await upstream((req, res) => {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid_session", error_description: "no" }));
  });
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`);
    assert.equal(res.status, 400, "the Company's status must reach the agent unchanged");
    await res.body?.cancel();
    const rec = r.records[0];
    assert.equal(rec.response?.status, 400);
    assert.equal(rec.response?.error, "invalid_session",
      "the Company's error code is part of what happened and belongs in the record");
    assert.equal(rec.rejection, undefined, "the recorder claimed a refusal it did not make");
  } finally { await r.close(); await up.close(); }
});

test("the two capture paths agree, field for field, on the same bytes", async () => {
  // THE test in this file. Everything else here proves the recorder is self-consistent, which
  // is not the claim; the claim is that a verdict from a recorded log means what a verdict from
  // a hosted run means. So the same raw request goes to a Company and to a recorder configured
  // with the same origin and the same documents, and every field a check reads must match. Any
  // drift between the two paths, now or later, shows up here rather than in somebody's report.
  const { createGrader } = await import("../server.mjs");
  const up = await upstream();
  const ORIGIN = "https://api.shop.example";
  const common = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
                   apiOperations: operationsToTemplates(DEFAULT_OPERATIONS) };

  const g = createGrader({ ...common });
  const gPort = await g.listen(0);
  const r = createRecorder({ ...common, upstream: `http://127.0.0.1:${up.port}` });
  const rPort = await r.listen(0, "127.0.0.1");

  // A request with everything a rule reads: a destination path, a Session header, a duplicate
  // of another header, a version header, and a body.
  const bytes = (host) =>
    "POST /poppy/orders HTTP/1.1\r\n"
    + `Host: ${host}\r\n`
    + "Poppy-Session: aaa.bbb.ccc\r\n"
    + "Poppy-Version: 1.0\r\n"
    + "Accept: application/json\r\n"
    + "Accept: text/plain\r\n"
    + "Content-Type: application/json\r\n"
    + "Content-Length: 13\r\n"
    + "Connection: close\r\n\r\n"
    + '{"hello":"x"}';
  try {
    await raw(gPort, bytes("api.shop.example"));
    await raw(rPort, bytes("api.shop.example"));
    assert.equal(g.records.length, 1, "the Company recorded nothing");
    assert.equal(r.records.length, 1, "the recorder recorded nothing");
    const a = g.records[0], b = r.records[0];

    const READ_BY_CHECKS = ["method", "url", "path", "host", "body", "bodyComplete",
                            "isResource", "isPage", "mustNotCarry", "misdirected",
                            "sessionHeaderCount", "sessionHeaderDecodable", "sessionHeaderDuplicated"];
    for (const f of READ_BY_CHECKS)
      assert.deepEqual(b[f], a[f], `${f} differs between the Company and the recorder: ${JSON.stringify(a[f])} vs ${JSON.stringify(b[f])}`);
    assert.deepEqual(b.headers, a.headers, "the headers a rule reads differ between the two paths");
    assert.ok(Math.abs(b.at - a.at) <= 1, "the arrival stamps are not comparable");
    // And the fields that SHOULD differ, because only one of them is a Company.
    assert.equal(a.rejection === undefined && b.rejection === undefined, true,
      "neither of these requests was refused, so neither may claim a refusal");
    assert.equal(b.response?.status, 200, "the recorder must record what the Company answered");
  } finally { await r.close(); await g.close(); await up.close(); }
});

test("a record survives the file it is written to", async () => {
  // A recorded run is judged from a file, so every field a check reads has to come back out of
  // JSON the same. A Buffer body, an undefined that disappears, a header object that serialises
  // as null: each of those would make the judged log differ from the recorded one, silently.
  const up = await upstream();
  const ORIGIN = "https://api.shop.example";
  const r = createRecorder({ origin: ORIGIN, discovery: discoveryFor(ORIGIN),
                             apiOperations: operationsToTemplates(DEFAULT_OPERATIONS),
                             upstream: `http://127.0.0.1:${up.port}` });
  const port = await r.listen(0, "127.0.0.1");
  try {
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`,
      { method: "POST", body: '{"a":1}', headers: { "content-type": "application/json", "poppy-session": "aaa.bbb.ccc" } });
    await res.body?.cancel();
    const live = r.records[0];
    const roundTripped = JSON.parse(JSON.stringify(live));
    for (const f of ["method", "url", "path", "host", "body", "bodyComplete", "isResource",
                     "isPage", "mustNotCarry", "sessionHeaderCount", "sessionHeaderDecodable",
                     "sessionHeaderDuplicated", "at", "seq"])
      assert.deepEqual(roundTripped[f], live[f], `${f} did not survive JSON`);
    assert.deepEqual(roundTripped.headers, live.headers, "the headers did not survive JSON");
  } finally { await r.close(); await up.close(); }
});

// ---------------------------------------------------------------------------------------
// The file, and judging from it. A recorded verdict is only worth something if it can be
// produced again from the log without the network, the config, or the process that recorded it.
// ---------------------------------------------------------------------------------------

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("a run written to a file grades exactly as it did in memory", async () => {
  // The point of the file. If a record loses a field on the way out, the judged log is not the
  // recorded log, and nobody would be told: both sides would simply be self-consistent.
  const { openRunFile, appendRecord, readRun } = await import("../recorder.mjs");
  const { grade } = await import("../checks.mjs");
  const up = await upstream();
  const ORIGIN = "https://api.shop.example";
  const cfg = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
                apiOperations: operationsToTemplates(DEFAULT_OPERATIONS),
                upstream: `http://127.0.0.1:${up.port}` };
  const r = createRecorder(cfg);
  const port = await r.listen(0, "127.0.0.1");
  const dir = mkdtempSync(join(tmpdir(), "poppy-rec-"));
  const path = join(dir, "run.jsonl");
  try {
    const file = openRunFile(path, { origin: ORIGIN, ctx: { identifier: `${ORIGIN}/poppy`, domain: "api.shop.example" },
                                     discovery: cfg.discovery, apiOperations: cfg.apiOperations,
                                     graderCommit: "test" });
    const res = await fetch(`http://127.0.0.1:${port}/poppy/orders`,
      { method: "POST", body: '{"a":1}', headers: { "content-type": "application/json", "poppy-session": "aaa.bbb.ccc" } });
    await res.body?.cancel();
    for (const rec of r.records) appendRecord(file, rec);

    const back = readRun(path);
    assert.equal(back.header.origin, ORIGIN);
    assert.deepEqual(back.header.apiOperations, cfg.apiOperations,
      "the header must carry what the log was classified against, or the judge needs the config");
    assert.equal(back.records.length, r.records.length);
    const ctx = { identifier: `${ORIGIN}/poppy`, domain: "api.shop.example" };
    assert.deepEqual(JSON.stringify(grade(back.records, ctx)), JSON.stringify(grade(r.records, ctx)),
      "the log in the file does not grade the same as the log in memory");
    assert.ok(readFileSync(path, "utf8").trim().split("\n").length >= 2, "the file must be a header line plus a record per line");
  } finally { await r.close(); await up.close(); }
});

test("judging one recorded Company abstains on the pairwise rules, with our cause", async () => {
  // Two sentences of 1.0 can only be judged across two Companies. A single recording cannot,
  // and the honest outcome is an abstention that says it is ours, never a pass: a pairwise rule
  // that passed for free would tell a builder their agent keeps User IDs apart when nothing
  // checked.
  const { judge } = await import("../recorder.mjs");
  const ORIGIN = "https://api.shop.example";
  const { report } = judge([{ header: { origin: ORIGIN, ctx: { identifier: `${ORIGIN}/poppy`, domain: "api.shop.example" } },
                              records: [] }], { graderCommit: "test" });
  assert.equal(report.pairwise.length, 2, "both pairwise rules must appear in a one-Company report");
  for (const v of report.pairwise) {
    assert.notEqual(v.verdict, "PASS", `${v.id} passed without a second Company`);
    assert.equal(v.cause, "grader", `${v.id} blamed the agent for something this grader could not do`);
  }
  assert.equal(report.mode, "recorded", "a report judged from a file must say what kind of run it was");
});

test("two recordings of the same Company become one log, and of two become a pair", async () => {
  // A builder whose documents are on the apex and whose API is on another host records both and
  // judges them together: 3.2 says several domains with one issuer ARE one Company, so their
  // logs belong to one Session and `session.not-on-documents` can only be judged across both.
  // Two different identifiers are two Companies, which is what the pairwise rules need.
  const { judge } = await import("../recorder.mjs");
  const one = { identifier: "https://shop.example/poppy", domain: "shop.example" };
  const other = { identifier: "https://other.example/poppy", domain: "other.example" };
  const mk = (ctx, n) => ({ header: { origin: `https://${ctx.domain}`, ctx },
                            records: Array.from({ length: n }, (_, i) => ({ seq: i + 1, at: i, method: "GET", url: `https://${ctx.domain}/poppy/orders`, headers: {}, isResource: true })) });

  const merged = judge([mk(one, 2), mk(one, 3)], { graderCommit: "test" });
  assert.equal(merged.run.companies.length, 1, "one issuer is one Company (3.2)");
  assert.equal(merged.run.companies[0].log.length, 5, "the two logs of one Company were not joined");

  const pair = judge([mk(one, 2), mk(other, 2)], { graderCommit: "test" });
  assert.equal(pair.run.companies.length, 2);
  assert.ok(pair.report.pairwise.every(v => v.cause !== "grader"),
    "with two Companies the pairwise rules must actually be judged");

  assert.throws(() => judge([mk(one, 1), mk(other, 1), mk({ identifier: "https://third.example/poppy", domain: "third.example" }, 1)], { graderCommit: "test" }),
    /two/i, "three Companies must be refused rather than silently reduced to two");
});

test("a recorder in front of an origin nothing is listed on refuses to start", async () => {
  // The failure that reads as success. If the configured origin is not the origin the Company's
  // own document lists, every request classifies as "not a Session destination", every rule
  // abstains as unreached, and the report says nothing failed. A builder would read that as a
  // pass. Same reasoning as the hosted Company's own config check and as the canary's reach
  // leg: a grader that cannot see anything must say so instead of grading.
  const elsewhere = discoveryFor("https://api.shop.example");
  assert.throws(
    () => createRecorder({ origin: "https://nothing-here.example", upstream: "http://127.0.0.1:1",
                           discovery: elsewhere, apiOperations: [] }),
    /nothing .*is listed on|no destination/i,
    "a recorder whose origin matches nothing in the document started anyway");
});

test("destinations on other origins are a warning, not a refusal", async () => {
  // A Company whose conversations live at a partner and whose API is here is an ordinary layout
  // the guides describe. The recorder sees only what reaches it, so the honest thing is to say
  // which listed destinations it will never examine, and carry on.
  const d = discoveryFor("https://api.shop.example");
  d.agent.protocols[0].endpoint = "https://partner.example/conversations";
  const r = createRecorder({ origin: "https://api.shop.example", upstream: "http://127.0.0.1:1",
                             discovery: d, apiOperations: operationsToTemplates(DEFAULT_OPERATIONS) });
  try {
    assert.ok(r.warnings.some(w => /partner\.example/.test(w) && /examined by no rule/.test(w)),
      `the recorder did not warn about a destination it cannot see: ${JSON.stringify(r.warnings)}`);
  } finally { await r.close(); }
});

test("a request Node refuses before the handler runs is still in the recorded log", async () => {
  // The hosted Company keeps these rows, and its header comment makes a promise of it: a request
  // nothing recorded is a request no rule examined. The recorder had no clientError listener, so
  // a malformed request was answered by Node and vanished, and a recorded log quietly held less
  // than a hosted one. That is the difference between a log and a selection.
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    await raw(port, "GET /poppy/orders HTTP/1.1\r\nHost: api.shop.example\r\nBad Header: x\r\n\r\n");
    const rejected = r.records.filter(x => x.rejected);
    assert.equal(rejected.length, 1, `the malformed request is not in the log: ${JSON.stringify(r.records)}`);
    assert.match(String(rejected[0].code), /HPE|UNKNOWN/, "the row must say why Node refused it");
  } finally { await r.close(); await up.close(); }
});

test("a stream the client abandoned is still written to the log", async () => {
  // A response that is torn down never emits `finish`, only `close`, so a recorder that wrote
  // its records on `finish` would lose every long poll an agent ever opened. Asserted without
  // calling flush, because flush emits everything regardless and would hide exactly this.
  const up = await upstream((req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("event: ping\n\n");            // and never ends
  });
  const written = [];
  const r = createRecorder({ ...cfgFor("https://api.shop.example", up.port),
                             onRecord: (rec) => written.push(rec) });
  const port = await r.listen(0, "127.0.0.1");
  try {
    const ac = new AbortController();
    const stream = fetch(`http://127.0.0.1:${port}/poppy/conversations/c_1/events?wait=30`,
                         { signal: ac.signal }).catch(() => {});
    await new Promise(done => setTimeout(done, 300));
    ac.abort();
    await stream;
    await new Promise(done => setTimeout(done, 300));
    assert.equal(written.length, 1,
      `a streamed request the client abandoned was never written: ${JSON.stringify(written)}`);
    assert.match(String(written[0].path), /events/);
  } finally { await r.close(); await up.close(); }
});

test("the recorder stops while a stream is still open", async () => {
  // Node's server.close() waits for live connections, so an agent holding a long poll on the
  // events route of 8.6 kept the recorder alive for ever: the documented Ctrl-C hung, a second
  // Ctrl-C was swallowed, and the builder lost the report. The client is deliberately NOT
  // aborted here: with no live connection, close() resolves on its own and this would pass
  // whether or not the fix is present, which a mutation proved.
  const up = await upstream((req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("event: ping\n\n");
  });
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  const ac = new AbortController();
  const stream = fetch(`http://127.0.0.1:${port}/poppy/conversations/c_1/events?wait=30`,
                       { signal: ac.signal }).catch(() => {});
  await new Promise(done => setTimeout(done, 300));
  const closed = await Promise.race([
    r.close().then(() => "closed"),
    new Promise(done => setTimeout(() => done("still open"), 3000)),
  ]);
  ac.abort();
  await stream;
  await up.close();
  assert.equal(closed, "closed", "the recorder could not be stopped while a stream was open");
});
test("a body that never finishes is recorded as incomplete, and is written to the log", async () => {
  // Two guards a review found unprotected: marking every body complete broke no test, and
  // emitting a record on `finish` instead of `close` meant an aborted exchange was never
  // written to the file at all. An agent that resets a connection is exactly the case a log has
  // to keep, because its record is evidence and its absence looks like a request never sent.
  const up = await upstream();
  const written = [];
  const r = createRecorder({ ...cfgFor("https://api.shop.example", up.port), onRecord: (rec) => written.push(rec) });
  const port = await r.listen(0, "127.0.0.1");
  try {
    await new Promise((resolve) => {
      const s = connect(port, "127.0.0.1", () => {
        s.write("POST /poppy/orders HTTP/1.1\r\nHost: api.shop.example\r\n"
          + "content-type: application/json\r\ncontent-length: 40\r\n\r\n" + '{"mes');
        setTimeout(() => { s.destroy(); resolve(); }, 150);
      });
      s.on("error", () => resolve());
    });
    await new Promise(done => setTimeout(done, 200));
    // A destroyed connection can also leave a parser row, which is a second legitimate record
    // and not a duplicate: one is the request, the other is what Node refused afterwards.
    const requests = r.records.filter(x => !x.rejected);
    assert.equal(requests.length, 1, `the request was not recorded: ${JSON.stringify(r.records)}`);
    assert.equal(requests[0].bodyComplete, false, "a body that never arrived was marked complete");
    assert.ok(written.some(x => x === requests[0]),
      "the incomplete record was never written to the log, so the file holds less than the run");
  } finally { await r.close(); await up.close(); }
});

test("hop by hop headers are the proxy's own and do not reach the Company", async () => {
  // RFC 9110 7.6.1. Forwarding them unchanged broke no test, and passing a client's
  // `proxy-connection` or its `transfer-encoding` straight through makes the recorder lie to the
  // Company about how the body is framed.
  const up = await upstream();
  const r = createRecorder(cfgFor("https://api.shop.example", up.port));
  const port = await r.listen(0, "127.0.0.1");
  try {
    await raw(port, "GET /poppy/orders HTTP/1.1\r\nHost: api.shop.example\r\n"
      + "Proxy-Connection: keep-alive\r\nPoppy-Version: 1.0\r\nConnection: close\r\n\r\n");
    assert.equal(up.seen.length, 1);
    assert.equal(up.seen[0].headers["proxy-connection"], undefined,
      "a hop by hop header reached the Company");
    assert.equal(up.seen[0].headers["poppy-version"], "1.0",
      "an end to end header was dropped, so the Company saw a different request");
  } finally { await r.close(); await up.close(); }
});
