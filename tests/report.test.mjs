// The report is the only thing a stranger reads, so its failure modes are different from
// the checks'. The two that matter: it leaks one of the agent's secrets while reporting on
// it, or it makes an INCONCLUSIVE read as a failure and a builder fixes something that was
// never broken.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHECKS, PAIRWISE, grade } from "../checks.mjs";
import { buildReport, renderHtml, REACH, anchorFor } from "../report.mjs";
import * as f from "./fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CTX_A = { identifier: "https://shop.example/poppy", domain: "shop.example" };
const CTX_B = { identifier: "https://other-shop.example/poppy", domain: "other-shop.example" };
const keys = await f.agentKeys();

// Every secret gets a unique sentinel, so a leak names itself.
const SENTINELS = {
  token: "SENTINEL-ACCESS-TOKEN-aaaaaaaa",
  cookie: "SENTINEL-COOKIE-bbbbbbbb",
  body: "SENTINEL-BODY-cccccccc",
  query: "SENTINEL-QUERY-dddddddd",
  header: "SENTINEL-UNKNOWN-HEADER-eeeeeeee",
  ip: "203.0.113.77",
};

async function runWithSecrets() {
  const log = await f.conformingLog(keys);
  const leaky = await f.request(keys, {
    path: "/poppy/orders", token: SENTINELS.token, ath: f.athOf(SENTINELS.token),
  });
  leaky.url += `?cursor=${SENTINELS.query}`;
  leaky.headers.cookie = `s=${SENTINELS.cookie}`;
  leaky.headers["x-secret"] = SENTINELS.header;
  leaky.body = JSON.stringify({ note: SENTINELS.body });
  leaky.remoteAddress = SENTINELS.ip;
  // A genuine FAIL, so the tests about the shape of a FAIL block have one to inspect. An
  // htu naming the other Company is the mistake a two-host run most plausibly produces.
  const wrong = await f.request(keys, { path: "/poppy/orders", htu: "https://other-shop.example/poppy/orders" });
  return {
    token: "tok_report_test", started: 1763412063, ended: 1763412230, frozen: true,
    companies: [{ ctx: CTX_A, log: [...log, leaky, wrong] }, { ctx: CTX_B, log: [] }],
    warnings: [], graderCommit: "abc1234",
  };
}

test("no secret appears anywhere in the HTML or the JSON", async () => {
  const report = buildReport(await runWithSecrets());
  const html = renderHtml(report);
  const json = JSON.stringify(report);
  for (const [what, value] of Object.entries(SENTINELS)) {
    assert.ok(!html.includes(value), `the HTML leaks ${what}`);
    assert.ok(!json.includes(value), `the JSON leaks ${what}`);
  }
  // and no compact JWT at all: a JWS is three base64url parts, and showing one would let
  // the page replay or re-sign a request
  assert.ok(!/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(html), "the HTML contains a compact JWT");
  assert.ok(!/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(json), "the JSON contains a compact JWT");
});

test("a private key member is named but never shown", async () => {
  const { exportJWK } = await import("jose");
  const priv = await exportJWK(keys.delegated.privateKey);
  const r = await f.request(keys, { dlgCompact: await f.delegation(keys, { payload: { cnf: { jwk: priv } } }) });
  const html = renderHtml(buildReport({
    token: "t", started: 1, ended: 2, frozen: true, warnings: [], graderCommit: "x",
    companies: [{ ctx: CTX_A, log: [r] }, { ctx: CTX_B, log: [] }],
  }));
  assert.ok(html.includes("private member"), "the report does not say a private member was present");
  assert.ok(!html.includes(priv.d), "the report leaks the private key member it is reporting");
});

test("the top sentence counts match the verdicts", async () => {
  const report = buildReport(await runWithSecrets());
  const n = v => report.rules.filter(r => r.worst === v).length + report.pairwise.filter(r => r.verdict === v).length;
  assert.ok(report.summary.fail === n("FAIL"), `summary says ${report.summary.fail} FAIL, verdicts say ${n("FAIL")}`);
  assert.ok(report.topSentence.includes(`failed ${report.summary.fail}`), report.topSentence);
  assert.ok(report.topSentence.includes(`passed ${report.summary.pass}`), report.topSentence);
});

test("an empty run says so, and claims nothing", () => {
  const report = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [], graderCommit: "x",
                               companies: [{ ctx: CTX_A, log: [] }, { ctx: CTX_B, log: [] }] });
  assert.equal(report.topSentence, "No request reached the grader during this run, so no rule was judged.");
  assert.equal(report.summary.fail, 0);
});

test("FAIL blocks come before NOT REACHED, which come before PASS", async () => {
  const report = buildReport(await runWithSecrets());
  const html = renderHtml(report);
  const iFail = html.indexOf('data-verdict="FAIL"');
  const iSkip = html.indexOf('data-verdict="INCONCLUSIVE"');
  const iPass = html.indexOf('data-verdict="PASS"');
  assert.ok(iFail >= 0 && iSkip >= 0 && iPass >= 0, "all three groups must render");
  assert.ok(iFail < iSkip, "a builder arrives asking what to fix");
  assert.ok(iSkip < iPass, "nothing follows from a PASS");
});

test("an abstention never reads as a failure", async () => {
  const report = buildReport(await runWithSecrets());
  const html = renderHtml(report);
  for (const m of html.matchAll(/data-verdict="INCONCLUSIVE"[\s\S]*?<\/section>/g)) {
    const block = m[0].replace(/<blockquote>[\s\S]*?<\/blockquote>/g, "");   // the quoted spec may say it
    assert.ok(!/fail/i.test(block), `an abstention block contains the word fail: ${block.slice(0, 160)}`);
  }
  assert.ok(html.includes("Not reached by your agent") || html.includes("Not judged by this grader"),
    "the two abstention causes must be labelled differently");
});

test("REACH covers every rule exactly, and says what to do", () => {
  const ids = [...CHECKS, ...PAIRWISE].map(c => c.id);
  assert.deepEqual(ids.filter(i => !REACH[i]), [], "rules with no guidance for reaching them");
  assert.deepEqual(Object.keys(REACH).filter(i => !ids.includes(i)), [], "guidance for rules that do not exist");
  for (const [id, r] of Object.entries(REACH))
    assert.ok(typeof r.how === "string" && r.how.length > 30, `${id} has no usable sentence`);
  assert.equal(REACH["session.ath"].reachable, false,
    "this grader issues no access tokens, so the report must say the rule is not reachable here");
});

test("every FAIL names its rule, quotes it, links it and shows the request that decided it", async () => {
  const report = buildReport(await runWithSecrets());
  const fails = report.rules.flatMap(r => r.perCompany.filter(c => c.verdict === "FAIL").map(c => ({ r, c })));
  assert.ok(fails.length > 0, "this fixture must produce at least one FAIL or this test proves nothing");
  for (const { r, c } of fails) {
    assert.equal(r.quote, CHECKS.find(x => x.id === r.id).quote, `${r.id} quote drifted from the check`);
    assert.ok(r.section, `${r.id} has no section`);
    assert.ok(anchorFor(r.section), `${r.id} section ${r.section} has no anchor in the capture`);
    assert.ok(c.why && c.why.length > 10, `${r.id} FAIL has no sentence`);
    assert.ok(c.decidedBy.length > 0, `${r.id} FAIL shows no deciding request`);
    for (const ord of c.decidedBy)
      assert.ok(report.requests.some(q => q.ordinal === ord), `${r.id} cites request #${ord}, which is not in the index`);
  }
});

test("every recorded request appears once in the index, and unexamined ones say so", async () => {
  const run = await runWithSecrets();
  const report = buildReport(run);
  const total = run.companies.reduce((n, c) => n + c.log.length, 0);
  assert.equal(report.requests.length, total, "the index must hold every request exactly once");
  const ords = report.requests.map(r => r.ordinal);
  assert.equal(new Set(ords).size, ords.length, "ordinals must be unique");
  for (const q of report.requests.filter(x => !x.isResource && !x.mustNotCarry && !x.isPage))
    assert.ok(/examined by no rule/.test(q.note ?? ""), `request #${q.ordinal} is unexamined and does not say so`);
});

test("the report says what it judged against and what it cannot judge", async () => {
  const report = buildReport(await runWithSecrets());
  const about = JSON.stringify(report.about);
  for (const needed of ["1.0", "2026-11-14", "jwks_uri", "keyed hash", "examined by no rule"])
    assert.ok(about.includes(needed), `the About section does not mention ${needed}`);
  assert.ok(/not a statement that your agent conforms/i.test(about),
    "the report must say a PASS is not conformance of the whole agent");
});

test("the HTML is self contained and escapes what the agent controls", async () => {
  const run = await runWithSecrets();
  run.companies[0].log[1].headers["user-agent"] = '<script>alert(1)</script>';
  const html = renderHtml(buildReport(run));
  for (const forbidden of ["<script", " src=", "url(", "@import"])
    assert.ok(!html.includes(forbidden), `the HTML is not self contained: it has ${forbidden}`);
  assert.ok(!html.includes("<script>alert(1)"), "an agent-controlled value was not escaped");
  for (const m of html.matchAll(/href="([^"]+)"/g))
    assert.ok(m[1].startsWith("https://personalagentprotocol.org/"), `a link leaves the spec origin: ${m[1]}`);
});

test("traffic at one Company only reports both pairwise rules as not reached, naming the host", async () => {
  const report = buildReport(await runWithSecrets());
  for (const p of report.pairwise) {
    assert.equal(p.verdict, "INCONCLUSIVE", `${p.id} judged a one-sided run`);
    assert.ok(p.why.includes("other-shop.example") || p.reach.how.includes("other-shop.example"),
      `${p.id} does not name the Company that saw nothing`);
  }
});

test("a frozen run renders identically twice", async () => {
  const run = await runWithSecrets();
  assert.equal(renderHtml(buildReport(run)), renderHtml(buildReport(run)),
    "a report a builder saves must not change under them");
});

test("the control: traffic from the authors' signing code renders no FAIL", async () => {
  const ref = await import("../reference/jose.ts");
  const operator = await ref.generateKey(), key = await ref.generateKey();
  const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk, iss: f.CLIENT_ID });
  const sid = ref.randomId(16), sub = ref.randomId(16);
  const mk = async path => {
    const url = `https://shop.example${path}`;
    return { host: "shop.example", method: "GET", path, url, at: ref.nowSeconds(),
             isResource: true, isPage: false, mustNotCarry: false, body: null,
             sessionHeaderCount: 1, sessionHeaderDecodable: true, sessionHeaderDuplicated: false,
             headers: { "poppy-session": await ref.signSessionJwt({
               key, delegation, iss: f.CLIENT_ID, aud: CTX_A.identifier, sid, sub,
               method: "GET", url }), "poppy-version": "1.0" } };
  };
  const report = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [], graderCommit: "x",
    companies: [{ ctx: CTX_A, log: [await mk("/poppy/orders"), await mk("/poppy/orders/1")] },
                { ctx: CTX_B, log: [] }] });
  const fails = report.rules.flatMap(r => r.perCompany.filter(c => c.verdict === "FAIL").map(c => `${r.id}: ${c.why}`));
  assert.deepEqual(fails, [], "the report shows a FAIL against traffic built by the authors' own code");
});

test("a FAIL names the requests that breached, not every request in the Session", async () => {
  // The authors' own validator exposed this against the live grader. It sends one deliberately
  // over-long delegation among 29 otherwise conforming requests, and the report said the
  // failure was "decided by" all 29. A builder would have gone looking at 28 requests that
  // were fine. A failure a builder cannot trace to the right request is worse than a vague
  // one, because it sends them somewhere with confidence.
  const keys = await f.agentKeys();
  const iat = Math.floor(Date.now() / 1000);
  const ok = [await f.request(keys, {}), await f.request(keys, {}), await f.request(keys, {})];

  const cases = [
    ["delegation.exp-24h", await f.request(keys, { dlg: { iat, exp: iat + 25 * 3600 } })],
    ["delegation.no-identifiers", await f.request(keys, { sub: "user-leaked",
        dlg: { payload: { extra: "user-leaked" } } })],
  ];
  for (const [id, breach] of cases) {
    const log = [...ok, breach];
    const v = grade(log, f.ctx).find(x => x.id === id);
    assert.equal(v.verdict, "FAIL", `${id} did not fail the breach: ${v.why}`);
    assert.deepEqual(v.decidedBy, [breach],
      `${id} named ${v.decidedBy.length} of ${log.length} requests as deciding it`);
  }
});

test("a FAIL about a Session names that Session's requests and no others", async () => {
  // The same defect in the form it takes for a rule about a whole Session rather than one
  // request: the breach belongs to one Session ID, and the other Session's requests did
  // nothing wrong.
  const keys = await f.agentKeys();
  const good = "sid-stable", bad = "sid-changes";
  const log = [
    await f.request(keys, { sid: good, sub: "user-a" }),
    await f.request(keys, { sid: good, sub: "user-a" }),
    await f.request(keys, { sid: bad, sub: "user-b" }),
    await f.request(keys, { sid: bad, sub: "user-c" }),      // sub changed within one Session
  ];
  const v = grade(log, f.ctx).find(x => x.id === "session.sub-stable");
  assert.equal(v.verdict, "FAIL", v.why);
  assert.deepEqual(v.decidedBy, [log[2], log[3]],
    "the failure named requests from the Session that did nothing wrong");
});

test("a replayed jti names the requests that share it", async () => {
  const keys = await f.agentKeys();
  const jti = "reused-" + Math.random().toString(36).slice(2);
  const log = [
    await f.request(keys, {}),
    await f.request(keys, { jti, path: "/poppy/orders" }),
    await f.request(keys, {}),
    await f.request(keys, { jti, path: "/poppy/invoices" }),   // same jti, different request
  ];
  const v = grade(log, f.ctx).find(x => x.id === "session.jti-unique");
  assert.equal(v.verdict, "FAIL", v.why);
  assert.deepEqual(v.decidedBy, [log[1], log[3]],
    "the replay named requests that carried a different jti");
});

test("a version change names the requests where it changed, not the whole Session", async () => {
  // Against the live grader this named 29 of 37 requests. The Session really did carry three
  // values, so it was not wrong, but a builder reading "decided by" 29 requests has to find
  // the change themselves, which is the work the report exists to do.
  const keys = await f.agentKeys();
  const sid = "sid-one";
  const log = [
    await f.request(keys, { sid, version: "1.0" }),
    await f.request(keys, { sid, version: "1.0" }),
    await f.request(keys, { sid, version: "1.0" }),
    await f.request(keys, { sid, version: "0.9" }),      // here
    await f.request(keys, { sid, version: "0.9" }),
    await f.request(keys, { sid, version: null }),        // and here
  ];
  const v = grade(log, f.ctx).find(x => x.id === "version.constant");
  assert.equal(v.verdict, "FAIL", v.why);
  assert.deepEqual(v.decidedBy, [log[0], log[3], log[5]],
    "the failure did not point at the first request carrying each different value");
});

test("the report identifies the oracle by its content, not by the archive it arrived in", async () => {
  // Measured: three downloads of the kit an hour apart produced three different zip sha256
  // values over byte-identical content, proven by digesting all 96 files of two of them. So
  // the zip hash is packaging, and a report citing it as the oracle's provenance would make
  // two runs of identical code appear to cite different oracles. The identity has to be a
  // digest of the files we actually use, computed from the files on disk so it is verified
  // rather than asserted.
  const { createHash } = await import("node:crypto");
  const { readFileSync, readdirSync } = await import("node:fs");
  const rep = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [],
                            graderCommit: "x",
                            companies: [{ ctx: CTX_A, log: [] }, { ctx: CTX_B, log: [] }] });

  assert.ok(rep.grader.oracle, "the report does not identify the oracle at all");
  assert.match(rep.grader.oracle.digest, /^[0-9a-f]{16,64}$/);
  assert.ok(rep.grader.oracle.files >= 3, `only ${rep.grader.oracle.files} oracle files named`);

  // recompute it from the files themselves
  const dir = join(HERE, "../reference");
  const prov = JSON.parse(readFileSync(join(dir, "PROVENANCE.json"), "utf8"));
  const lines = Object.keys(prov.files).sort()
    .map(n => `${n}:${createHash("sha256").update(readFileSync(join(dir, n))).digest("hex")}`);
  const want = createHash("sha256").update(lines.join("\n")).digest("hex");
  assert.equal(rep.grader.oracle.digest, want.slice(0, rep.grader.oracle.digest.length),
    "the oracle digest in the report is not a digest of the vendored files on disk");

  // and the unstable value must not be presented as the oracle's identity
  const text = JSON.stringify(rep) + renderHtml(rep);
  assert.ok(!text.includes(prov.kit_zip_sha256),
    "the report still cites the kit zip hash, which is not stable across downloads");
});

test("the vendored provenance says plainly that the zip hash is not a content identifier", () => {
  // Otherwise the next person to compare two kit downloads concludes the oracle changed.
  const prov = JSON.parse(readFileSync(join(HERE, "../reference/PROVENANCE.json"), "utf8"));
  const note = JSON.stringify(prov).toLowerCase();
  assert.match(note, /not a content identifier|packaging|differs between downloads/,
    "nothing in the provenance warns that the zip hash changes without the content changing");
});

test("the page carries the same provenance as the data", async () => {
  // Two outputs of one pure function, and the page is the one a builder actually reads. The
  // oracle digest reached the JSON and not the page, so only a reader of the data could tell
  // which code judged them.
  const rep = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [],
                            graderCommit: "abc123def456",
                            companies: [{ ctx: CTX_A, log: [] }, { ctx: CTX_B, log: [] }] });
  const html = renderHtml(rep);
  for (const [what, value] of [["the grader commit", rep.grader.commit],
                               ["the oracle digest", rep.grader.oracle.digest],
                               ["the grader clock", rep.grader.clock],
                               ["the specification version", rep.spec.version]])
    assert.ok(html.includes(String(value)), `the page does not carry ${what} (${value})`);
});

test("when a rejection ended the run, the report says so instead of blaming the agent", async () => {
  // Enforcement introduced a way for this report to lie. Section 7 tells an agent that gets
  // invalid_session to stop sending the request until it fixes the cause, so a run can end at
  // its first request. Every rule after that is unreached, and the advice beside an unreached
  // rule says "drive your agent so that it sends a Session header on a listed destination",
  // which the builder DID: we refused it. The report has to attribute that.
  const keys = await f.agentKeys();
  const bad = await f.request(keys, { noDlg: true });
  bad.response = { status: 400, error: "invalid_session" };
  bad.rejection = { rule: "delegation.present", error: "invalid_session" };

  const rep = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [],
                            graderCommit: "x",
                            companies: [{ ctx: CTX_A, log: [bad] }, { ctx: CTX_B, log: [] }] });

  assert.equal(rep.summary.rejected, 1, "the report does not count what this Company refused");
  assert.ok(rep.about.stopped, "the report does not say the run ended in a rejection");
  assert.match(rep.about.stopped, /delegation\.present/, rep.about.stopped);
  assert.match(rep.about.stopped, /nothing followed|stopped there/i, rep.about.stopped);

  // and the unreached rules carry that sentence rather than advice the builder already followed
  const unreached = rep.rules.filter(r => r.worst === "INCONCLUSIVE" && r.reach);
  assert.ok(unreached.length > 0, "nothing was unreached, so this proves nothing");
  const reachable = unreached.filter(r => r.reach.reachable !== false);
  const ours = unreached.filter(r => r.reach.reachable === false);
  assert.ok(reachable.length > 0 && ours.length > 0,
    "this test needs both a rule the builder could have reached and one this grader cannot offer");
  for (const r of reachable)
    assert.match(r.reach.how, /refused|rejected|stopped/i,
      `${r.id} still advises the builder to do what we refused: ${r.reach.how}`);
  // A rule this grader cannot offer at all keeps its own note: that is our limit, not a
  // consequence of the refusal, and overwriting it would blame the refusal for our gap.
  for (const r of ours)
    assert.ok(!/stopped your agent there/.test(r.reach.how),
      `${r.id} is our own limit and was blamed on the refusal: ${r.reach.how}`);

  const html = renderHtml(rep);
  assert.match(html, /delegation\.present/);
});

test("a run that was not stopped by a rejection keeps the ordinary advice", async () => {
  // The control. Without it the change above could blanket every report with an excuse.
  const keys = await f.agentKeys();
  const ok = await f.request(keys, {});
  ok.response = { status: 200, error: null };
  const rep = buildReport({ token: "t", started: 1, ended: 2, frozen: true, warnings: [],
                            graderCommit: "x",
                            companies: [{ ctx: CTX_A, log: [ok] }, { ctx: CTX_B, log: [] }] });
  assert.equal(rep.summary.rejected, 0);
  assert.equal(rep.about.stopped, null);
  const unreached = rep.rules.filter(r => r.worst === "INCONCLUSIVE" && r.reach);
  assert.ok(unreached.length > 0);
  assert.ok(unreached.every(r => !/refused|rejected|stopped/i.test(r.reach.how)),
    "a run nobody refused was told it had been stopped");
});
