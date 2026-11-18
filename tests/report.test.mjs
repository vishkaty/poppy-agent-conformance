// The report is the only thing a stranger reads, so its failure modes are different from
// the checks'. The two that matter: it leaks one of the agent's secrets while reporting on
// it, or it makes an INCONCLUSIVE read as a failure and a builder fixes something that was
// never broken.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHECKS, PAIRWISE } from "../checks.mjs";
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
