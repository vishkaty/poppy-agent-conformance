// Versions, and what a 1.0 instrument may say about traffic that is not 1.0.
//
// A Company may serve several versions at once (3.4): `poppy.json` is the document for the
// version it prefers and `supported_versions` maps each other version it serves to that
// version's document. The rule that reads `Poppy-Version` compared the declared version
// against the preferred one ALONE and compared majors only, so it faulted a conforming 0.4
// agent at a host that serves 0.4, and passed a 0.3 agent at a host that serves only 0.4.
//
// The compatibility sentence is spec/spec.md:272, verbatim: "Two versions are compatible when
// they have the same major version and, before 1.0, the same minor version."
import { test } from "node:test";
import assert from "node:assert/strict";
import { compatible, contextOf } from "../discovery.mjs";
import { CHECKS } from "../checks.mjs";
import * as f from "./fixture.mjs";

const rule = (id) => CHECKS.find(c => c.id === id);

test("3.4 compatibility is the same major, and before 1.0 the same minor", () => {
  for (const [a, b] of [["1.0", "1.0"], ["1.0", "1.7"], ["1.7", "1.0"], ["0.4", "0.4"], ["2.0", "2.0"]])
    assert.equal(compatible(a, b), true, `${a} and ${b} have the same major at or after 1.0`);
  // Before 1.0 the minor must match too, which is why a Company can serve 0.3 beside 0.4 as
  // separate documents: they are not compatible with each other.
  for (const [a, b] of [["0.3", "0.4"], ["0.4", "0.3"], ["0.1", "0.2"]])
    assert.equal(compatible(a, b), false, `${a} and ${b} are both before 1.0 with different minors`);
  for (const [a, b] of [["0.4", "1.0"], ["1.0", "2.0"], ["1.0", "0.4"]])
    assert.equal(compatible(a, b), false, `${a} and ${b} differ in major`);
  // 3.4 and 3.1 both say `major.minor`, and the authors' own schema constrains both the
  // document's version and the keys of supported_versions to exactly that shape.
  for (const bad of ["1", "1.0.0", "v1.0", "", "1.x", "x.y", null, undefined, {}, "1.0 "])
    assert.equal(compatible(bad, "1.0"), false, `${JSON.stringify(bad)} is not major.minor`);
});

test("the served set is the preferred version plus every version listed beside it", () => {
  const ctx = contextOf({ protocol_version: "1.0",
                          supported_versions: { "0.4": "https://shop.example/poppy/0.4.json",
                                                "0.3": "https://shop.example/poppy/0.3.json" },
                          organization: { domain: "shop.example" },
                          auth: { issuer: "https://shop.example/poppy" } });
  assert.deepEqual([...ctx.servedVersions].sort(), ["0.3", "0.4", "1.0"]);
  // A Company that serves one version says so with no supported_versions at all.
  assert.deepEqual(contextOf({ protocol_version: "1.0" }).servedVersions, ["1.0"]);
  // Nothing known is NOT the same as 1.0, and a rule must be able to tell the difference.
  assert.deepEqual(contextOf({}).servedVersions, []);
});

const sessionAt = async (keys, version) =>
  [await f.request(keys, { version, sub: "user-one", seq: 1 })];

test("a conforming 0.4 agent is not faulted at a host that serves 0.4", async () => {
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0", "0.4", "0.3"], protocolVersion: "1.0" };
  const v = rule("version.sent").run(await sessionAt(keys, "0.4"), serves);
  assert.notEqual(v.verdict, "FAIL", `0.4 is one of the versions this Company serves: ${v.why}`);
});

test("a 0.3 agent IS faulted at a host that serves only 0.4, because 3.4 makes them incompatible", async () => {
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["0.4"], protocolVersion: "0.4" };
  const v = rule("version.sent").run(await sessionAt(keys, "0.3"), serves);
  assert.equal(v.verdict, "FAIL", "0.3 and 0.4 are both before 1.0 and differ in minor");
});

test("a host serving 1.0 alone still faults 0.4, which is the control", async () => {
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0"], protocolVersion: "1.0" };
  assert.equal(rule("version.sent").run(await sessionAt(keys, "0.4"), serves).verdict, "FAIL");
  assert.equal(rule("version.sent").run(await sessionAt(keys, "1.7"), serves).verdict, "PASS",
    "a later minor version of the same major is compatible");
});

test("with no served version known, the rule abstains as OUR limit rather than assuming 1.0", async () => {
  const keys = await f.agentKeys();
  // It used to read `ctx?.protocolVersion ?? "1.0"`, so an unconfigured recorder silently
  // judged every agent against a version nobody had told it the Company serves. A guess that
  // produces a verdict is the one thing this grader does not do.
  const v = rule("version.sent").run(await sessionAt(keys, "1.0"), { ...f.ctx, servedVersions: [], protocolVersion: undefined });
  assert.equal(v.verdict, "INCONCLUSIVE");
  assert.equal(v.cause, "grader", "the gap is in what this grader was told, not in what the agent did");
});

test("a log recorded before the served set existed judges exactly like one recorded after", async () => {
  // `judge` rebuilds the context from the Company's own document in the log header rather than
  // trusting the context stored beside it. Without that, every run captured before this change
  // would abstain on every version rule, because its stored context has no served set. The
  // document is in the log, so this costs no network and no configuration.
  const { judge } = await import("../recorder.mjs");
  const keys = await f.agentKeys();
  const discovery = { protocol_version: "1.0",
                      supported_versions: { "0.4": "https://shop.example/poppy/0.4.json" },
                      organization: { domain: "shop.example" },
                      auth: { issuer: "https://shop.example/poppy", disabled: true } };
  const run = {
    header: { kind: "poppy-recorded-run", version: 1, origin: "https://shop.example",
              discovery,
              // the shape a recorder wrote before `servedVersions` was a field at all
              ctx: { identifier: "https://shop.example/poppy", domain: "shop.example",
                     protocolVersion: "1.0", authDisabled: true, extensions: [] } },
    // A 1.0 request, deliberately. A 0.4 one would be OUT OF SCOPE at this Company once the
    // partition exists, so it abstains either way and could not tell the two cases apart. With
    // the served set recovered from the document this passes; without it the rule abstains with
    // cause grader because it was told no version at all.
    records: [await f.request(keys, { version: "1.0", sub: "user-one", seq: 1 })],
  };
  const { report } = judge([run], { graderCommit: "test" });
  const v = report.rules.find(r => r.id === "version.sent");
  // `worst`, not `verdict`: a per rule entry in a report carries perCompany and worst, and the
  // first version of this test asserted on `v.verdict`, which does not exist there. Comparing
  // undefined against "INCONCLUSIVE" passes, so the test passed while the fix it was written for
  // had not even been applied. Assert on the field that exists, and on the cause beside it.
  assert.equal(v.worst, "PASS",
    `0.4 is listed in this Company's own supported_versions, so a 0.4 agent conforms here: ${JSON.stringify(v.perCompany)}`);
  assert.equal(v.perCompany[0].cause ?? null, null, "nothing should abstain: the document is in the header");
});

// ---- the scoping partition: what a 1.0 instrument may read at all ----
//
// 1.0 line 298 begins "From 1.0", so its promise that `protocol_version`,
// `supported_versions`, `Poppy-Version` and `version_unsupported` keep their meaning in every
// version is a promise 1.0 makes about itself and later versions. It cannot bind 0.3 or 0.4.
// Line 7 says 1.0 is "0.4 with the fixes implementers needed, which the changelog lists", and
// this repository holds only 1.0. So a 1.0 sentence applied to a 0.x request is a claim the
// instrument cannot ground, in either direction.
const BREACHES = await import("./breaches.mjs");

async function logOf(keys, over) {
  const breach = await BREACHES.BREACH["session.alg"](keys);
  return breach.map(r => ({ ...r, headers: { ...r.headers, ...(over.headers ?? {}) } }));
}

test("a breach under a version this Company serves beside 1.0 is judged by NO rule of 1.0", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0", "0.4"], protocolVersion: "1.0" };
  const log = await logOf(keys, { headers: { "poppy-version": "0.4" } });
  const faulted = grade(log, serves).filter(v => v.verdict === "FAIL").map(v => v.id);
  assert.deepEqual(faulted, [],
    `0.4 is a version this Company serves and no 0.4 text is held here, so nothing may be claimed: ${faulted}`);
});

test("the same breach at 1.0 is still caught in full, which is the control", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0", "0.4"], protocolVersion: "1.0" };
  const log = await logOf(keys, { headers: { "poppy-version": "1.0" } });
  assert.ok(grade(log, serves).some(v => v.id === "session.alg" && v.verdict === "FAIL"),
    "a 1.0 request is judged by every 1.0 rule");
});

test("a version nothing serves is judged by the version rule alone", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0", "0.4"], protocolVersion: "1.0" };
  const log = await logOf(keys, { headers: { "poppy-version": "2.0" } });
  const verdicts = grade(log, serves);
  assert.equal(verdicts.find(v => v.id === "version.sent").verdict, "FAIL",
    "2.0 is compatible with nothing this Company serves, and 3.4 keeps its meaning in every version");
  const others = verdicts.filter(v => v.id !== "version.sent" && v.verdict === "FAIL").map(v => v.id);
  assert.deepEqual(others, [], `no other 1.0 rule may read a 2.0 request: ${others}`);
});

test("a Session request with no version is out of scope where a pre-0.4 version is served", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  // `Poppy-Version` arrived in 0.4, so a conforming 0.3 agent sends none and is indistinguishable
  // from a 1.0 agent that omitted it. At a Company serving 0.3 the request cannot be judged.
  const serves = { ...f.ctx, servedVersions: ["1.0", "0.3"], protocolVersion: "1.0" };
  const log = [await f.request(keys, { version: null, sub: "user-one", seq: 1 })];
  const faulted = grade(log, serves).filter(v => v.verdict === "FAIL").map(v => v.id);
  assert.deepEqual(faulted, [], `0.3 is served here, so an absent version is ambiguous: ${faulted}`);
});

test("a Session request with no version IS faulted where only 1.0 is served, the control", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0"], protocolVersion: "1.0" };
  const log = [await f.request(keys, { version: null, sub: "user-one", seq: 1 })];
  assert.equal(grade(log, serves).find(v => v.id === "version.sent").verdict, "FAIL",
    "every version this Company serves requires the header, so an absent one is the agent's breach");
});

test("only the two rules about `Poppy-Version` itself may read a version this Company does not serve", async () => {
  // The flag is the whole exception to the partition, so it must not spread quietly. 1.0 line 298
  // names `protocol_version`, `supported_versions`, `Poppy-Version` and `version_unsupported` as
  // keeping their meaning in every version, and the only rules resting on that are the two about
  // the header itself. Anything else carrying the flag would be a 1.0 sentence applied to traffic
  // 1.0 does not govern.
  const { CHECKS } = await import("../checks.mjs");
  const flagged = CHECKS.filter(c => c.appliesTo === "every version").map(c => c.id).sort();
  // The recovery rule is the third, and the same sentence warrants it: line 298 names
  // `version_unsupported` itself among the things that keep their meaning in every version, and
  // the refusal that starts that rule can only be seen on a request whose declared version this
  // Company does not serve.
  assert.deepEqual(flagged, ["version.constant", "version.new-session-after-unsupported", "version.sent"]);
});

test("the report counts what it did not judge, and names the versions this Company serves", async () => {
  // A partition that drops records silently is worse than one that judges them wrongly, because
  // the reader cannot see it happen: the traffic was recorded, it was deliberately not graded,
  // and a report that never mentions it reads as though it had never arrived.
  const { judge } = await import("../recorder.mjs");
  const keys = await f.agentKeys();
  const discovery = { protocol_version: "1.0",
                      supported_versions: { "0.4": "https://shop.example/poppy/0.4.json" },
                      organization: { domain: "shop.example" },
                      auth: { issuer: "https://shop.example/poppy", disabled: true } };
  const run = {
    header: { origin: "https://shop.example", discovery },
    records: [
      await f.request(keys, { version: "1.0", sub: "user-one", seq: 1 }),
      await f.request(keys, { version: "0.4", sub: "user-one", seq: 2 }),
      await f.request(keys, { version: "0.4", sub: "user-one", seq: 3, path: "/poppy/orders/1" }),
    ],
  };
  const { report } = judge([run], { graderCommit: "test" });
  assert.equal(report.summary.notJudgedForVersion, 2,
    "two requests declared 0.4, which this Company serves under a text this grader does not hold");
  assert.match(report.topSentence, /not judged/,
    `the top sentence must say so: ${report.topSentence}`);
  assert.match(report.topSentence, /0\.4/, "and name the version those requests declared");
  // And the hard invariant: nothing out of scope may ever be cited as deciding a verdict.
  const outOfScope = new Set([run.records[1], run.records[2]]);
  for (const rule of report.rules)
    for (const c of rule.perCompany)
      for (const cited of c.decidedBy ?? [])
        assert.ok(!outOfScope.has(cited), `${rule.id} cited a request it must not have read`);
});

// ---- recovery after version_unsupported ----
//
// 3.4 line 286, after the Company refuses: "The Personal Agent then fetches `poppy.json` again,
// without using a cached copy, and chooses again. If it chooses another version, it starts a new
// Session and sends the request again, once. Otherwise it stops sending the request."
//
// This is the opposite of what section 7 says about invalid_session, where "A new Session doesn't
// fix it". The existing retry rule is scoped to invalid_session alone, so the two do not collide,
// and nothing checked this one.
const REFUSED = { rejection: { rule: "version.sent", error: "version_unsupported" },
                  response: { status: 400, error: "version_unsupported" } };

const convo = (over) => ({
  method: "POST", path: "/poppy/conversations", conversationRoute: "start",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ id: "r1", message: { author: { type: "human" }, text: "hi" } }),
  ...over });

test("resending in the SAME Session after version_unsupported is faulted", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0"], protocolVersion: "1.0" };
  const log = [
    await f.request(keys, convo({ sid: "s1", sub: "u1", version: "0.9", seq: 1, ...REFUSED })),
    await f.request(keys, convo({ sid: "s1", sub: "u1", version: "1.0", seq: 2 })),
  ];
  const v = grade(log, serves).find(x => x.id === "version.new-session-after-unsupported");
  assert.equal(v.verdict, "FAIL", `3.4 says it starts a NEW Session: ${v?.why}`);
});

test("resending in a NEW Session after version_unsupported is exactly what 3.4 prescribes", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0"], protocolVersion: "1.0" };
  const log = [
    await f.request(keys, convo({ sid: "s1", sub: "u1", version: "0.9", seq: 1, ...REFUSED })),
    await f.request(keys, convo({ sid: "s2", sub: "u1", version: "1.0", seq: 2 })),
  ];
  const v = grade(log, serves).find(x => x.id === "version.new-session-after-unsupported");
  assert.notEqual(v.verdict, "FAIL", `a new Session is the prescribed recovery: ${v?.why}`);
});

test("with nothing refused for a version, the recovery rule has nothing to judge", async () => {
  const { grade } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = { ...f.ctx, servedVersions: ["1.0"], protocolVersion: "1.0" };
  const log = [await f.request(keys, convo({ sid: "s1", sub: "u1", version: "1.0", seq: 1 }))];
  const v = grade(log, serves).find(x => x.id === "version.new-session-after-unsupported");
  assert.equal(v.verdict, "INCONCLUSIVE", "no refusal, so no recovery to judge");
});

// ---- the two regressions the partition introduced, found by audit before the push ----

test("the hosted Company refuses to list a version it does not implement", async () => {
  // It implements 1.0 and serves one document. Listing 0.4 in supported_versions would make a
  // 0.4 Session request OUT OF SCOPE: no rule reads it, enforce returns null, and the server read
  // null as "the Session stands" and handed an unverified JWT to the conversation store. Measured:
  // a Session JWT with its signature destroyed, declaring 0.4, was answered 201 with a conversation
  // id. 3.4 forbids handling a request under another version; a Company that cannot handle 0.4
  // must not claim to serve it. The guard is at the door, so the state cannot arise.
  const { validateConfig } = await import("../server.mjs");
  const { discoveryFor } = await import("../discovery.mjs");
  const origin = "http://127.0.0.1:8";
  const d = discoveryFor(origin);
  assert.throws(() => validateConfig({ origin, discovery: { ...d, supported_versions: { "0.4": `${origin}/poppy/0.4.json` } } }),
    /supported_versions.*0\.4/, "0.4 is not compatible with the 1.0 this Company implements");
  assert.doesNotThrow(() => validateConfig({ origin, discovery: d }), "serving one version is the ordinary case");
});

test("at a valid hosted configuration no Session request can be out of scope", async () => {
  // The property that makes the regression impossible rather than merely unlikely: with the guard
  // above, every version this Company serves is 1.x, so a Session request is judged in full, or
  // judged by the version rules alone and refused, and never silently unread.
  const { contextOf, discoveryFor } = await import("../discovery.mjs");
  const { versionScopeOf } = await import("../checks.mjs");
  const ctx = contextOf(discoveryFor("http://127.0.0.1:8"));
  const keys = await f.agentKeys();
  for (const version of ["1.0", "1.7", "0.4", "0.3", "2.0", null, "junk"]) {
    const r = await f.request(keys, { version, sub: "u", seq: 1 });
    assert.notEqual(versionScopeOf(r, ctx), "out-of-scope", `declaring ${version} must be read by something here`);
  }
});

test("gradePair honours the partition, so 0.x traffic is not compared across Companies", async () => {
  // grade() filtered out-of-scope records but gradePair handed raw logs to the two pairwise rules,
  // the ones the file itself calls the most dangerous: two 0.4 Sessions sharing a sub at two
  // Companies were accused of letting the Companies match the User, on text this grader does not
  // hold. Measured: grade faulted nothing, gradePair faulted both.
  const { gradePair } = await import("../checks.mjs");
  const keys = await f.agentKeys();
  const serves = (identifier) => ({ ...f.ctx, identifier, servedVersions: ["1.0", "0.4"], protocolVersion: "1.0" });
  const ctxA = serves("https://a.example/poppy"), ctxB = serves("https://b.example/poppy");
  const at = async (ctx, version) => [await f.request(keys, { version, sub: "same-user", aud: ctx.identifier, seq: 1 })];
  const faulted = gradePair(await at(ctxA, "0.4"), await at(ctxB, "0.4"), ctxA, ctxB).filter(v => v.verdict === "FAIL").map(v => v.id);
  assert.deepEqual(faulted, [], `0.4 is served under a text this grader does not hold: ${faulted}`);
  // The control: the same sub at two Companies under 1.0 is exactly the 5.1 breach.
  const caught = gradePair(await at(ctxA, "1.0"), await at(ctxB, "1.0"), ctxA, ctxB).find(v => v.id === "pairwise.user-id");
  assert.equal(caught.verdict, "FAIL", "the rule itself still works on 1.0 traffic");
});
