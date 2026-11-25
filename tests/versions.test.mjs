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
    records: [await f.request(keys, { version: "0.4", sub: "user-one", seq: 1 })],
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
