// Attribution by the client_id each Session JWT claimed. Increment 6 of the production plan.
//
// In front of a real store the log holds many agents at once, and a run wide verdict says "your
// agent failed N" about all of them together. The hosted rig avoided this with an exclusive lease;
// a recorder has no lease. So a recorded run can be judged per claimed client_id: each group gets
// the existing report over its own records only, requests carrying no decodable Session header
// belong to no group and are counted, and there is no aggregate across agents, because a total is
// a verdict about nobody. The recorder verifies nothing about the claim, and every group says so.
//
// The invariant that makes cross agent corruption impossible: an agent's report is a function of
// its own records alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { judge } from "../recorder.mjs";
import * as f from "./fixture.mjs";

const A = "https://agent-a.example/agent.json";
const B = "https://agent-b.example/agent.json";
const DISCOVERY = { protocol_version: "1.0", organization: { domain: "shop.example" },
                    auth: { issuer: "https://shop.example/poppy", disabled: true } };
const runOf = (records, over = {}) => ({ header: { origin: "https://shop.example", discovery: DISCOVERY, ...over }, records });

// Volatile fields only: the clock and the end time. Everything else must be identical.
const strip = (report) => JSON.parse(JSON.stringify(report, (k, v) =>
  (k === "clock" || k === "ended" || k === "started") ? undefined : v));

async function conformingA(keys) {
  return (await f.conformingLog(keys)).map(r => r.headers?.["poppy-session"]
    ? r : r);   // the conforming log is already one agent; its client_id is the fixture default
}

test("an agent's report is a function of its own records alone", async () => {
  const ka = await f.agentKeys(), kb = await f.agentKeys();
  const mine = await f.conformingLog(ka);                                   // agent A, conforming
  const solo = judge([runOf(mine)], { graderCommit: "t", attribution: "by-issuer" });
  assert.ok(Array.isArray(solo.agents), "by-issuer mode returns one report per claimed client_id");
  const aAlone = solo.agents.find(g => g.iss === f.CLIENT_ID);
  assert.ok(aAlone, "agent A has a group");

  // A crowd: B breaching with the same sid and request ids as A, a client with no Session header
  // at all, and a request declaring a version nothing serves. Shuffled, several ways.
  // Every B record claims B's client_id. The shared BREACH fixtures all claim the default one,
  // which is right for every other test and would make "B" into A here.
  const crowd = [
    await f.request(kb, { clientId: B, sesTyp: "JWT", sub: "user-b", seq: 899 }),   // session.typ breach
    await f.request(kb, { clientId: B, sid: "sid-1", sub: "user-b", seq: 900 }),
    { ...(await f.request(kb, { clientId: B, noSession: true, seq: 901 })) },
    await f.request(kb, { clientId: B, version: "2.0", seq: 902 }),
  ];
  for (let seed = 1; seed <= 5; seed++) {
    const all = [...mine, ...crowd];
    for (let i = all.length - 1; i > 0; i--) { const j = (seed * 7919 + i * 104729) % (i + 1); [all[i], all[j]] = [all[j], all[i]]; }
    const together = judge([runOf(all)], { graderCommit: "t", attribution: "by-issuer" });
    const aInCrowd = together.agents.find(g => g.iss === f.CLIENT_ID);
    assert.deepEqual(strip(aInCrowd.report.rules), strip(aAlone.report.rules),
      `seed ${seed}: agent A's verdicts changed because other agents were in the log`);
  }
});

test("a request with no decodable Session header belongs to no group and is counted", async () => {
  const ka = await f.agentKeys();
  const bare = await f.request(ka, { noSession: true, seq: 5 });
  const log = [...(await f.conformingLog(ka)), bare];
  const out = judge([runOf(log)], { graderCommit: "t", attribution: "by-issuer" });
  // The conforming log itself carries bare requests (discovery, a token refresh), which is what
  // 5.2 prescribes for those. Derived from the input, never hard coded.
  const expected = log.filter(r => typeof r.headers?.["poppy-session"] !== "string").length;
  assert.equal(out.unattributed.count, expected, `every request with no Session header is counted: ${expected}`);
  assert.ok(expected >= 3, "the fixture must really contain bare requests");
  for (const g of out.agents)
    for (const rule of g.report.rules)
      for (const c of rule.perCompany)
        for (const cited of c.decidedBy ?? [])
          assert.notEqual(cited, bare, `${g.iss} was charged with a request nobody signed`);
});

test("every breach by one agent fails in that agent's group and in no other", async () => {
  const ka = await f.agentKeys(), kb = await f.agentKeys();
  const breach = [await f.request(kb, { clientId: B, sesTyp: "JWT", sub: "user-b", seq: 50 })];
  const out = judge([runOf([...(await f.conformingLog(ka)), ...breach])], { graderCommit: "t", attribution: "by-issuer" });
  const groups = Object.fromEntries(out.agents.map(g => [g.iss, g]));
  const failedIn = (iss) => groups[iss].report.rules.filter(r => r.worst === "FAIL").map(r => r.id);
  assert.deepEqual(failedIn(f.CLIENT_ID), [], `agent A faulted for B's breach: ${failedIn(f.CLIENT_ID)}`);
  assert.ok(failedIn(B).includes("session.typ"), `B's own breach lands in B's group: ${failedIn(B)}`);
});

test("single-agent mode is byte for byte what judge returned before", async () => {
  const ka = await f.agentKeys();
  const run = runOf(await f.conformingLog(ka));
  const before = judge([run], { graderCommit: "t" });
  const explicit = judge([run], { graderCommit: "t", attribution: "single-agent" });
  assert.deepEqual(strip(explicit.report), strip(before.report), "the default is unchanged");
  assert.equal(explicit.agents, undefined, "and carries no groups");
});
