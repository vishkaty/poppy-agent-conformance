// One agent's verdict must not depend on another agent's traffic.
//
// In front of a production store the log holds many agents at once, and several rules key
// their uniqueness maps on a value each agent chooses for itself: the Session `sid`, the
// Session `jti`, a conversation request id. Two agents that both number from one then
// collide, and the rule faults whichever it sees second. `session.jti-unique` says in its
// own words that one key "signed 2 different requests", which across two different signers
// is a false accusation of signature replay about somebody else's agent.
//
// The spec scopes all of this to the agent, and says so three times:
//   5.1 line 478: "A Session belongs to one User, at one Company, through one Personal Agent."
//   5.1 line 495: "An agent another company runs connects under its own `client_id`."
//   8.3:          an id "MUST make it unique for the User across all its requests", its own.
// So keying by client_id is not a workaround for a shared host. It is what a Session is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS } from "../checks.mjs";
import * as f from "./fixture.mjs";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { randomUUID } from "node:crypto";

const A = "https://agent-a.example/agent.json";
const B = "https://agent-b.example/agent.json";

const verdictOf = (id, log) => CHECKS.find(c => c.id === id).run(log, f.ctx);

// Each case: two agents, each conforming on its own, colliding on the value the rule keys on.
const CASES = [
  { rule: "session.sub-stable", why: "two agents both chose the Session id `1`, for different Users",
    build: async (ka, kb) => [
      await f.request(ka, { clientId: A, sid: "1", sub: "user-a", seq: 1 }),
      await f.request(kb, { clientId: B, sid: "1", sub: "user-b", seq: 2 }),
    ] },
  { rule: "version.constant", why: "two agents both chose the Session id `1`, on different versions",
    build: async (ka, kb) => [
      await f.request(ka, { clientId: A, sid: "1", sub: "user-a", version: "1.0", seq: 1 }),
      await f.request(kb, { clientId: B, sid: "1", sub: "user-b", version: "1.4", seq: 2 }),
    ] },
  { rule: "session.jti-unique", why: "two agents both numbered a signature `j1`",
    build: async (ka, kb) => [
      await f.request(ka, { clientId: A, jti: "j1", sub: "user-a", path: "/poppy/orders", seq: 1 }),
      await f.request(kb, { clientId: B, jti: "j1", sub: "user-b", path: "/poppy/orders/1", seq: 2 }),
    ] },
  { rule: "conversation.request-id", why: "one person using two agents, each numbering its own requests from `r1`",
    build: async (ka, kb) => [
      await f.request(ka, { clientId: A, sub: "user-one", method: "POST", path: "/poppy/conversations",
        conversationRoute: "start", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "r1", message: { author: { type: "human" }, text: "from agent a" } }), seq: 1 }),
      await f.request(kb, { clientId: B, sub: "user-one", method: "POST", path: "/poppy/conversations",
        conversationRoute: "start", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: "r1", message: { author: { type: "human" }, text: "from agent b" } }), seq: 2 }),
    ] },
];

test("no rule faults one agent for a value another agent chose", async () => {
  const ka = await f.agentKeys();
  const kb = await f.agentKeys();
  const wrong = [];
  for (const c of CASES) {
    const log = await c.build(ka, kb);
    const v = verdictOf(c.rule, log);
    if (v.verdict === "FAIL")
      wrong.push(`${c.rule}: ${c.why}\n      -> ${v.why}\n      -> ${JSON.stringify(v.evidence ?? []).slice(0, 110)}`);
  }
  assert.deepEqual(wrong, [], `one agent was faulted for another agent's choice:\n    ${wrong.join("\n    ")}`);
});

test("the same collision inside ONE agent is still faulted, which is the control", async () => {
  const ka = await f.agentKeys();
  // Identical to the cases above except that both requests are the same agent, where the
  // sentences really do bind. If these stopped failing, the fix above would have deleted the
  // rules rather than scoped them.
  const same = [
    ["session.sub-stable", [await f.request(ka, { clientId: A, sid: "1", sub: "user-a", seq: 1 }),
                            await f.request(ka, { clientId: A, sid: "1", sub: "user-b", seq: 2 })]],
    ["session.jti-unique", [await f.request(ka, { clientId: A, jti: "j1", sub: "user-a", path: "/poppy/orders", seq: 1 }),
                            await f.request(ka, { clientId: A, jti: "j1", sub: "user-a", path: "/poppy/orders/1", seq: 2 })]],
  ];
  for (const [rule, log] of same)
    assert.equal(verdictOf(rule, log).verdict, "FAIL", `${rule} must still fault one agent colliding with itself`);
});

test("a FAIL names only the requests that decided it, not every agent in the log", async () => {
  // Two delegation rules mapped the delegations out of the log and then cited every Session
  // request as `decidedBy`, so one bad delegation named every request of every agent. The
  // report then marks all of them as claimed by a rule, and a builder reading it sees their
  // own conforming requests listed under somebody else's breach.
  const ka = await f.agentKeys();
  const kb = await f.agentKeys();
  const good = await f.request(ka, { clientId: A, sub: "user-a", path: "/poppy/orders", seq: 1 });

  const priv = await exportJWK(kb.delegated.privateKey);           // carries `d`
  const leaks = await f.request(kb, { clientId: B, sub: "user-b", path: "/poppy/orders/1", seq: 2,
    dlgCompact: await f.delegation(kb, { clientId: B, payload: { cnf: { jwk: priv } } }) });
  const v1 = verdictOf("delegation.no-private-key", [good, leaks]);
  assert.equal(v1.verdict, "FAIL", "the leaked private key is still a breach");
  assert.deepEqual(v1.decidedBy, [leaks], "only the request whose delegation carried the key");

  const rsa = await generateKeyPair("RS256", { extractable: true });
  const now = Math.floor(Date.now() / 1000);
  const wrongAlg = await new SignJWT({ iss: B, iat: now, exp: now + 3600,
      jti: randomUUID(), cnf: { jwk: kb.jwk } })
    .setProtectedHeader({ alg: "RS256", typ: "poppy-delegation+jwt" })
    .sign(rsa.privateKey);
  const badAlg = await f.request(kb, { clientId: B, sub: "user-b", path: "/poppy/orders/1", seq: 2,
    dlgCompact: wrongAlg });
  const v2 = verdictOf("delegation.alg", [good, badAlg]);
  assert.equal(v2.verdict, "FAIL", "RS256 is still not one of the two 1.0 defines");
  assert.deepEqual(v2.decidedBy, [badAlg], "only the request carrying the RS256 delegation");
});
