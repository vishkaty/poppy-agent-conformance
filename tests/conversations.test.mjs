// Section 8, enough of it that a real agent can finish a conversation.
//
// Why this is not optional for a grader whose purpose is judging agents: conversations are the
// main interface of the protocol, and an agent that POSTs its first message and gets back
// `{ok: true}` has no Conversation ID, so it cannot use the other five routes of 8.2 at all.
// Measured: the only agent that ever reached routes two to six against this Company was the
// authors' validator, by inventing ids. So the threshold for "a useful target" is precise:
// return a Conversation ID and remember it.
//
// Out of scope on purpose, each because 1.0 makes it optional or this Company lacks the thing:
// streaming (8.6, "A Company that doesn't stream returns JSON as usual"), Direct Conversations
// (8.10), sign-in during a conversation (8.11, no accounts), and version_mismatch (one version).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createGrader } from "../server.mjs";
import { discoveryFor, identifierOf } from "../discovery.mjs";
import { post, get } from "./http.mjs";

const ref = await import("../reference/jose.ts");
const CLIENT = "https://agent.example/agent.json";

// A conforming agent against a real Company, because enforcement means an unsigned request
// never reaches the conversation code at all.
async function agent(origin, over = {}) {
  const doc = await (await fetch(`${origin}/.well-known/poppy.json`)).json();
  const endpoint = doc.agent.protocols.find(p => p.type === "poppy").endpoint;
  const operator = await ref.generateKey(), key = await ref.generateKey();
  const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk,
                                                iss: over.iss ?? CLIENT });
  const sid = ref.randomId(16), sub = over.sub ?? ref.randomId(16);
  const call = async (method, url, body) => {
    const jwt = await ref.signSessionJwt({ key, delegation, iss: over.iss ?? CLIENT,
      aud: identifierOf(doc), sid, sub, method, url });
    return (method === "GET" ? get : post)(url, {
      method, body: body === undefined ? undefined : JSON.stringify(body),
      headers: { "poppy-session": jwt, "poppy-version": doc.protocol_version,
                 ...(body === undefined ? {} : { "content-type": "application/json" }) },
    });
  };
  return { endpoint, call };
}

async function company(fn) {
  const g = createGrader({ origin: "http://127.0.0.1", discovery: discoveryFor,
                           operations: [{ method: "GET", path: "/poppy/orders" }] });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try { return await fn(g); } finally { await g.close(); }
}

test("a conversation starts with 201 and an id, and the id works on the other routes", async () => {
  // 8.3: "HTTP/1.1 201 Created ... { "conversation_id": "cnv_8f3Kd2" }", and later messages
  // "returns HTTP 202 with the same body".
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const made = await a.call("POST", a.endpoint,
      { id: "req_1", message: { author: { type: "agent" }, text: "hello" } });
    assert.equal(made.status, 201, made.text);
    const id = made.body?.conversation_id;
    assert.ok(id, `no conversation_id in ${made.text}`);

    const msg = await a.call("POST", `${a.endpoint}/${id}/messages`,
      { id: "req_2", message: { text: "another" } });
    assert.equal(msg.status, 202, msg.text);
    assert.equal(msg.body.conversation_id, id);

    const read = await a.call("GET", `${a.endpoint}/${id}/events`);
    assert.equal(read.status, 200, read.text);
    // 8.5 names the fields a read reports, and 8.7 their values.
    assert.equal(read.body.conversation_id, id);
    assert.ok(Array.isArray(read.body.events), "events is not a list");
    assert.equal(typeof read.body.cursor, "string");
    assert.equal(read.body.has_more, false);
    assert.equal(read.body.working, false, "this Company acts before it answers, so nothing is pending");
    assert.equal(read.body.handoff, "none");
    assert.equal(read.body.responder, "agent");
    assert.equal(read.body.closed, false);
    // both of the agent's messages were recorded, with the role the Company sets (8.4)
    const mine = read.body.events.filter(e => e.type === "message" && e.message.role === "user");
    assert.equal(mine.length, 2, `recorded ${mine.length} of the agent's 2 messages`);
    for (const e of read.body.events) {
      assert.match(e.id, /^evt_/);
      assert.match(e.created_at, /^\d{4}-\d{2}-\d{2}T/);
    }
  });
});

test("a read from a cursor returns only later events, and the cursor moves", async () => {
  // 8.5: "The Personal Agent reads the events after the last cursor it saved."
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const id = (await a.call("POST", a.endpoint, { id: "r1", message: { text: "one" } })).body.conversation_id;
    const first = await a.call("GET", `${a.endpoint}/${id}/events`);
    const cursor = first.body.cursor;
    assert.ok(first.body.events.length >= 1);

    const nothingNew = await a.call("GET", `${a.endpoint}/${id}/events?cursor=${cursor}`);
    assert.equal(nothingNew.status, 200, nothingNew.text);
    assert.deepEqual(nothingNew.body.events, [], "a read from the latest cursor returned old events");
    assert.equal(nothingNew.body.cursor, cursor, "the cursor moved with nothing to report");

    await a.call("POST", `${a.endpoint}/${id}/messages`, { id: "r2", message: { text: "two" } });
    const later = await a.call("GET", `${a.endpoint}/${id}/events?cursor=${cursor}`);
    assert.equal(later.body.events.length, 1, `got ${later.body.events.length} events after the cursor`);
    assert.notEqual(later.body.cursor, cursor);

    // 8.13: "invalid_cursor | 400 | The cursor is unknown or doesn't belong to this conversation."
    const bad = await a.call("GET", `${a.endpoint}/${id}/events?cursor=evt_nope`);
    assert.equal(bad.status, 400, bad.text);
    assert.equal(bad.body.error, "invalid_cursor");
  });
});

test("an unknown conversation, and one belonging to someone else, get the same 404", async () => {
  // 8.13: "conversation_not_found | 404 | The Conversation ID is unknown or belongs to a
  // different Personal Agent, User, or account (8.2). All return the same error."
  await company(async (g) => {
    const mine = await agent(g.config.origin);
    const id = (await mine.call("POST", mine.endpoint, { id: "r1", message: { text: "x" } })).body.conversation_id;

    const unknown = await mine.call("GET", `${mine.endpoint}/cnv_nope/events`);
    assert.equal(unknown.status, 404, unknown.text);
    assert.equal(unknown.body.error, "conversation_not_found");

    // another User of the same agent (8.2: "Same Personal Agent, another User ID | Rejected")
    const otherUser = await agent(g.config.origin, { sub: "someone-else" });
    const theirs = await otherUser.call("GET", `${mine.endpoint}/${id}/events`);
    assert.equal(theirs.status, 404, theirs.text);
    assert.deepEqual(theirs.body, unknown.body, "the two 404s are distinguishable");

    // another Personal Agent (8.2: "Another Personal Agent | Rejected")
    const otherAgent = await agent(g.config.origin, { iss: "https://other-agent.example/agent.json" });
    const alien = await otherAgent.call("POST", `${mine.endpoint}/${id}/messages`,
      { id: "r9", message: { text: "let me in" } });
    assert.equal(alien.status, 404, alien.text);
    assert.deepEqual(alien.body, unknown.body);
  });
});

test("closing is idempotent, and a closed conversation takes no more messages", async () => {
  // 8.12 and 8.13: close returns 202; "A message, handoff request, or handoff cancel was sent
  // to a closed conversation" is conversation_closed, 409.
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const id = (await a.call("POST", a.endpoint, { id: "r1", message: { text: "x" } })).body.conversation_id;

    const closed = await a.call("POST", `${a.endpoint}/${id}/close`, { id: "r2" });
    assert.equal(closed.status, 202, closed.text);
    const again = await a.call("POST", `${a.endpoint}/${id}/close`, { id: "r3" });
    assert.equal(again.status, 202, "closing again was not accepted");

    const read = await a.call("GET", `${a.endpoint}/${id}/events`);
    assert.equal(read.body.closed, true);
    const stateEvents = read.body.events.filter(e => e.type === "state");
    assert.equal(stateEvents.length, 1, `closing twice added ${stateEvents.length} state events`);

    for (const [route, body] of [["messages", { id: "r4", message: { text: "late" } }],
                                 ["handoff", { id: "r5" }],
                                 ["handoff/cancel", { id: "r6" }]]) {
      const res = await a.call("POST", `${a.endpoint}/${id}/${route}`, body);
      assert.equal(res.status, 409, `${route}: ${res.text}`);
      assert.equal(res.body.error, "conversation_closed", route);
    }
  });
});

test("a handoff request is answered, because 8.9 requires the Company to say why not", async () => {
  // 8.9: "If no one is available, handoff goes back to none with responder still agent, and the
  // Company Agent says why in a message." This Company has nobody, so it says so at once.
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const id = (await a.call("POST", a.endpoint, { id: "r1", message: { text: "x" } })).body.conversation_id;
    const asked = await a.call("POST", `${a.endpoint}/${id}/handoff`, { id: "r2" });
    assert.equal(asked.status, 202, asked.text);
    const read = await a.call("GET", `${a.endpoint}/${id}/events`);
    assert.equal(read.body.handoff, "none", "handoff stayed pending with nobody looking");
    assert.equal(read.body.responder, "agent");
    const said = read.body.events.filter(e => e.type === "message" && e.message.role === "company");
    assert.ok(said.length >= 1, "the Company said nothing about a handoff it cannot do");
    assert.match(said.map(e => e.message.text).join(" "), /person|nobody|no one/i);
  });
});

test("a request id makes a retry safe, and a reused id with a different body is a conflict", async () => {
  // 8.2: "Every POST has a JSON body with a request id (8.3), so retries are safe."
  // 8.13: "request_id_conflict | 409 | A request reused an ID that the Company accepted with a
  // different path or body (8.3)."
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const body = { id: "req_same", message: { text: "once" } };
    const first = await a.call("POST", a.endpoint, body);
    const retry = await a.call("POST", a.endpoint, body);
    assert.equal(first.status, 201, first.text);
    assert.equal(retry.status, 201, "an identical retry was not safe");
    assert.equal(retry.body.conversation_id, first.body.conversation_id,
      "an identical retry started a second conversation");

    const different = await a.call("POST", a.endpoint, { id: "req_same", message: { text: "different" } });
    assert.equal(different.status, 409, different.text);
    assert.equal(different.body.error, "request_id_conflict");
  });
});

test("a POST with no request id, or a message with no content, is invalid_request", async () => {
  // 8.13: "invalid_request | 400 | The request is malformed, such as a missing request `id`
  // (8.3), a message with no content (8.4)". 8.4: "A message MUST have at least one of `text`,
  // `data`, `context`, or `extensions`."
  await company(async (g) => {
    const a = await agent(g.config.origin);
    for (const [what, body] of [["no id", { message: { text: "x" } }],
                                ["no message", { id: "r1" }],
                                ["empty message", { id: "r2", message: {} }],
                                ["not an object", "plain text"]]) {
      const res = await a.call("POST", a.endpoint, body);
      assert.equal(res.status, 400, `${what}: ${res.status} ${res.text}`);
      assert.equal(res.body?.error, "invalid_request", what);
    }
  });
});

test("the conversation routes are still recorded and judged like any destination", async () => {
  // Implementing section 8 must not make these requests invisible to the grader.
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const id = (await a.call("POST", a.endpoint, { id: "r1", message: { text: "x" } })).body.conversation_id;
    await a.call("GET", `${a.endpoint}/${id}/events`);
    const seen = g.records.filter(r => r.isResource).map(r => `${r.method} ${r.path}`);
    assert.ok(seen.some(x => x.endsWith("/poppy/conversations")), seen.join(", "));
    assert.ok(seen.some(x => x.includes("/events")), seen.join(", "));
    for (const r of g.records.filter(r => r.isResource))
      assert.equal(r.response.status < 400, true, `${r.method} ${r.path} answered ${r.response.status}`);
  });
});
