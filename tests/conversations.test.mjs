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

test("a recorded message keeps the request's own id, because 8.3 says that is its id", async () => {
  // 8.2: "The Personal Agent chooses request IDs, and each of its messages has its request's
  // ID." 8.4 repeats it for the `id` field: "the request's ID for the Personal Agent's
  // messages (8.3)". This Company minted a fresh id instead, so an agent that sent a message
  // and then looked for it in the events could not find it. Three checks in the authors own
  // validator failed on exactly that, all reading "no message event with id ...".
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const sent = { id: "req_Ab-_09", message: { author: { type: "agent" }, text: "keep my id",
                                                data: { n: [1, 2] }, context: { user_available: false } } };
    const id = (await a.call("POST", a.endpoint, sent)).body.conversation_id;
    const read = await a.call("GET", `${a.endpoint}/${id}/events`);
    const mine = read.body.events.find(e => e.type === "message" && e.message.id === sent.id);
    assert.ok(mine, `no message event with id ${sent.id}: ${JSON.stringify(read.body.events)}`);
    assert.equal(mine.message.role, "user");
    // 8.5: the event "holds the message as it was sent, with its author, text, data, and
    // context, plus role".
    assert.deepEqual(mine.message.author, sent.message.author);
    assert.equal(mine.message.text, sent.message.text);
    assert.deepEqual(mine.message.data, sent.message.data);
    assert.deepEqual(mine.message.context, sent.message.context);

    // and a message with ONLY context is still recorded (8.4 permits it, 8.5 records it)
    const second = await a.call("POST", `${a.endpoint}/${id}/messages`,
      { id: "req_contextonly", message: { context: { locale: "en-GB" } } });
    assert.equal(second.status, 202, second.text);
    const after = await a.call("GET", `${a.endpoint}/${id}/events`);
    assert.ok(after.body.events.some(e => e.message?.id === "req_contextonly"),
      "a message carrying only context was not recorded");
  });
});

test("an id outside the alphabet 8.2 defines is invalid_request, and 256 characters is allowed", async () => {
  // 8.2: "Conversation IDs, request IDs, message IDs, and event IDs are strings of 1 to 256
  // characters from the URL-safe base64 alphabet (RFC 4648, section 5): letters, digits, `-`,
  // and `_`." 8.13 lists "an ID with characters not allowed (8.2)" under invalid_request.
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const ok = await a.call("POST", a.endpoint, { id: "A".repeat(256), message: { text: "x" } });
    assert.equal(ok.status, 201, `a 256 character id was refused: ${ok.text}`);

    for (const [what, reqId] of [["257 characters", "A".repeat(257)],
                                 ["a slash", "req/one"],
                                 ["a space", "req one"],
                                 ["a plus", "req+one"],
                                 ["empty", ""]]) {
      const res = await a.call("POST", a.endpoint, { id: reqId, message: { text: "x" } });
      assert.equal(res.status, 400, `${what}: ${res.status} ${res.text}`);
      assert.equal(res.body?.error, "invalid_request", what);
    }
  });
});

test("a wait that is not a whole number of seconds is invalid_request", async () => {
  // 8.13: "invalid_request | 400 | The request is malformed, such as ... a `wait` that isn't a
  // whole number of seconds."
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const id = (await a.call("POST", a.endpoint, { id: "r1", message: { text: "x" } })).body.conversation_id;
    for (const wait of ["1.5", "soon", "-1", "", "1e3"]) {
      const res = await a.call("GET", `${a.endpoint}/${id}/events?wait=${encodeURIComponent(wait)}`);
      assert.equal(res.status, 400, `wait=${wait}: ${res.status} ${res.text}`);
      assert.equal(res.body?.error, "invalid_request", `wait=${wait}`);
    }
    // and a whole number is fine, answered at once because 8.5 says it MAY return sooner
    const fine = await a.call("GET", `${a.endpoint}/${id}/events?wait=30`);
    assert.equal(fine.status, 200, fine.text);
  });
});

test("a Direct Conversation is linked to its parent, and refused in the four ways 8.10 names", async () => {
  // 8.10: "The parent conversation MUST be open, belong to the same owner (8.2), and not be a
  // Direct Conversation itself. It can have one open Direct Conversation at a time. Otherwise
  // the Company returns `conversation_not_found` for an unknown parent or one with a different
  // owner, `conversation_closed` for a closed one, `invalid_request` for one that is a Direct
  // Conversation, and `direct_conversation_open` for one that already has an open Direct
  // Conversation."
  //
  // The create path only. The Company asking to talk with the User (a `user_requested` event)
  // is out of scope: this Company never asks.
  await company(async (g) => {
    const a = await agent(g.config.origin);
    const start = async (over) => a.call("POST", a.endpoint,
      { id: `r_${Math.random().toString(36).slice(2, 10)}`,
        message: { author: { type: "human" }, text: "direct" }, ...over });

    const parent = (await start({ message: { text: "parent" } })).body.conversation_id;

    const direct = await start({ parent_conversation_id: parent });
    assert.equal(direct.status, 201, direct.text);
    const directId = direct.body.conversation_id;
    assert.notEqual(directId, parent);

    // one at a time
    const second = await start({ parent_conversation_id: parent });
    assert.equal(second.status, 409, second.text);
    assert.equal(second.body.error, "direct_conversation_open");
    assert.equal(second.body.conversation_id, directId,
      "8.10 names the open Direct Conversation in conversation_id");

    // a Direct Conversation cannot itself be a parent
    const nested = await start({ parent_conversation_id: directId });
    assert.equal(nested.status, 400, nested.text);
    assert.equal(nested.body.error, "invalid_request");

    // unknown parent, and a parent belonging to someone else: both not found
    const unknown = await start({ parent_conversation_id: "cnv_nope" });
    assert.equal(unknown.status, 404, unknown.text);
    assert.equal(unknown.body.error, "conversation_not_found");
    const other = await agent(g.config.origin, { sub: "another-user" });
    const theirs = await other.call("POST", other.endpoint,
      { id: "r_other", message: { text: "x" }, parent_conversation_id: parent });
    assert.equal(theirs.status, 404, theirs.text);
    assert.deepEqual(theirs.body, unknown.body, "the two 404s are distinguishable");

    // a closed parent
    await a.call("POST", `${a.endpoint}/${directId}/close`, { id: "r_closedirect" });
    await a.call("POST", `${a.endpoint}/${parent}/close`, { id: "r_closeparent" });
    const afterClose = await start({ parent_conversation_id: parent });
    assert.equal(afterClose.status, 409, afterClose.text);
    assert.equal(afterClose.body.error, "conversation_closed");
  });
});

test("a Company that verifies does not keep conversation state for claims it could not verify", async () => {
  // The residual half of the 5.3 breach. Closing the egress hole meant not fetching outside a
  // run, so outside a run a delegation cannot be verified; and conversation ownership is the
  // client_id and User ID a Session JWT carries. 5.3: "The Company MUST NOT use unverified
  // Session claims to attribute a request to a Personal Agent, User, or Session, or to look up
  // their state." So a Company configured to verify must refuse to create or continue a
  // conversation when verification did not happen, rather than hold state under a client_id
  // nobody proved.
  //
  // Requests that use no Session claims are unaffected: 5.3 lets an endpoint that uses none
  // handle a request without verifying one, which is why the API operations still answer.
  const g = createGrader({ origin: "http://127.0.0.1", discovery: discoveryFor,
                           operations: [{ method: "GET", path: "/poppy/orders" }],
                           verifyDelegations: true,
                           // verification cannot run: this models being outside a lease
                           verifyWhen: () => false,
                           issuerKeys: { forIssuer: async () => { throw new Error("must not be called"); },
                                         newRun() {}, forget() {} } });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const a = await agent(g.config.origin);
    const made = await a.call("POST", a.endpoint, { id: "r1", message: { text: "hello" } });
    assert.equal(made.status, 400, `a conversation was created on unverified claims: ${made.text}`);
    assert.equal(made.body?.error, "invalid_session");
    assert.match(made.body?.error_description ?? "", /verif/i, made.text);

    // an API operation, which uses no Session claims, still answers
    const api = await a.call("GET", `${g.config.origin}/poppy/orders`);
    assert.equal(api.status, 200, `an endpoint using no Session claims was refused: ${api.text}`);
  } finally { await g.close(); }
});

test("the same Company serves conversations once verification has run", async () => {
  // The control, so the rule above cannot be satisfied by refusing conversations always.
  const g = createGrader({ origin: "http://127.0.0.1", discovery: discoveryFor,
                           operations: [{ method: "GET", path: "/poppy/orders" }] });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const a = await agent(g.config.origin);
    const made = await a.call("POST", a.endpoint, { id: "r1", message: { text: "hello" } });
    assert.equal(made.status, 201, made.text);
  } finally { await g.close(); }
});

test("inside a run, the refusal says why verification failed and does not tell the builder to lease one", async () => {
  // Found by the first run against a third-party agent SDK, which held a lease and was told
  // "lease a run first with POST /grader/runs" because its client_id host does not resolve.
  // One sentence covered four situations: no lease, a Session JWT with no `iss`, a fetch that
  // got no bytes, and a fetch whose answer was the agent's own defect. In three of them the
  // advice is wrong, and a builder who follows it re-leases and sees the same refusal. The
  // report already names the real reason, and this is the same honesty on the wire: the
  // abstention in checks.mjs is never just silence, so neither is the refusal.
  const detail = "could not resolve agent.example: getaddrinfo ENOTFOUND agent.example";
  const g = createGrader({ origin: "http://127.0.0.1", discovery: discoveryFor,
                           operations: [{ method: "GET", path: "/poppy/orders" }],
                           verifyDelegations: true,
                           // a run IS open, and the fetch ran and got no bytes
                           verifyWhen: () => true,
                           issuerKeys: { forIssuer: async () => ({ outcome: "grader", detail, keys: [], kids: [] }),
                                         newRun() {}, forget() {} } });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const a = await agent(g.config.origin);
    const made = await a.call("POST", a.endpoint, { id: "r1", message: { text: "hello" } });
    assert.equal(made.status, 400, `a conversation was created on unverified claims: ${made.text}`);
    assert.equal(made.body?.error, "invalid_session");
    const why = made.body?.error_description ?? "";
    assert.doesNotMatch(why, /lease a run/i,
      `the builder holds a lease and was told to get one: ${why}`);
    assert.ok(why.includes(detail),
      `the refusal does not say why verification failed, so the builder cannot act on it: ${why}`);
  } finally { await g.close(); }
});
