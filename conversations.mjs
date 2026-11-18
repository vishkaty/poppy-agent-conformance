// Section 8, enough of it that a real agent can finish a conversation.
//
// Why a grader needs any of it. Conversations are the protocol's main interface, and an agent
// that POSTs its first message and gets back `{ok: true}` has no Conversation ID, so it cannot
// use the other five routes of 8.2 at all. Measured: the only agent that ever reached routes
// two to six against this Company was the protocol authors' own validator, by inventing ids.
// So the threshold for a useful target is exact: return a Conversation ID and remember it.
//
// This Company is deliberately silent and immediate. It records what the agent sends, answers
// at once, and never leaves work pending, so `working` is always false by the time it answers:
// 8.7 makes `working` true only for "a request it accepted but hasn't acted on". It is not
// pretending to be a shop, and it says nothing an agent could mistake for a real reply.
//
// Out of scope, each because 1.0 makes it optional or this Company lacks the thing: streaming
// (8.6, "A Company that doesn't stream returns JSON as usual"), Direct Conversations (8.10),
// sign-in during a conversation (8.11, there are no accounts here, so the "Rejected with a
// challenge" row of the 8.2 ownership table cannot arise), and `version_mismatch` (8.2, this
// Company serves one version).
import { createHash, randomBytes } from "node:crypto";

const id = (prefix) => `${prefix}_${randomBytes(9).toString("base64url")}`;
const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const hash = (s) => createHash("sha256").update(String(s)).digest("hex");

// The errors of 8.13 that this Company can produce, with the status each one carries there.
const ERRORS = {
  conversation_not_found: 404,
  conversation_closed: 409,
  request_id_conflict: 409,
  invalid_cursor: 400,
  invalid_request: 400,
};
const fail = (error, detail) => ({ status: ERRORS[error], body: { error, ...(detail ? { error_description: detail } : {}) } });

export function createConversations({ max = 200 } = {}) {
  const store = new Map();          // conversation id -> conversation
  const requests = new Map();       // `${owner}\u0000${request id}` -> { path, bodyHash, response }

  // A conversation belongs to the Personal Agent's client_id and the User ID that started it
  // (8.2), and an Agent ID is deliberately not part of it: "Agent IDs aren't part of
  // ownership." Both come from the VERIFIED Session, which is why enforcement runs first: 5.3
  // says "The Company MUST NOT use unverified Session claims to attribute a request to a
  // Personal Agent, User, or Session, or to look up their state."
  const ownerOf = (jwt) => `${jwt?.payload?.iss ?? ""}\u0000${jwt?.payload?.sub ?? ""}`;

  function prune() {
    while (store.size > max) store.delete(store.keys().next().value);
  }

  function add(c, event) {
    const e = { id: id("evt"), created_at: nowIso(), ...event };
    c.events.push(e);
    return e;
  }

  // 8.4: "A message MUST have at least one of `text`, `data`, `context`, or `extensions`."
  const hasContent = (m) => !!m && typeof m === "object"
    && ["text", "data", "context", "extensions"].some(k => m[k] !== undefined);

  function record(c, message) {
    // 8.4: the Company sets `role`, and ignores an `id` or `role` the agent sent.
    const { id: _ignored, role: _alsoIgnored, ...rest } = message;
    return add(c, { type: "message", message: { id: id("msg"), role: "user", ...rest } });
  }

  const say = (c, text) => add(c, { type: "message",
    message: { id: id("msg"), role: "company", author: { type: "agent" }, text } });

  const state = (c) => ({ working: false, handoff: "none", responder: "agent", closed: c.closed });

  // Returns { status, body } or null when this is not a conversation request.
  //
  // `body` is the parsed JSON body, or undefined for a GET.
  function handle({ route, convId }, { jwt, body, query, path }) {
    if (!route) return null;
    const owner = ownerOf(jwt);

    // Every POST carries a request id (8.2), and a repeat of one already accepted returns the
    // original answer rather than doing the thing twice. Stored only for ACCEPTED requests and
    // only after the whole body arrived, so a reset upload and its retry cannot conflict with
    // each other.
    const isPost = route !== "events";
    let reqKey = null;
    if (isPost) {
      if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.id !== "string" || !body.id)
        return fail("invalid_request", "every POST carries a JSON body with a request id (8.3)");
      reqKey = `${owner}\u0000${body.id}`;
      const seen = requests.get(reqKey);
      if (seen) {
        if (seen.path === path && seen.bodyHash === hash(JSON.stringify(body))) return seen.response;
        return fail("request_id_conflict", "this request id was accepted with a different path or body (8.3)");
      }
    }

    const remember = (response) => {
      if (reqKey) requests.set(reqKey, { path, bodyHash: hash(JSON.stringify(body)), response });
      return response;
    };

    if (route === "create") {
      if (!hasContent(body.message))
        return fail("invalid_request", "a new conversation starts with its first message (8.3), and a message has at least one of text, data, context or extensions (8.4)");
      const cid = id("cnv");
      const c = { id: cid, owner, events: [], closed: false };
      store.set(cid, c);
      prune();
      record(c, body.message);
      return remember({ status: 201, body: { conversation_id: cid } });
    }

    // 8.13: an unknown Conversation ID and one belonging to someone else "All return the same
    // error", so there is one answer here and it is built once.
    const c = store.get(convId);
    if (!c || c.owner !== owner) return fail("conversation_not_found");

    if (route === "events") {
      const cursor = query.get("cursor");
      let from = 0;
      if (cursor) {
        const at = c.events.findIndex(e => e.id === cursor);
        if (at === -1) return fail("invalid_cursor");
        from = at + 1;
      }
      const events = c.events.slice(from);
      return { status: 200, body: {
        conversation_id: c.id, events,
        // The cursor stands still when there was nothing to report, so a poll does not skip.
        cursor: events.length ? events[events.length - 1].id : (cursor ?? ""),
        has_more: false, ...state(c),
      } };
    }

    // 8.12: "A close sent to a conversation that is already closed returns HTTP 202 and changes
    // nothing", so close is the one route a closed conversation still accepts.
    if (c.closed && route !== "close")
      return remember(fail("conversation_closed"));

    if (route === "close") {
      if (!c.closed) {
        c.closed = true;
        // 8.7: "Every change to handoff, responder, or closed has a state event."
        add(c, { type: "state", ...state(c) });
      }
      return remember({ status: 202, body: { conversation_id: c.id } });
    }

    if (route === "messages") {
      if (!hasContent(body.message))
        return fail("invalid_request", "a message has at least one of text, data, context or extensions (8.4)");
      record(c, body.message);
      return remember({ status: 202, body: { conversation_id: c.id } });
    }

    if (route === "handoff") {
      // 8.9: "If no one is available, handoff goes back to none with responder still agent, and
      // the Company Agent says why in a message." Nobody is ever available here, so it says so
      // at once and `handoff` never becomes pending.
      say(c, "No person is available at this grader: it records what your agent sends and judges it against the specification, and there is nobody here to hand over to.");
      return remember({ status: 202, body: { conversation_id: c.id } });
    }

    if (route === "handoff-cancel") {
      // Nothing to cancel, because nothing was ever pending. 8.9 makes a cancel safe.
      return remember({ status: 202, body: { conversation_id: c.id } });
    }

    return null;
  }

  return { handle, get size() { return store.size; } };
}
