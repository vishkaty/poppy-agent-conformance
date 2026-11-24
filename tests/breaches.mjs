// One deliberate breach per check, shared.
//
// It lives in its own module because two different properties are asserted over it. One is
// coverage: every check must have a breach, so adding a check without a way to fail it breaks
// the suite rather than quietly adding a green light. The other is MONOTONICITY, which the
// enforcement work needs: a rule that can be decided on the request in front of you must fail
// on that request ALONE and also fail inside a log of conforming traffic. A rule that fails
// alone and passes in company cannot be enforced, because the status code and the report would
// disagree about the same request, and it is also a hole in the report.
import { generateKeyPair, SignJWT, exportJWK } from "jose";
import { randomUUID } from "node:crypto";
import * as f from "./fixture.mjs";

export const CTX_A = { identifier: "https://shop.example/poppy", domain: "shop.example" };
export const CTX_B = { identifier: "https://other-shop.example/poppy", domain: "other-shop.example" };

export const keys = await f.agentKeys();
export const conforming = await f.conformingLog(keys);

// One breach per check. Each returns a log that must fail exactly that check.
export const BREACH = {
  // An iss no Company could fetch, so no Company could verify the delegation.
  "session.iss-https":          async () => [await f.request(keys, { claims: { iss: "http://agent.example/agent.json" } })],
  // A delegation signed by a key the agent never published, which is the forgery that
  // verifying against jwks_uri exists to catch.
  "delegation.signature": async () => {
    const stranger = await f.agentKeys();
    const dlgCompact = await f.delegation(stranger);     // signed by the stranger's operator key
    return [await f.request(keys, { dlgCompact })];      // published key set is still ours
  },
  // A header that is present and is not a JWT. It used to pass every check.
  "session.header-jwt": async () => {
    const r = await f.request(keys, {});
    r.headers["poppy-session"] = "not-a-jwt";
    r.sessionHeaderDecodable = false;
    return [r];
  },
  // A request carrying the Session header and no Poppy-Version, which 3.4 makes a per-request
  // failure with its own error. The historical rule below is a different breach: two values
  // inside one Session.
  // An extension declared that the chosen document does not list. This Company lists none by
  // default, so any declaration is one, and that is the realistic shape of the mistake: an agent
  // that declares what it supports rather than what the Company offers.
  "version.extensions-listed": async () => [await f.request(keys, {
    path: "/poppy/orders", sub: "user-one",
    headers: { "poppy-extensions": '"operations";v="3"' } })],
  // An operator signature that covers the method and the target and not the Session header, which
  // is what Web Bot Auth's own defaults produce.
  "session.operator-signature-covers": async () => [await f.request(keys, {
    path: "/poppy/orders", sub: "user-one",
    headers: { "signature-input": 'sig1=("@method" "@target-uri");keyid="k"', signature: "sig1=:abc:" } })],
  // A context field in the wrong format. 8.4 names a language tag of RFC 5646, and an underscore
  // where a hyphen belongs is the mistake a developer actually makes.
  "conversation.context-fields": async () => [await f.request(keys, {
    method: "POST", path: "/poppy/conversations", conversationRoute: "start", sub: "user-one",
    body: JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "hello",
                                                context: { locale: "en_US" } } }) })],
  // One delegated key signing for two Users at one Company, which is what an agent that caches a
  // single delegation per process does. 5.2 names the cost: a leaked key should expose one User.
  "delegation.key-per-user": async () => {
    const dlgCompact = await f.delegation(keys);
    return [await f.request(keys, { dlgCompact, sid: "s1", sub: "user-A", seq: 1, at: 1 }),
            await f.request(keys, { dlgCompact, sid: "s2", sub: "user-B", seq: 2, at: 2 })];
  },
  // A sign-in grant at a Company that offers none. 3.2 forbids starting Direct, Device or
  // Mediated Sign-In there, and the grant is what identifies the attempt on the wire.
  "signin.not-when-disabled": async () => [await f.request(keys, {
    method: "POST", path: "/poppy/token", noSession: true, sub: "user-one", isResource: false,
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=authorization_code&code=abc&client_id=https%3A%2F%2Fagent.example%2Fagent.json" })],
  // A request refused with invalid_session and then sent again, to be refused by the same rule.
  // Section 7 tells an agent to stop until it fixes the cause, and says a new Session is not a fix.
  "session.stops-after-refusal": async () => {
    // 8.3: "To retry a request, the Personal Agent sends it again to the same path with the same
    // ID", so the breach is the same path and the same request id, refused twice over. A bodyless
    // GET cannot express it: two of those to one path are indistinguishable from each other.
    const refused = { rejection: { rule: "session.alg", error: "invalid_session" },
                      response: { status: 400, error: "invalid_session" } };
    const body = JSON.stringify({ id: "r1", message: { author: { type: "agent" }, text: "hello" } });
    const post = (seq) => f.request(keys, { method: "POST", path: "/poppy/conversations", body,
                                            conversationRoute: "start", sub: "user-one",
                                            seq, at: seq, ...refused });
    return [await post(1), await post(2)];
  },
  // A message with none of the four content fields. This Company already answers
  // `invalid_request` for it, as 8.13 says, so a rule had to fault it too.
  "conversation.message-content": async () => [await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                                                       conversationRoute: "start", sub: "user-one",
                                                                       body: JSON.stringify({ id: "r1", message: { author: { type: "agent" } } }) })],
  // A message that never says whether a person or an AI wrote it. Nothing refuses this, which is
  // why it needs a rule: it was answered 201 and reported clean.
  "conversation.message-author":  async () => [await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                                                       conversationRoute: "start", sub: "user-one",
                                                                       body: JSON.stringify({ id: "r1", message: { text: "hello" } }) })],
  // A request id with characters 8.2 does not allow. 8.13 lists "an ID with characters not
  // allowed (8.2)" under invalid_request, and this Company answers exactly that, so a rule had
  // to fault it or the status and the verdict disagreed about one request.
  "conversation.id-format":     async () => [await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                                                     conversationRoute: "start", sub: "user-one",
                                                                     body: JSON.stringify({ id: "msg 1/2", message: { text: "hello" } }) })],
  // A conversation POST with no request id. 8.3 makes it a MUST on the agent and 8.13 names
  // the answer, and a body carrying the id inside `message` with none at the top level is a
  // shape real traffic has had, which is how this rule came to exist.
  "conversation.request-id":    async () => [await f.request(keys, { method: "POST", path: "/poppy/conversations",
                                                                     conversationRoute: "start",
                                                                     body: JSON.stringify({ message: { text: "hello" } }) })],
  "version.sent":               async () => [await f.request(keys, { version: null })],
  "session.header-sent":        async () => [await f.request(keys, { noSession: true })],
  "session.typ":                async () => [await f.request(keys, { sesTyp: "JWT" })],
  "session.alg": async () => {
    // Signed with RS256, which 5.2 forbids: "alg MUST be ES256". Built with a real RSA key
    // rather than by editing the header, so the JWT is one an agent could actually send.
    const rsa = await generateKeyPair("RS256", { extractable: true });
    const dlg = await f.delegation(keys);
    const jwt = await new SignJWT({
      iss: f.CLIENT_ID, aud: f.IDENTIFIER, sid: "s", sub: "u",
      htm: "GET", htu: "https://shop.example/poppy/orders",
      iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
    }).setProtectedHeader({ alg: "RS256", typ: "poppy-session+jwt", poppy_dlg: dlg })
      .sign(rsa.privateKey);
    const r = await f.request(keys, {});
    r.headers["poppy-session"] = jwt;
    return [r];
  },
  "session.aud":                async () => [await f.request(keys, { aud: "https://elsewhere.example/poppy" })],
  "session.htm-htu":            async () => [await f.request(keys, { htu: "https://shop.example/poppy/elsewhere" })],
  "session.iat-window":         async () => [await f.request(keys, { iat: Math.floor(Date.now() / 1000) - 600 })],
  "session.claims-present":     async () => [await f.request(keys, { drop: ["jti"] })],
  "session.sub-stable": async () => {
    const sid = "sid-fixed", dlgCompact = await f.delegation(keys);
    return [await f.request(keys, { sid, sub: "user-a", dlgCompact }),
            await f.request(keys, { sid, sub: "user-b", dlgCompact })];
  },
  "session.jti-unique": async () => {
    // One jti signing two DIFFERENT requests, which cannot be a retry. An identical resend
    // is deliberately not a FAIL: 5.3 leaves rejecting a reused jti to the Company.
    const jti = "reused-" + randomUUID();
    return [await f.request(keys, { jti, path: "/poppy/orders" }),
            await f.request(keys, { jti, path: "/poppy/orders/2" })];
  },
  "delegation.typ":             async () => [await f.request(keys, { dlg: { typ: "JWT" } })],
  "delegation.exp-24h": async () => {
    const iat = Math.floor(Date.now() / 1000);
    return [await f.request(keys, { dlg: { iat, exp: iat + 86400 + 60 } })];
  },
  "delegation.no-identifiers": async () => {
    // the delegation naming the User ID, which 5.2 forbids outright
    const sub = "user-leaked-" + randomUUID();
    const dlgCompact = await f.delegation(keys, { payload: { note: sub } });
    return [await f.request(keys, { sub, dlgCompact })];
  },
  // Two versions inside ONE Session, which is the historical rule. A missing header is
  // version.sent's breach, and using it here was how the two rules came to overlap.
  "version.constant": async () => {
    const sid = "sid-version", dlgCompact = await f.delegation(keys);
    return [await f.request(keys, { sid, dlgCompact, version: "1.0" }),
            await f.request(keys, { sid, dlgCompact, version: "1.3" })];
  },
  "session.signature": async () => {
    const r = await f.request(keys, {});
    const parts = r.headers["poppy-session"].split(".");
    parts[2] = "A".repeat(parts[2].length);        // the signature destroyed
    r.headers["poppy-session"] = parts.join(".");
    return [r];
  },
  "delegation.no-private-key": async () => {
    const priv = await exportJWK(keys.delegated.privateKey);   // carries `d`
    return [await f.request(keys, { dlgCompact: await f.delegation(keys, { payload: { cnf: { jwk: priv } } }) })];
  },
  "delegation.not-expired": async () => {
    const now = Math.floor(Date.now() / 1000);
    return [await f.request(keys, { dlgCompact: await f.delegation(keys, { iat: now - 7200, exp: now - 3600 }), at: now, iat: now })];
  },
  "delegation.iss-matches": async () =>
    [await f.request(keys, { dlgCompact: await f.delegation(keys, { payload: { iss: "https://other.example/agent.json" } }) })],
  "session.ath": async () => [await f.request(keys, { token: "tok-x", ath: "not-the-hash" })],
  "delegation.present": async () => [await f.request(keys, { noDlg: true })],
  "delegation.alg": async () => {
    const rsa = await generateKeyPair("RS256", { extractable: true });
    const now = Math.floor(Date.now() / 1000);
    const dlg = await new SignJWT({ iss: f.CLIENT_ID, iat: now, exp: now + 3600,
      jti: randomUUID(), cnf: { jwk: keys.jwk } })
      .setProtectedHeader({ alg: "RS256", typ: "poppy-delegation+jwt" }).sign(rsa.privateKey);
    return [await f.request(keys, { dlgCompact: dlg })];
  },
  "session.not-on-documents": async () => {
    // The agent sending its Session JWT to poppy.json, which 5.2 forbids outright.
    const r = await f.request(keys, { path: "/.well-known/poppy.json" });
    r.isResource = false; r.mustNotCarry = true;
    r.classifiedAs = "a discovery or description document, or an OAuth endpoint (5.2)";
    r.sessionHeaderCount = 1;
    return [r];
  },
};

// Rules a CONFORMING log cannot reach, with the reason. The control asserts that every rule
// passes on conforming traffic, which was true while every rule was about a request an agent
// sends. A rule about what an agent does AFTER being refused cannot be reached by traffic that is
// never refused, and making it PASS on silence instead would be the exact failure this file's
// neighbour test forbids: "a grader that reports PASS on silence is the most damaging failure
// available to it". So the rule abstains there, and the abstention is declared here rather than
// tolerated quietly. The test also asserts each listed rule really is unreached, so this list
// cannot hide a rule that fails.
export const CONFORMING_UNREACHED = {
  "version.extensions-listed":
    "this Company lists no extensions, so a conforming agent declares none and sends no Poppy-Extensions header at all. 3.4 asks for the header only when an agent uses an extension with the Company",
  "session.stops-after-refusal":
    "it judges what an agent does after this Company refuses a request under a rule, and conforming traffic is never refused, so there is no refusal for the control to stop sending after",
};

// The same idea for the OTHER control, the one built entirely by the protocol authors own signing
// code. It is a different body of traffic and reaches a different set of rules: it mints Session
// JWTs and sends no token request at all, so the sign-in rule has no grant to judge there, while
// the conforming log above does send a refresh and reaches it. Two lists rather than one, because
// a shared list would have to claim a rule is unreachable in traffic that reaches it.
export const REFERENCE_UNREACHED = {
  ...CONFORMING_UNREACHED,
  "session.operator-signature-covers":
    "this control is built with the authors own signing helpers, which mint Session JWTs and delegations and do no Web Bot Auth signing, so its requests carry no operator signature for 5.3's sentence to judge",
  "signin.not-when-disabled":
    "this control is Session traffic built with the authors own helpers and sends no token request, so there is no grant for 3.2's prohibition to be judged on",
};
