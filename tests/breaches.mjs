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
