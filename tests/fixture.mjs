// A conforming agent's traffic, and one deliberate breach per rule.
//
// Hostnames are the reserved example names of RFC 2606, not the hostnames of any real
// deployment. A public test suite that hardcodes somebody live infrastructure both
// advertises it and breaks when it moves.
//
// Real ES256 keys and real compact JWTs, not hand-built strings. A fixture that could not
// exist on the wire is the quickest way to write a check that passes on fiction: this
// project has a recorded case of an SSRF pin that never ran because every fixture used an
// address literal, and the suite was green throughout.
import { SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint } from "jose";
import { randomUUID, createHash } from "node:crypto";

export const IDENTIFIER = "https://shop.example/poppy";
export const DOMAIN = "shop.example";
export const CLIENT_ID = "https://agent.example/agent.json";
const ORIGIN = "https://shop.example";

export async function agentKeys() {
  const operator = await generateKeyPair("ES256", { extractable: true });
  const delegated = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(delegated.publicKey);
  // The operator's PUBLIC key, which is what the agent publishes at its jwks_uri and what a
  // Company fetches to verify a delegation (5.2 step 1). Carried here so a conforming fixture
  // request can model a Company that did fetch it, which is the ordinary case.
  const operatorJwk = await exportJWK(operator.publicKey);
  return { operator, delegated, jwk, operatorJwk,
           thumb: await calculateJwkThumbprint(jwk, "sha256"),
           operatorThumb: await calculateJwkThumbprint(operatorJwk, "sha256") };
}

// What server.mjs attaches to a record once it has fetched the agent's documents. Default:
// the fetch succeeded and the operator's key is published. `over.issuerKeys` replaces it, and
// `over.noIssuerKeys` models a Company that did not look.
export function issuerKeysFor(keys, over = {}) {
  if (over.noIssuerKeys) return undefined;
  if (over.issuerKeys) return over.issuerKeys;
  // Published under `k1`, which is the kid `delegation()` above writes into the delegation
  // header. A real agent chooses its own kid and publishes the key under it; 5.2 says `kid`
  // "names the key in `jwks_uri`", so these two have to agree or the fixture models an agent
  // whose key set does not match its own delegations.
  return { outcome: "ok", iss: CLIENT_ID, jwksUri: "https://agent.example/jwks.json",
           keys: [{ ...keys.operatorJwk, kid: "k1" }], kids: ["k1"],
           source: "fetch", fetchedAt: Math.floor(Date.now() / 1000), ageSeconds: 0 };
}

export async function delegation(keys, over = {}) {
  const iat = over.iat ?? Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: CLIENT_ID, iat, exp: over.exp ?? iat + 3600,
    jti: randomUUID(), cnf: { jwk: keys.jwk }, ...over.payload,
  })
    .setProtectedHeader({ alg: "ES256", typ: over.typ ?? "poppy-delegation+jwt", kid: "k1" })
    .sign(keys.operator.privateKey);
}

// One recorded request, conforming unless `over` says otherwise.
export async function request(keys, over = {}) {
  const method = over.method ?? "GET";
  const path = over.path ?? "/poppy/orders";
  const at = over.at ?? Math.floor(Date.now() / 1000);
  const dlg = over.dlgCompact ?? await delegation(keys, over.dlg ?? {});
  const claims = {
    iss: CLIENT_ID, aud: over.aud ?? IDENTIFIER,
    sid: over.sid ?? "sid-" + randomUUID(), sub: over.sub ?? "user-" + randomUUID(),
    htm: over.htm ?? method, htu: over.htu ?? ORIGIN + path,
    iat: over.iat ?? at, jti: over.jti ?? randomUUID(),
    ...(over.ath !== undefined ? { ath: over.ath } : {}),
    ...(over.agent_id !== undefined ? { agent_id: over.agent_id } : {}),
    ...over.claims,
  };
  for (const k of over.drop ?? []) delete claims[k];
  const jwt = await new SignJWT(claims)
    .setProtectedHeader({ alg: over.alg ?? "ES256", typ: over.sesTyp ?? "poppy-session+jwt",
                          kid: keys.thumb, poppy_dlg: over.noDlg ? undefined : dlg })
    .sign(keys.delegated.privateKey);
  return {
    host: DOMAIN, method, path, url: ORIGIN + path, at,
    // the fields record.mjs produces, so a fixture cannot pass a check by omitting them
    isResource: true, isPage: false, mustNotCarry: false,
    sessionHeaderCount: over.noSession ? 0 : 1, sessionHeaderDecodable: !over.noSession,
    sessionHeaderDuplicated: false,
    headers: {
      "poppy-session": over.noSession ? undefined : jwt,
      "poppy-version": over.version === null ? undefined : (over.version ?? "1.0"),
      ...(over.token ? { authorization: `DPoP ${over.token}` } : {}),
      // Merged last, so a test can set a content type or any other header. It could not before,
      // and a rule that reads one then saw nothing: the THIRD field this fixture silently dropped
      // while the test that depended on it read as though it had been set.
      ...(over.headers ?? {}),
    },
    body: over.body ?? "",
    conversationRoute: over.conversationRoute ?? null,
    // Carried through, because a test that says a body was truncated or that a target was refused
    // and is then silently given a clean record is a test that proves the opposite of what it
    // reads. Two rules were nearly shipped on exactly that: the fixture dropped these fields and
    // the "does not accuse" cases passed for free.
    ...(over.bodyComplete !== undefined ? { bodyComplete: over.bodyComplete } : {}),
    ...(over.bodyTruncated !== undefined ? { bodyTruncated: over.bodyTruncated } : {}),
    ...(over.unsafeTarget !== undefined ? { unsafeTarget: over.unsafeTarget } : {}),
    ...(over.refused !== undefined ? { refused: over.refused } : {}),
    // `seq` is how the report and the history rules order a log, and it was the one field a test
    // could ask for and silently not get. A rule that looks for a LATER request then found none,
    // every time, and passed.
    ...(over.seq !== undefined ? { seq: over.seq } : {}),
    ...(over.rejection !== undefined ? { rejection: over.rejection } : {}),
    ...(over.response !== undefined ? { response: over.response } : {}),
    ...(over.isResource !== undefined ? { isResource: over.isResource } : {}),
    issuerKeys: issuerKeysFor(keys, over),
  };
}

// A short conforming session: three requests, one Session, stable sub.
// An operator signature as Web Bot Auth produces one, covering what 5.3 makes a MUST. The
// component list is what the rule reads; the signature value itself is never verified here,
// because 5.3 gives that to the key directory and this grader holds no operator keys.
const SIGNED = { "signature-input": 'sig1=("@method" "@target-uri" "poppy-session");keyid="operator"',
                 signature: "sig1=:ZmFrZQ==:" };
const SIGNED_WITH_TOKEN = { "signature-input": 'sig1=("@method" "@target-uri" "poppy-session" "authorization");keyid="operator"',
                            signature: "sig1=:ZmFrZQ==:" };

export async function conformingLog(keys, over = {}) {
  const sid = "sid-" + randomUUID(), sub = "user-" + randomUUID();
  const dlgCompact = await delegation(keys);
  // One of these carries an access token with a correct `ath`, so the signed-in rules have
  // something to judge. Without it session.ath is INCONCLUSIVE on the control, and a
  // control that abstains proves less than one that passes.
  const token = "tok-" + randomUUID();
  // A real conforming agent does discovery first, with NO Session header, so the control
  // includes it. Without a document fetch session.not-on-documents abstains, and a control
  // that abstains proves less than one that passes.
  const discovery = {
    host: DOMAIN, method: "GET", path: "/.well-known/poppy.json",
    url: ORIGIN + "/.well-known/poppy.json", at: Math.floor(Date.now() / 1000),
    isResource: false, isPage: false, mustNotCarry: true,
    classifiedAs: "a discovery or description document, or an OAuth endpoint (5.2)",
    headers: {}, body: null, sessionHeaderCount: 0, sessionHeaderDecodable: false,
    sessionHeaderDuplicated: false,
  };
  // A refresh at a Company with sign-in switched off, which 3.2 explicitly keeps working:
  // "Refresh tokens the Company issued earlier keep working until it revokes them." It carries no
  // Session header, because 5.2 says OAuth endpoints do not, and it gives the sign-in rule
  // something to pass on instead of abstaining.
  const refresh = {
    host: DOMAIN, method: "POST", path: "/poppy/token", url: ORIGIN + "/poppy/token",
    at: Math.floor(Date.now() / 1000), isResource: false, isPage: false, mustNotCarry: true,
    classifiedAs: "a discovery or description document, or an OAuth endpoint (5.2)",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=refresh_token&refresh_token=rt_example", bodyComplete: true,
    sessionHeaderCount: 0, sessionHeaderDecodable: false, sessionHeaderDuplicated: false,
  };
  return Promise.all([
    discovery, refresh,
    // 5.3: a conforming agent SHOULD sign these with Web Bot Auth, and the signature MUST cover
    // `poppy-session`, and `authorization` wherever a token is sent. Without them the rule about
    // what a signature covers abstains here, and a control that abstains proves less than one
    // that passes.
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders", headers: SIGNED }),
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders/1", headers: SIGNED }),
    // 8.3: "Every `POST` body has an `id`, chosen by the Personal Agent". A conforming agent
    // sends one, and the record carries which conversation route it is, so the rule about
    // request IDs has something to pass on.
    request(keys, { ...over, sid, sub, dlgCompact, method: "POST", path: "/poppy/conversations",
                    // 8.4 wants one of text, data, context or extensions; 8.8 wants the agent to
                    // say whether a person or an AI wrote it. A control that omitted either would
                    // make those rules abstain, and a control that abstains proves less than one
                    // that passes.
                    // A context too, in the formats 8.4 names, so the rule about them is reached
                    // and passes here rather than abstaining.
                    body: JSON.stringify({ id: "req-" + randomUUID(),
                                           message: { author: { type: "agent" }, text: "hello",
                                                      context: { locale: "en-US",
                                                                 time_zone: "America/Los_Angeles",
                                                                 user_available: true } } }),
                    headers: SIGNED,
                    conversationRoute: "start" }),
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders/2", headers: SIGNED_WITH_TOKEN,
                    token, ath: createHash("sha256").update(token).digest("base64url") }),
  ]);
}

// The Company these fixtures describe, which sets `auth.disabled` exactly as the deployed one
// does. A rule that asks whether sign-in is offered has to be told, and a ctx that left it out
// made such a rule abstain here while the deployment judged it.
export const ctx = { identifier: IDENTIFIER, domain: DOMAIN, authDisabled: true };
export const athOf = t => createHash("sha256").update(t).digest("base64url");
