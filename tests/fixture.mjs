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
    },
    body: over.body ?? "",
    issuerKeys: issuerKeysFor(keys, over),
  };
}

// A short conforming session: three requests, one Session, stable sub.
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
  return Promise.all([
    discovery,
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders" }),
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders/1" }),
    request(keys, { ...over, sid, sub, dlgCompact, method: "POST", path: "/poppy/conversations" }),
    request(keys, { ...over, sid, sub, dlgCompact, path: "/poppy/orders/2",
                    token, ath: createHash("sha256").update(token).digest("base64url") }),
  ]);
}

export const ctx = { identifier: IDENTIFIER, domain: DOMAIN };
export const athOf = t => createHash("sha256").update(t).digest("base64url");
