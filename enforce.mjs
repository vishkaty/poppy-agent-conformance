// What this Company REFUSES, as opposed to what it reports.
//
// The grader records every request and puts its verdicts in a private report. That alone makes
// it a Company that answers 200 to a forged Session JWT, and a builder whose agent passes here
// would then fail against a real Company: their recovery code, which section 7 puts
// requirements on, is never exercised. So requests that fail a rule a Company can decide on
// are refused with the error 1.0 names.
//
// ONE implementation decides both. `enforce` calls `grade` on a log of exactly the request in
// front of it and reads the same verdicts, the same `why`, and the same quoted sentences the
// report prints. There is no second rule engine to drift, which is the fix this project has
// already applied to the OpenAPI document and the discovery document.
//
// A wrong FAIL in a report is this instrument's most expensive output. A wrong REFUSAL is
// worse: the agent cannot proceed at all and will conclude the Company is broken. Two things
// bound that. Only rules that are MONOTONE are enforced, meaning a rule that fails on one
// request also fails on any log containing it, which tests/monotone.test.mjs asserts over
// every id below. And nothing is refused unless it is a destination: 5.3 says "An endpoint
// that uses no Session claims MAY handle a request without verifying the header or requiring
// one", and 5.2 says documents and OAuth endpoints do not carry the header at all.
import { grade } from "./checks.mjs";

// In the order 5.3 verifies, which is also the precedence when a request fails several.
//
// It matters which one an agent is told. Section 7 gives invalid_session "A new Session
// doesn't fix it: the Personal Agent stops sending the request until it fixes the cause" and
// version_unsupported "fetches poppy.json again... starts a new Session and sends the request
// again, once". A request with a bad delegation AND no version that was told
// version_unsupported would start a new Session, fail the same way, and loop.
export const ENFORCED = [
  "session.header-sent",      // 5.3: "MUST reject a request without the Session header when handling it depends on Session claims"
  "session.header-jwt",       // 5.2: "The header holds a JWT that the Personal Agent signs for that one request". Two headers joined are not a JWT either.
  // Section 3, and the precondition of the fetch below: an iss that is not an HTTPS URL is one
  // no Company can fetch the client metadata from, so nothing further can be decided.
  "session.iss-https",
  "delegation.present",       // 5.2: "MUST reject, with invalid_session, a Session JWT without a delegation"
  "delegation.alg",
  "delegation.iss-matches",
  // 5.2 step 1, and the forgery everything else here could not see: a delegation signed by a
  // key the agent never published. Before delegation.typ on purpose, because a forged
  // delegation may also carry a wrong typ and the signature is the thing worth saying.
  "delegation.signature",
  "delegation.typ",           // 5.2 delegated keys, the three checks, and "a Session JWT whose delegation fails any of these checks"
  "delegation.not-expired",
  "delegation.exp-24h",
  // `alg` before the signature, though 5.3 step 2 verifies the signature first. An
  // unacceptable alg is the CAUSE and a failed signature is its symptom: a JWT signed RS256
  // cannot verify against the ES256 key its delegation names, so both fail, and "alg MUST be
  // ES256" is the sentence that tells a builder what to change. Both are invalid_session, so
  // this changes only what the agent is told, never the status.
  "session.alg",              // 5.2: "`alg` MUST be `ES256`"
  "session.signature",        // 5.3 step 2: "Verifies the JWT's delegation and signature"
  "session.typ",              // 5.3 step 2: "then `typ` and the claims above"
  "session.aud",
  "session.htm-htu",
  "session.iat-window",
  "session.claims-present",
  "session.ath",              // 5.3 step 3
  "version.sent",             // 3.4: "MUST also check `Poppy-Version`... rejects a request without it"
];

export const ENFORCE_EXCLUDED = {
  // 8.13 puts a missing request id under `invalid_request`. This enforcement path speaks
  // `invalid_session` and `version_unsupported` only, so refusing from here would answer the
  // wrong error for the breach; the conversation handler already answers it where the
  // specification does.
  "conversation.request-id": "8.13 puts a missing request id under `invalid_request`, and this path answers `invalid_session` or `version_unsupported` only, so enforcing it here would name the wrong error. The conversation handler answers it where the specification puts it.",

  "session.jti-unique": "Reuse needs two requests to observe, so it is not decidable on the request in front of you, and 5.3 only says a Company MAY reject a reused jti.",
  "session.sub-stable": "Change within a Session needs two requests in it, and 1.0 names no Company error for it. 5.3 step 4 treats an unknown client_id, sid and User ID combination as a NEW Session rather than a failed check.",
  "version.constant": "Sameness across a Session needs two requests in it and names no Company error. Its per-request half is version.sent, which is enforced.",
  "session.not-on-documents": "It is about documents, which this Company serves rather than refuses, and 5.2 says documents do not carry the header. There is no error to return at a document.",
  "delegation.no-identifiers": "A privacy MUST NOT on the agent, not among the delegation checks 5.2 tells a Company to reject on. It is also the most contestable accusation this grader makes, so it is reported and never refused.",
  "delegation.no-private-key": "The same, and a JWK carrying a private member still verifies, so the breach is reported rather than used to close the door.",
};

const INVALID_SESSION = 400, VERSION_UNSUPPORTED = 400;

// The error each enforced rule maps to. Everything a Session check decides is
// invalid_session, which 5.3 states outright: "A failed Session check returns HTTP 400 with
// {"error": "invalid_session"}". 400 and not 401 is deliberate in the specification, "so that
// OAuth libraries, which treat a 401 as a problem with the access token, don't discard a valid
// token".
//
// session_ended appears nowhere, on purpose. Section 7 gives it the OPPOSITE instruction to
// invalid_session, and this Company ends no Session and holds no account, so no failure here
// can be one. A test asserts it is never emitted.
function errorFor(id) {
  return id === "version.sent"
    ? { status: VERSION_UNSUPPORTED, error: "version_unsupported" }
    : { status: INVALID_SESSION, error: "invalid_session" };
}

// null when the request stands, or the refusal to send.
export function enforce(record, ctx) {
  // Only destinations. A document, a website page, a misdirected target, a refused target and
  // anything that is not a Session destination are answered as before.
  if (!record || !record.isResource) return null;

  const verdicts = grade([record], ctx);
  const byId = new Map(verdicts.map(v => [v.id, v]));
  for (const id of ENFORCED) {
    const v = byId.get(id);
    if (!v || v.verdict !== "FAIL") continue;
    const { status, error } = errorFor(id);
    return {
      rule: id, status,
      headers: { "content-type": "application/json" },
      // 5.3: "Either MAY include an error_description for the developer, as in RFC 6749 §5.2."
      // It is the report's own sentence, so what the agent is told and what the report says
      // cannot differ. The checks' `why` carries no JWT, signature or token by construction,
      // and a test asserts that here too.
      body: { error, error_description: `${id}: ${v.why}` },
    };
  }
  return null;
}

// An access token this Company never issued.
//
// Section 7: "invalid_token | 401 | The access token is expired, revoked, or invalid", and
// access token errors "are in the WWW-Authenticate header". 4.5: "A service that gets a token
// not issued for it returns invalid_token with resource_metadata in its challenge (RFC 9728
// §5.1)". This Company runs no token endpoint, so every Authorization header it receives is
// such a token. It is a separate answer from a Session failure, and it comes second: 5.3's
// steps are what a Company "MUST complete before relying on Session claims", so a request
// that fails both is told about its Session first.
export function tokenChallenge(origin) {
  const challenge = `Bearer error="invalid_token", error_description="this grader issues no access tokens, so this one was not issued for it", `
    + `resource_metadata="${String(origin).replace(/\/+$/, "")}/.well-known/oauth-protected-resource"`;
  return { status: 401, headers: { "content-type": "application/json", "www-authenticate": challenge },
           body: { error: "invalid_token" } };
}
