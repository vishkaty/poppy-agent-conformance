// The checks a Company can make about a Personal Agent, and nothing else can.
//
// Every check quotes the sentence of published 1.0 it enforces, verbatim, and the suite
// refuses a check whose quote is not in the capture. That is the one discipline carried
// over from the register: an id that exists is not a rule that applies.
//
// Three verdicts, never two. INCONCLUSIVE is not a soft FAIL: it means the agent never
// reached the point the rule governs, and reporting it as a pass or a failure would be a
// claim about code that never ran. Two of the four defects this project once found in its
// own runner were rules failing an agent that followed the document, so a wrong FAIL is
// the expensive direction and silence is cheaper than a guess.
//
// These functions are pure, over a recorded request log. The HTTP layer records; this
// judges. That split is deliberate: it makes every verdict reproducible from a log file
// without a network, a tunnel or an agent.

// Our acceptance window. 5.3 leaves it to the Company, "such as one minute", and the
// guides say "about one minute, plus a small clock skew" and elsewhere "such as 30
// seconds". A flat 60 was tighter than the authors' own suggestion, so a conforming agent
// on a slightly skewed clock would have been failed. Both numbers are printed in the
// verdict, because a FAIL that hides its own threshold cannot be argued with.
export const WINDOW_SECONDS = 60;
export const SKEW_SECONDS = 30;

import { createHash, createPublicKey, verify as verifySig, constants as cryptoConstants } from "node:crypto";

// A request as the grader records it.
//   { host, method, url, path, headers: {...}, body, at }   at = Unix seconds we saw it

const b64urlJson = s => {
  try { return JSON.parse(Buffer.from(s, "base64url").toString("utf8")); }
  catch { return null; }
};
export function decodeJwt(compact) {
  if (typeof compact !== "string") return null;
  const parts = compact.split(".");
  if (parts.length !== 3) return null;
  const header = b64urlJson(parts[0]), payload = b64urlJson(parts[1]);
  if (!header || !payload) return null;
  return { header, payload, signature: parts[2], compact };
}

// Requests that carry a Session header, which are the only ones most rules govern.
export const sessionRequests = log => log
  .map(r => ({ r, jwt: decodeJwt(r.headers?.["poppy-session"]) }))
  .filter(x => x.jwt);

// JWS verification, synchronous. node:crypto takes a JWK directly and understands the raw
// R||S signature form JWS uses via dsaEncoding, so this needs no async and the checks stay
// pure functions over a log. Returns true, false, or null when we cannot judge the
// algorithm, which is reported as INCONCLUSIVE rather than guessed.
function verifyCompact(compact, jwk) {
  const parts = String(compact ?? "").split(".");
  if (parts.length !== 3 || !jwk) return null;
  let key;
  try { key = createPublicKey({ key: jwk, format: "jwk" }); } catch { return null; }
  const header = b64urlJson(parts[0]);
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sig = Buffer.from(parts[2], "base64url");
  try {
    switch (header?.alg) {
      case "ES256": return verifySig("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
      case "RS256": return verifySig("sha256", data, key, sig);
      case "PS384": return verifySig("sha384", data,
        { key, padding: cryptoConstants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, sig);
      default: return null;
    }
  } catch { return false; }
}

const PASS = why => ({ verdict: "PASS", why });
// FAIL carries the records that decided it, so a report can show the builder the request
// and not only a sentence about it. A FAIL a builder cannot trace to a request is one they
// have to ask us about, and this grader is meant to answer without us.
const FAIL = (why, evidence = [], decidedBy = []) => ({ verdict: "FAIL", why, evidence, decidedBy });
// SKIP carries WHY it abstained. "unreached" means the agent never got to the point the
// rule governs, which the builder can change; "grader" means this grader could not judge
// it, which the builder cannot. Reporting both as one label blames the builder for our
// limits.
// Record the message and the request together, in one statement, so it can be the body of
// an `if` without braces.
const note = (bad, hits, r, msg) => { bad.push(msg); hits.push(r); };

const SKIP = (why, cause = "unreached") => ({ verdict: "INCONCLUSIVE", why, cause });

// `htu` is the request URL without query or fragment (5.2), so the comparison is against
// the URL we served, not the one we expected.
// 5.3 compares htm and htu "as RFC 9449 §4.3 describes for DPoP proofs", and that section
// applies RFC 3986 normalization first, so https://host:443/p and https://HOST/p are the
// same URI as https://host/p. Comparing raw strings reported both as mismatches. Trailing
// slash and path case stay significant, which RFC 3986 also requires.
// RFC 3986 section 6.2.2, which is the normalization RFC 9449 section 4.3 says to apply:
// the hex digits of a percent-encoded octet are compared without regard to case, and an
// octet encoding an UNRESERVED character is decoded. Reserved octets such as %2F are kept
// encoded, because decoding one would change which path it is. Without this an agent whose
// library writes `~` where a proxy writes `%7E` was failed for a difference the referenced
// RFC says is none.
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
function normalizePath(path) {
  return String(path).replace(/%([0-9A-Fa-f]{2})/g, (whole, hex) => {
    const ch = String.fromCharCode(parseInt(hex, 16));
    return UNRESERVED.test(ch) ? ch : `%${hex.toUpperCase()}`;
  });
}

function normalizeUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (!u.protocol || !u.host) return null;
  return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${normalizePath(u.pathname)}`;   // URL drops a default port
}
const htuOf = r => normalizeUrl(r.url);

// Is this `typ` the media type 5.2 requires?
//
// 5.2 says "`typ` MUST be `poppy-session+jwt` ... (RFC 8725 §3.11)", and RFC 8725 builds on
// RFC 7515 section 4.1.9, where a `typ` containing no slash is treated as though
// `application/` were prepended, and media type names are compared without regard to case.
// So `application/poppy-session+jwt` names exactly the same type as the literal. Failing an
// agent over that would be failing it for a spelling, and a wrong FAIL is the most expensive
// thing this instrument can produce. The spelling IS reported, because a stricter Company may
// compare the literal and a builder should know.
function typIs(value, want) {
  if (typeof value !== "string") return { ok: false, exact: false };
  const seen = value.toLowerCase().replace(/^application\//, "");
  return { ok: seen === want, exact: value === want };
}

export const CHECKS = [
  {
    id: "session.header-sent",
    section: "5.2",
    quote: "The Personal Agent MUST send a `Poppy-Session` header on every request to a Company's APIs, conversations, and other resource endpoints this protocol or an extension defines.",
    run(log) {
      const resource = log.filter(r => r.isResource);
      if (!resource.length) return SKIP("the agent made no request to a resource endpoint");
      const bare = resource.filter(r => !r.headers?.["poppy-session"]);
      return bare.length
        ? FAIL(`${bare.length} resource request(s) carried no Session header`,
               bare.slice(0, 3).map(r => `${r.method} ${r.path}`), bare)
        : PASS(`every one of ${resource.length} resource request(s) carried the header`);
    },
  },
  {
    id: "session.header-jwt",
    section: "5.2",
    quote: "The header holds a JWT that the Personal Agent signs for that one request, with a delegated key that a key from its `jwks_uri` vouches for",
    // The gap this filled: a header present but not a JWT at all passed EVERYTHING. Every
    // Session rule reads `sessionRequests`, which decodes the header and skips what it cannot
    // decode, and session.header-sent only asks whether a value was sent. So an agent that
    // sent the literal string "not-a-jwt" was told nothing was wrong, and under enforcement
    // it was answered 200. Found by writing the test that the status and the verdict can
    // never disagree.
    //
    // It covers BOTH ways the sentence can be broken, because there is one sentence and this
    // project refuses two checks for one. Two Poppy-Session headers are joined by Node into
    // one undecodable string, so a repeated header and a header holding something that is not
    // a JWT are the same failure of the same rule, and the evidence says which it was.
    run(log) {
      const carrying = log.filter(r => r.isResource && r.headers?.["poppy-session"] !== undefined);
      if (!carrying.length) return SKIP("no request to a resource endpoint carried the header");
      const bad = [], hits = [];
      for (const r of carrying) {
        if (r.sessionHeaderDuplicated)
          note(bad, hits, r, `${r.method} ${r.path}: ${r.sessionHeaderCount} Poppy-Session headers, so no single JWT signs the request`);
        else if (!decodeJwt(r.headers["poppy-session"]))
          note(bad, hits, r, `${r.method} ${r.path}: the header held ${JSON.stringify(String(r.headers["poppy-session"]).slice(0, 24))}, which is not a JWT`);
      }
      return bad.length
        ? FAIL("a Poppy-Session header did not hold one JWT for that request", bad.slice(0, 3), hits)
        : PASS(`every one of ${carrying.length} Session header(s) held a single decodable JWT`);
    },
  },
  {
    id: "session.typ",
    section: "5.2",
    quote: "`typ` MUST be `poppy-session+jwt`, so the JWT can't be mistaken for a client assertion, delegation, or any other JWT",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const judged = s.map(x => ({ ...x, t: typIs(x.jwt.header.typ, "poppy-session+jwt") }));
      const bad = judged.filter(x => !x.t.ok);
      if (bad.length)
        return FAIL(`typ was not poppy-session+jwt`,
                    [...new Set(bad.map(x => JSON.stringify(x.jwt.header.typ)))].slice(0, 3), bad.map(x => x.r));
      const loose = [...new Set(judged.filter(x => !x.t.exact).map(x => JSON.stringify(x.jwt.header.typ)))];
      return loose.length
        ? PASS(`every Session JWT named the media type poppy-session+jwt, but not with the exact spelling 5.2 gives: ${loose.slice(0, 2).join(", ")}. RFC 7515 makes these the same type; a Company that compares the literal would reject it`)
        : PASS("every Session JWT declared poppy-session+jwt");
    },
  },
  {
    id: "session.alg",
    section: "5.2",
    quote: "`alg` MUST be `ES256`, so every Personal Agent and Company can work together.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = s.filter(x => x.jwt.header.alg !== "ES256");
      return bad.length
        ? FAIL("a Session JWT was not signed with ES256", [...new Set(bad.map(x => String(x.jwt.header.alg)))], bad.map(x => x.r))
        : PASS("every Session JWT used ES256");
    },
  },
  {
    id: "session.aud",
    section: "5.2",
    quote: "`aud` is the Company's identifier (3.2), as a single string",
    // The identifier is ours, so this is the check an agent cannot fake and a second
    // Company is needed to catch: an agent that sends one Company's aud to another has
    // built a token that the other MUST reject.
    run(log, ctx) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = s.filter(x => x.jwt.payload.aud !== ctx.identifier);
      if (bad.length) return FAIL(
        `aud was not this Company's identifier, ${ctx.identifier}`,
        [...new Set(bad.map(x => JSON.stringify(x.jwt.payload.aud)))].slice(0, 3), bad.map(x => x.r));
      const arrays = s.filter(x => Array.isArray(x.jwt.payload.aud));
      return arrays.length ? FAIL("aud was an array, and 1.0 requires a single string", [], arrays.map(x => x.r))
                           : PASS(`aud was exactly ${ctx.identifier} on every request`);
    },
  },
  {
    id: "session.htm-htu",
    section: "5.2",
    quote: "`htm` and `htu` are the request's method and URL, without the query or fragment",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], unusable = [], hits = [];
      for (const { r, jwt } of s) {
        const want = htuOf(r);
        // A relative or unparseable recorded url means the LOG is wrong, not the agent. It
        // used to make htuOf return null and the comparison silently skip, so a wrong htu
        // passed: a check that cannot fail. Say so instead of judging.
        if (!want) { unusable.push(`${r.method} ${r.path}: the recorded url is not absolute`); continue; }
        if (jwt.payload.htm !== r.method) note(bad, hits, r, `${r.method} ${r.path}: htm was ${JSON.stringify(jwt.payload.htm)}`);
        else {
          const got = normalizeUrl(jwt.payload.htu);
          if (!got) note(bad, hits, r, `${r.method} ${r.path}: htu was ${JSON.stringify(jwt.payload.htu)}, not an absolute URL`);
          else if (got !== want) note(bad, hits, r, `${r.method} ${r.path}: htu was ${got}, served ${want}`);
        }
      }
      if (unusable.length) return SKIP(`the recorder did not give an absolute url: ${unusable[0]}`, "grader");
      return bad.length ? FAIL("htm or htu did not match the request", bad.slice(0, 3), hits)
                        : PASS(`htm and htu matched on all ${s.length} request(s)`);
    },
  },
  {
    id: "session.iat-window",
    section: "5.2",
    quote: "`iat` is when the Personal Agent signed it, in Unix seconds",
    // 5.3 leaves the window to the Company, "such as one minute", so a FAIL here names our
    // window rather than implying the spec fixed one.
    // The sentence quoted states no window: it says what `iat` IS. The window is this Company's
    // to choose, and 5.3 says so in those words, "an acceptance window it chooses, such as one
    // minute". So a FAIL here is this Company's threshold applied to the agent's clock, which is
    // why the verdict prints both clocks and the threshold instead of only a verdict.
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = []; const hits = []; const offsets = [];
      for (const { r, jwt } of s) {
        const iat = jwt.payload.iat;
        if (typeof iat !== "number") { note(bad, hits, r, `${r.method} ${r.path}: iat was ${JSON.stringify(iat)}, not a number`); continue; }
        const skew = Math.abs(r.at - iat);
        if (skew > WINDOW_SECONDS + SKEW_SECONDS) {
          // BOTH clocks, by number. This rule compares the agent's iat with our own
          // Date.now(), and the canary that gates every run signs with that same clock, so a
          // deployment whose clock has drifted fails every conforming agent while its own
          // control passes. Nothing inside this process can detect that, so it is disclosed
          // instead: a builder who sees our clock beside theirs can tell in one glance.
          note(bad, hits, r, `${r.method} ${r.path}: iat was ${skew}s from when we saw it (your iat ${iat}, our clock ${r.at})`);
          offsets.push(r.at - iat);
        }
      }
      if (!bad.length) return PASS(`iat was within ${WINDOW_SECONDS + SKEW_SECONDS}s on every request`);
      // A constant offset across several requests is what a wrong clock looks like, on either
      // side. Said only when it IS constant, so the sentence carries information: two requests
      // off by wildly different amounts are not a clock.
      const spread = offsets.length > 1 ? Math.max(...offsets) - Math.min(...offsets) : null;
      const constant = offsets.length > 1 && spread <= SKEW_SECONDS;
      return FAIL(`iat fell outside our acceptance window of ${WINDOW_SECONDS}s plus ${SKEW_SECONDS}s of clock skew`
                  + (constant ? `; every one was off by about the same amount, within ${spread}s, which is what a wrong clock on either side looks like rather than a signing defect` : ""),
                  bad.slice(0, 3), hits);
    },
  },
  {
    id: "session.claims-present",
    section: "5.2",
    quote: "The Personal Agent MUST include every claim except `agent_id`, and `ath` when there's no access token.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const required = ["iss", "aud", "sid", "sub", "htm", "htu", "iat", "jti"];
      const bad = []; const hits = [];
      for (const { r, jwt } of s) {
        // `=== undefined` alone accepted "" as present, so an agent sending empty strings
        // passed. 5.2 requires the claim, and an empty sid or jti is not a value: "sid is
        // the Session ID. The Personal Agent MUST choose it at random".
        const missing = required.filter(c => jwt.payload[c] === undefined);
        const empty = required.filter(c => typeof jwt.payload[c] === "string" && jwt.payload[c] === "");
        const wrongType = ["iss", "aud", "sid", "sub", "htm", "htu", "jti"]
          .filter(c => jwt.payload[c] !== undefined && typeof jwt.payload[c] !== "string")
          .concat(typeof jwt.payload.iat !== "number" && jwt.payload.iat !== undefined ? ["iat"] : []);
        if (missing.length) note(bad, hits, r, `${r.method} ${r.path}: missing ${missing.join(", ")}`);
        if (empty.length) note(bad, hits, r, `${r.method} ${r.path}: empty ${empty.join(", ")}`);
        if (wrongType.length) note(bad, hits, r, `${r.method} ${r.path}: wrong type for ${wrongType.join(", ")}`);
        const token = r.headers?.authorization;
        if (!token && jwt.payload.ath !== undefined)
          note(bad, hits, r, `${r.method} ${r.path}: ath present with no access token, which 5.2 says is left out`);
      }
      return bad.length ? FAIL("a required Session claim was missing, or ath was sent without a token", bad.slice(0, 3), hits)
                        : PASS("every required claim was present on every request");
    },
  },
  {
    id: "session.sub-stable",
    section: "5.2",
    quote: "It MUST send the same `sub` and `agent_id`, or no `agent_id`, in every Session JWT for a Session.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bySid = new Map();
      for (const { r, jwt } of s) {
        const sid = jwt.payload.sid;
        const e = bySid.get(sid) ?? bySid.set(sid, { values: new Set(), requests: [] }).get(sid);
        e.values.add(JSON.stringify([jwt.payload.sub, jwt.payload.agent_id ?? null]));
        e.requests.push(r);
      }
      const bad = [...bySid].filter(([, v]) => v.values.size > 1);
      if (!bySid.size) return SKIP("no sid was sent");
      // The rule is about change WITHIN a Session, so a Session of one request cannot show
      // it. "stable across 1 Session(s)" was a claim about nothing.
      if (!bad.length && ![...bySid].some(([, v]) => v.requests.length > 1))
        return SKIP("no Session carried two requests, so nothing could change within one");
      // Only the Sessions that changed. Naming every request meant a run with two Sessions,
      // one of them fine, pointed the builder at both.
      return bad.length
        ? FAIL("sub or agent_id changed within one Session",
               bad.map(([sid, v]) => `sid ${String(sid).slice(0, 12)}: ${v.values.size} different values`),
               bad.flatMap(([, v]) => v.requests))
        : PASS(`sub and agent_id were stable across ${bySid.size} Session(s)`);
    },
  },
  {
    id: "session.jti-unique",
    section: "5.2",
    quote: "`iat` is when the Personal Agent signed it, in Unix seconds, and `jti` is unique and unguessable.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      // Narrowed deliberately. 5.2 says "jti is unique and unguessable" and an agent signs a
      // JWT per request, so reuse is a defect. But 5.3 says a Company only "MAY reject a
      // reused jti", the guides call rejecting it optional, and 8.3 makes a retry of the
      // identical request a safe, intended operation. A builder whose HTTP client retries
      // on a connection reset would have an argument, and a contestable FAIL is worth less
      // than a clear one.
      //
      // So: FAIL only when one jti signs requests that DIFFER, which is a signature replayed
      // onto another request and cannot be a retry. Identical resends are reported as a note.
      // A request whose body was never fully received is left OUT of the comparison. The
      // Company never saw the whole request, so it cannot claim the signature was reused on
      // a DIFFERENT one: an upload reset at `{"mes` and retried in full is one request, and
      // comparing the partial body with the complete one made a conforming agent on a flaky
      // network look like it had replayed a signature. The exclusion is narrow on purpose:
      // a jti that signs two different COMPLETE requests still fails, which the control test
      // beside this one asserts.
      const byJti = new Map();
      let incomplete = 0;
      for (const { r, jwt } of s) {
        const j = jwt.payload.jti;
        if (j === undefined || j === "") continue;    // claims-present reports those
        if (r.bodyComplete === false) { incomplete++; continue; }
        const shape = `${r.method} ${htuOf(r) ?? r.path} ${r.body ?? ""}`;
        const e = byJti.get(j) ?? byJti.set(j, { shapes: new Set(), requests: [] }).get(j);
        e.shapes.add(shape); e.requests.push(r);
      }
      if (!byJti.size)
        return SKIP(incomplete
          ? `${incomplete} request(s) carried a jti but their bodies were never fully received, so none could be compared`
          : "no jti was sent");
      // One comparable request cannot show reuse, so a pass here would be a claim about
      // nothing. It read "all 1 jti values were distinct", which a builder reads as
      // conformance, and under a Company that rejects a bad request at once every run would
      // end with one request and print it.
      const comparable = [...byJti].reduce((n, [, v]) => n + v.requests.length, 0);
      if (comparable < 2)
        return SKIP("only one request could be compared, so nothing could be reused"
          + (incomplete ? `; ${incomplete} other request(s) were left out because the body was never fully received, which a reset upload and its retry look like` : ""));
      const replayed = [...byJti].filter(([, v]) => v.shapes.size > 1);
      const complete = s.length - incomplete;
      const note = incomplete
        ? `; ${incomplete} request(s) were left out because the body was never fully received, which a reset upload and its retry look like`
        : "";
      if (replayed.length) return FAIL(
        "one jti signed requests that differ, so a signature was replayed onto another request",
        replayed.map(([j, v]) => `${String(j).slice(0, 16)} signed ${v.shapes.size} different requests`).slice(0, 3),
        replayed.flatMap(([, v]) => v.requests));
      return byJti.size < complete
        ? PASS(`no jti signed two different requests; ${complete - byJti.size} identical resend(s) seen, which 5.3 leaves to the Company to reject${note}`)
        : PASS(`all ${byJti.size} jti values were distinct${note}`);
    },
  },
  {
    id: "session.iss-https",
    section: "3",
    quote: "Every URL this protocol defines or exchanges MUST be an HTTPS URL: in `poppy.json`, in authorization server and protected resource metadata, in client metadata documents (4.1), in extensions, and in assertions, Session JWTs, and responses.",
    // Its own check rather than part of the fetch, because a verdict quotes the sentence it
    // enforces and "find the key in the Personal Agent's jwks_uri" is the wrong sentence for a
    // scheme defect. It also decides with no network at all, which makes it the precondition
    // of everything the fetch does.
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], hits = [];
      for (const { r, jwt } of s) {
        const iss = jwt.payload.iss;
        let u = null;
        try { u = new URL(String(iss)); } catch { /* not a URL at all */ }
        if (!u) note(bad, hits, r, `${r.method} ${r.path}: iss ${JSON.stringify(iss)} is not a URL`);
        else if (u.protocol !== "https:") note(bad, hits, r, `${r.method} ${r.path}: iss ${JSON.stringify(iss)} is ${u.protocol}//`);
      }
      return bad.length
        ? FAIL("iss was not an HTTPS URL, so no Company can fetch the client metadata it names",
               [...new Set(bad)].slice(0, 3), hits)
        : PASS(`iss was an HTTPS URL on every one of ${s.length} request(s)`);
    },
  },
  {
    id: "delegation.signature",
    section: "5.2",
    quote: "Find the key in the Personal Agent's `jwks_uri` named by the delegation's `kid`, and verify the delegation's signature with it.",
    // The forgery this closes. Everything else here verifies a Session JWT against the key its
    // delegation NAMES, and took the delegation at its word, so a stranger could mint one
    // claiming any client_id and this Company would attribute state to it, which 5.3 forbids
    // in as many words: "The Company MUST NOT use unverified Session claims to attribute a
    // request to a Personal Agent, User, or Session, or to look up their state."
    //
    // `kid` is matched by its member, then by RFC 7638 thumbprint, then not at all, because
    // 5.2 says `kid` "names the key" with no requirement word.
    //
    // The reason first written here was wrong and is worth recording: it said the authors' own
    // signer omits `kid`, which is true of `generateKey()` called directly, as our own tests
    // call it, and NOT of the kit's actual identity path. Their `keygen` sets `kid` on the root
    // key, and their `delegation.schema.json` lists it as required. So the fallback is not
    // needed to accept their traffic; it is kept because the normative sentence carries no
    // requirement word and a refusal over an absent `kid` would be contestable, which is the
    // side this grader errs on.
    //
    // The fetch itself is NOT done here. This file stays pure and synchronous, so that every
    // verdict is reproducible from a recorded log with no network, and so that enforcement can
    // call it on one request. server.mjs attaches the outcome as `record.issuerKeys`.
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], hits = [];
      let verified = 0, notHttps = 0, theirServer = null;
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        if (!dlg) continue;                                  // delegation.present reports it
        const iss = String(jwt.payload.iss ?? "");
        if (!/^https:\/\//.test(iss)) { notHttps++; continue; }
        const fetched = r.issuerKeys;
        // "server" is THEIR host answering in a way we cannot read as a verdict, which a
        // builder can change, so it abstains as unreached. "grader" is us, which they cannot.
        if (fetched?.outcome === "server") { theirServer = fetched.detail; continue; }
        if (!fetched || fetched.outcome === "grader") continue;
        if (fetched.outcome === "agent") {
          note(bad, hits, r, `${r.method} ${r.path}: ${fetched.detail}`);
          continue;
        }
        const wanted = dlg.header.kid;
        const candidates = (fetched.keys ?? []).filter(k => {
          if (!k || typeof k !== "object") return false;
          if (wanted && k.kid === wanted) return true;
          if (wanted && thumbprintOf(k) === wanted) return true;
          if (wanted) return false;
          // No kid: every key whose type could have produced this alg.
          return dlg.header.alg === "PS384" ? k.kty === "RSA" : k.kty === "EC";
        });
        const ok = candidates.some(k => verifyCompact(jwt.header.poppy_dlg, k) === true);
        if (ok) { verified++; continue; }
        note(bad, hits, r, candidates.length
          ? `${r.method} ${r.path}: no key at ${fetched.jwksUri} verified the delegation's signature`
          : `${r.method} ${r.path}: kid ${JSON.stringify(wanted ?? null)} names no key at ${fetched.jwksUri}, which held ${JSON.stringify(fetched.kids ?? [])}`);
      }
      if (bad.length)
        return FAIL("a delegation was not signed by a key the agent published", [...new Set(bad)].slice(0, 3), hits);
      if (!verified) {
        // Never a failure: this grader may have been unable to look, and that is our limit.
        if (notHttps)
          return SKIP(`${notHttps} request(s) named an iss that is not an HTTPS URL, so there was nothing to fetch, which session.iss-https reports`);
        if (theirServer) return SKIP(theirServer);          // unreached: the builder can change it
        return SKIP(firstFetchReason(s) ?? "this grader did not fetch the agent's key set", "grader");
      }
      // What the verdict depended on, said out loud. A PASS or a FAIL decided on a cache the
      // builder cannot see is one they cannot argue with.
      const src = s.map(x => x.r.issuerKeys).find(k => k?.outcome === "ok");
      const where = src?.jwksUri ?? "the agent's jwks_uri";
      const how = src?.source === "cache" ? `, cached ${src.ageSeconds}s ago` : "";
      const aside = notHttps ? `; ${notHttps} other request(s) named an iss that is not HTTPS, which session.iss-https reports` : "";
      return PASS(`every one of ${verified} delegation(s) verified against a key published at ${where}${how}${aside}`);
    },
  },
  {
    id: "delegation.typ",
    section: "5.2",
    quote: "`typ` MUST be `poppy-delegation+jwt`, so a delegation can't be used as a Session JWT.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], none = [], hits = [], loose = new Set();
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        if (!dlg) { none.push(`${r.method} ${r.path}`); continue; }
        const t = typIs(dlg.header.typ, "poppy-delegation+jwt");
        if (!t.ok) note(bad, hits, r, `${r.method} ${r.path}: ${JSON.stringify(dlg.header.typ)}`);
        else if (!t.exact) loose.add(JSON.stringify(dlg.header.typ));
      }
      // Absence has its own check, delegation.present. Reporting it here was a
      // misattribution: the defect is that no delegation was sent at all, and 5.2 has its
      // own sentence for that.
      if (none.length && !bad.length) return SKIP("no delegation was sent, which delegation.present reports");
      if (bad.length) return FAIL("a delegation did not declare poppy-delegation+jwt", bad.slice(0, 3), hits);
      return loose.size
        ? PASS(`every delegation named the media type poppy-delegation+jwt, but not with the exact spelling 5.2 gives: ${[...loose].slice(0, 2).join(", ")}. RFC 7515 makes these the same type; a Company that compares the literal would reject it`)
        : PASS("every Session JWT carried a delegation declaring poppy-delegation+jwt");
    },
  },
  {
    id: "delegation.exp-24h",
    section: "5.2",
    quote: "`exp` MUST be at most 24 hours after `iat`.",
    run(log) {
      const s = sessionRequests(log);
      // The request is kept beside its delegation. Dropping it named every request in the
      // run as deciding the failure, which the authors' own validator exposed: it sends one
      // over-long delegation among otherwise conforming traffic, and the report sent a
      // builder to 28 requests that were fine.
      const pairs = s.map(x => ({ r: x.r, d: decodeJwt(x.jwt.header.poppy_dlg) })).filter(p => p.d);
      if (!pairs.length) return SKIP("no delegation was sent");
      const bad = []; const hits = [];
      for (const { r, d } of pairs) {
        const { iat, exp } = d.payload;
        if (typeof iat !== "number" || typeof exp !== "number") { note(bad, hits, r, `iat or exp was not a number`); continue; }
        if (exp - iat > 86400) note(bad, hits, r, `exp was ${Math.round((exp - iat) / 3600)}h after iat`);
      }
      return bad.length ? FAIL("a delegation lasted longer than 24 hours", [...new Set(bad)].slice(0, 3), [...new Set(hits)])
                        : PASS("every delegation expired within 24 hours of issue");
    },
  },
  {
    id: "delegation.no-identifiers",
    section: "5.2",
    quote: "The Personal Agent MUST NOT put a User ID, an Agent ID, a Company's issuer, or anything else about the User or the Companies they use in a delegation.",
    // The privacy rule with real teeth, and one only a Company can see, because the
    // delegation travels in a header the agent signs for us.
    run(log, ctx) {
      const s = sessionRequests(log);
      const pairs = s.map(x => ({ r: x.r, dlg: decodeJwt(x.jwt.header.poppy_dlg), ses: x.jwt })).filter(p => p.dlg);
      if (!pairs.length) return SKIP("no delegation was sent");
      // Exact leaf values, not a substring search over the payload.
      //
      // The substring version accused conforming agents constantly, measured: a one
      // character User ID failed 40 of 40 runs, because it matched inside the random
      // base64url of cnf.jwk. It also reported `iss` as a leak, which 5.2 REQUIRES the
      // delegation to carry, and any Company whose domain is a substring of the agent's
      // own hostname. A privacy accusation has to be exact or it must not be made.
      const leaves = (v, out = []) => {
        if (v === null || v === undefined) return out;
        if (Array.isArray(v)) { for (const x of v) leaves(x, out); return out; }
        if (typeof v === "object") { for (const x of Object.values(v)) leaves(x, out); return out; }
        out.push(String(v)); return out;
      };
      const bad = []; const hits = [];
      for (const { r, dlg, ses } of pairs) {
        const payload = { ...dlg.payload };
        delete payload.iss;    // required by 5.2
        delete payload.cnf;    // the delegated key itself, random by construction
        const vals = new Set(leaves(payload));
        const hostOf = x => { try { return new URL(x).host.toLowerCase(); } catch { return null; } };
        for (const [what, value] of [["the User ID", ses.payload.sub], ["the Agent ID", ses.payload.agent_id],
                                     ["this Company's identifier", ctx.identifier]]) {
          if (value && vals.has(String(value))) note(bad, hits, r, `the delegation contains ${what}`);
        }
        if (ctx.domain) for (const v of vals)
          if (v.toLowerCase() === String(ctx.domain).toLowerCase() || hostOf(v) === String(ctx.domain).toLowerCase())
            note(bad, hits, r, "the delegation names this Company's domain");
      }
      return bad.length ? FAIL("a delegation carried something it must not", [...new Set(bad)].slice(0, 4), [...new Set(hits)])
                        : PASS("no delegation carried a User ID, Agent ID, or anything naming this Company");
    },
  },
  {
    id: "version.sent",
    section: "3.4",
    quote: "On every request with the Session header (5.2), the Personal Agent sends the protocol version it implements, compatible with the chosen one, in `Poppy-Version`, as `major.minor`.",
    // The per-request half of the version rule, and the half a Company acts on. 3.4: "An
    // endpoint that verifies the Session header (5.3) MUST also check `Poppy-Version`. It
    // rejects a request without it, or with a version that isn't compatible with one the
    // Company serves, with `version_unsupported`". Compatibility is defined in the same
    // section: "Two versions are compatible when they have the same major version."
    run(log, ctx) {
      const withHeader = sessionRequests(log).filter(x => x.r.isResource);
      if (!withHeader.length) return SKIP("no request to a resource endpoint carried a Session header");
      const served = String(ctx?.protocolVersion ?? "1.0").split(".")[0];
      const bad = [], hits = [];
      for (const { r } of withHeader) {
        const v = r.headers?.["poppy-version"];
        if (v === undefined || v === "") { note(bad, hits, r, `${r.method} ${r.path}: no Poppy-Version`); continue; }
        if (!/^\d+\.\d+$/.test(String(v))) { note(bad, hits, r, `${r.method} ${r.path}: ${JSON.stringify(v)} is not major.minor`); continue; }
        if (String(v).split(".")[0] !== served)
          note(bad, hits, r, `${r.method} ${r.path}: ${JSON.stringify(v)} is not compatible with ${served}.x, which this Company serves`);
      }
      return bad.length
        ? FAIL("a request with the Session header carried no compatible Poppy-Version", [...new Set(bad)].slice(0, 3), hits)
        : PASS(`every one of ${withHeader.length} Session request(s) carried a compatible Poppy-Version`);
    },
  },
  {
    id: "version.constant",
    section: "3.4",
    quote: "The Personal Agent MUST send the same values on every request in a Session, and starts a new Session to change them.",
    // The quote here was a placeholder for an hour: a real sentence about
    // `supported_versions` URLs, which is a different rule in the same section. The verbatim
    // test PASSED it, because the sentence exists. That is the gap the register warned about
    // in its own words, "an id that exists is not an id that applies", and it is why every
    // check now declares the section its quote comes from and the test checks the quote is
    // inside that section. Scoping does not prove a quote is the right rule; it does catch
    // the common case, which is reaching for a sentence from somewhere else entirely.
    run(log) {
      const resource = log.filter(r => r.isResource);
      if (!resource.length) return SKIP("the agent made no request to a resource endpoint");
      // 3.4 binds the value to a SESSION: "The Personal Agent MUST send the same values on
      // every request in a Session, and starts a new Session to change them." Section 5
      // permits "several Sessions for the same User, for example for tasks running in
      // parallel", and 3.4's recovery has the agent pick another version and start a new
      // Session. Requiring one value across the whole log failed both of those.
      //
      // Presence is NOT judged here. It was, and that made this rule non-monotone: a request
      // carrying no Poppy-Version failed when it was alone and passed when another Session in
      // the same run had carried the header, so an agent that never sent it on one of its
      // Sessions was told it conformed. Presence is per request, has its own error in 3.4,
      // and is now version.sent.
      const withHeader = sessionRequests(log).filter(x => x.r.isResource);
      // The FIRST request carrying each distinct value, per Session. Naming every request in
      // the Session was not wrong, since they are all in the Session that breached, but
      // against a long run it named 29 of 37 and left the builder to find the change
      // themselves, which is the work this report exists to do.
      const bySid = new Map();
      for (const { r, jwt } of withHeader) {
        const sid = jwt.payload.sid;
        if (sid === undefined) continue;
        const e = bySid.get(sid) ?? bySid.set(sid, new Map()).get(sid);
        const v = String(r.headers?.["poppy-version"] ?? null);
        if (!e.has(v)) e.set(v, r);                  // first sighting of this value
      }
      if (!bySid.size) return SKIP("no request carried both a Session header and a sid");
      // Nothing could change inside a Session of one request, so a pass would be a claim
      // about nothing: the same defect that was fixed in session.sub-stable and
      // session.jti-unique, left behind here until a property over all three caught it.
      const counts = new Map();
      for (const { r, jwt } of withHeader) {
        const sid = jwt.payload.sid;
        if (sid !== undefined) counts.set(sid, (counts.get(sid) ?? 0) + 1);
      }
      const mixed = [...bySid].filter(([, v]) => v.size > 1);
      if (!mixed.length && ![...counts.values()].some(n => n > 1))
        return SKIP("no Session carried two requests, so nothing could change within one");
      return mixed.length
        ? FAIL("Poppy-Version changed within one Session",
               mixed.map(([sid, v]) => `sid ${String(sid).slice(0, 12)}: ${[...v.keys()].join(", ")}`).slice(0, 3),
               mixed.flatMap(([, v]) => [...v.values()]))
        : PASS(`every Session declared one Poppy-Version across ${bySid.size} Session(s)`);
    },
  },
  {
    id: "session.signature",
    section: "5.2",
    quote: "Verify the Session JWT's signature with the key in the delegation's `cnf.jwk`, and check that its `kid` is that key's thumbprint.",
    // The largest gap this grader had. Nothing verified any signature, so a Session JWT with
    // a destroyed signature passed all thirteen checks, measured. A grader that accepts a
    // forgery tells a builder with a broken signer that they conform.
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], unknown = []; const hits = []; let verified = 0;
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        const jwk = dlg?.payload?.cnf?.jwk;
        if (!jwk) continue;                       // delegation.present reports the absence
        verified++;
        const ok = verifyCompact(jwt.compact, jwk);
        if (ok === null) { unknown.push(`${r.method} ${r.path}: alg ${JSON.stringify(jwt.header.alg)}`); continue; }
        if (!ok) { note(bad, hits, r, `${r.method} ${r.path}: the signature does not verify against the delegation's cnf.jwk`); continue; }
        const thumb = thumbprintOf(jwk);
        if (thumb && jwt.header.kid && jwt.header.kid !== thumb)
          note(bad, hits, r, `${r.method} ${r.path}: kid is not the delegated key's thumbprint`);
      }
      if (bad.length) return FAIL("a Session JWT was not signed by the key its delegation names", bad.slice(0, 3), hits);
      if (unknown.length) return SKIP(`an algorithm this grader cannot verify: ${unknown[0]}`, "grader");
      // Count what was actually verified. It used to report "every Session JWT verified
      // against its delegation's key on 1 request(s)" for a JWT with NO delegation, because
      // there was no key and the loop skipped it. The verdict was harmless, since
      // delegation.present fails, but the sentence was false, and a false sentence in a
      // report is what this project spends most of its effort on.
      if (!verified) return SKIP("no Session JWT carried a delegation, so there was no key to verify against");
      return PASS(`every Session JWT verified against its delegation's key on ${verified} request(s)`);
    },
  },
  {
    id: "delegation.no-private-key",
    section: "5.2",
    quote: "It MUST NOT contain private key members.",
    run(log) {
      const dlgs = sessionRequests(log).map(x => decodeJwt(x.jwt.header.poppy_dlg)).filter(Boolean);
      if (!dlgs.length) return SKIP("no delegation was sent");
      const PRIVATE = ["d", "p", "q", "dp", "dq", "qi", "k"];
      const bad = []; const hits = [];
      for (const d of dlgs) {
        const jwk = d.payload?.cnf?.jwk;
        if (!jwk) continue;
        const found = PRIVATE.filter(m => jwk[m] !== undefined);
        if (found.length) bad.push(`cnf.jwk carries ${found.join(", ")}`);
      }
      return bad.length ? FAIL("a delegation exposed private key material", [...new Set(bad)], sessionRequests(log).map(x => x.r))
                        : PASS(`no delegation carried a private key member across ${dlgs.length} delegation(s)`);
    },
  },
  {
    id: "delegation.not-expired",
    section: "5.2",
    quote: "The Personal Agent MUST NOT sign a Session JWT after its delegation's `exp`.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = []; const hits = [];
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        const exp = dlg?.payload?.exp, iat = jwt.payload.iat;
        if (typeof exp !== "number" || typeof iat !== "number") continue;
        if (iat > exp) note(bad, hits, r, `${r.method} ${r.path}: signed ${iat - exp}s after the delegation expired`);
      }
      return bad.length ? FAIL("a Session JWT was signed after its delegation expired", bad.slice(0, 3), hits)
                        : PASS("every Session JWT was signed within its delegation's lifetime");
    },
  },
  {
    id: "delegation.iss-matches",
    section: "5.2",
    quote: "`iss` is the Personal Agent's `client_id`.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = []; const hits = [];
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        if (!dlg) continue;
        if (dlg.payload?.iss !== jwt.payload.iss)
          note(bad, hits, r, `${r.method} ${r.path}: delegation iss ${JSON.stringify(dlg.payload?.iss)} vs Session iss ${JSON.stringify(jwt.payload.iss)}`);
      }
      return bad.length ? FAIL("a delegation named a different client than its Session JWT", bad.slice(0, 2), hits)
                        : PASS("every delegation named the same client_id as its Session JWT");
    },
  },
  {
    id: "session.ath",
    section: "5.2",
    quote: "`ath` is the SHA-256 hash of the access token, base64url-encoded, when the request carries one, as in a DPoP proof.",
    run(log) {
      const s = sessionRequests(log).filter(x => x.r.headers?.authorization);
      if (!s.length) return SKIP("no request carried an access token");
      const bad = []; const hits = [];
      for (const { r, jwt } of s) {
        const token = String(r.headers.authorization).replace(/^(DPoP|Bearer)\s+/i, "");
        const want = createHash("sha256").update(token).digest("base64url");
        if (jwt.payload.ath === undefined) note(bad, hits, r, `${r.method} ${r.path}: a token was sent with no ath`);
        else if (jwt.payload.ath !== want) note(bad, hits, r, `${r.method} ${r.path}: ath is not the hash of the token sent`);
      }
      return bad.length ? FAIL("ath did not match the access token on the request", bad.slice(0, 3), hits)
                        : PASS(`ath matched the access token on all ${s.length} request(s)`);
    },
  },
  {
    id: "session.not-on-documents",
    section: "5.2",
    quote: "The Personal Agent MUST NOT send a Company's Session JWT to any other destination, except the website pages below.",
    // Only possible because the recorder now models the documents 5.2 forbids. Before that
    // there was no way to say "this URL must not carry it", so this breach could not be
    // examined at all: an agent sending its Session JWT to poppy.json, an OpenAPI document,
    // a supported_versions document or the token endpoint was simply never looked at.
    run(log) {
      // An agent that never put a Session header on anything has not reached the point this
      // rule governs, which is the choice of where to send one. Found by a run that fetched
      // poppy.json, sent no Session JWT anywhere, and PASSED this rule, which `curl` would also
      // have earned. The test is the raw header
      // count and not a decodable JWT on purpose: a garbage Session header sent to a document
      // is still the breach 5.2 names, and abstaining on it would excuse the worse agent.
      if (!log.some(r => (r.sessionHeaderCount ?? 0) > 0))
        return SKIP("no Session header was sent anywhere in this run, so the agent never chose where to send one");
      const docs = log.filter(r => r.mustNotCarry);
      if (!docs.length) return SKIP("the agent fetched no discovery or description document and no OAuth endpoint");
      const leaked = docs.filter(r => r.sessionHeaderCount > 0);
      return leaked.length
        ? FAIL("a Session JWT was sent to a destination 5.2 forbids",
               leaked.slice(0, 3).map(r => `${r.method} ${r.path} (${r.classifiedAs})`), leaked)
        : PASS(`no Session JWT went to any of the ${docs.length} document or OAuth request(s) seen`);
    },
  },
  {
    id: "delegation.present",
    section: "5.2",
    quote: "the Company MUST reject, with `invalid_session`, a Session JWT without a delegation, including one signed directly with a key from `jwks_uri`",
    // Its own rule, because a missing delegation is not a wrong typ. A Session JWT signed
    // directly with a jwks_uri key is the specific case the sentence names, and it looks
    // valid in every other respect.
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const none = s.filter(x => !decodeJwt(x.jwt.header.poppy_dlg));
      return none.length
        ? FAIL("a Session JWT carried no delegation in its poppy_dlg header",
               none.slice(0, 3).map(x => `${x.r.method} ${x.r.path}`), none.map(x => x.r))
        : PASS(`every one of ${s.length} Session JWT(s) carried a delegation`);
    },
  },
  {
    id: "delegation.alg",
    section: "5.2",
    quote: "`alg` is `ES256` or `PS384`. Companies MUST accept delegations signed with `ES256` and with `PS384`.",
    // Exactly those two and no others. PS384 must PASS: it is how a delegation is signed
    // blindly (10.7), so failing it would fail a conforming agent that protects its users
    // from its own operator.
    run(log) {
      const dlgs = sessionRequests(log).map(x => decodeJwt(x.jwt.header.poppy_dlg)).filter(Boolean);
      if (!dlgs.length) return SKIP("no delegation was sent");
      const allowed = new Set(["ES256", "PS384"]);
      const bad = dlgs.filter(d => !allowed.has(d.header?.alg));
      return bad.length
        ? FAIL("a delegation was signed with an algorithm 1.0 does not define for one",
               [...new Set(bad.map(d => String(d.header?.alg)))].slice(0, 3), sessionRequests(log).map(x => x.r))
        : PASS(`every delegation used ES256 or PS384 across ${dlgs.length} delegation(s)`);
    },
  },
  {
    id: "conversation.request-id",
    section: "8.3",
    quote: "Every `POST` body has an `id`, chosen by the Personal Agent, which MUST make it unique for the User across all its requests.",
    // Added because a conversation POST with no top-level `id` passed every rule here, and
    // nothing said so. It is a MUST on the agent, it is visible on the wire, and 8.13 puts the
    // Company's answer for it under `invalid_request`, so it belongs to the side this grader
    // judges.
    //
    // Scoped to the conversation routes of 8.2 and to no other POST. An API operation a Company
    // lists has its own body, and requiring an `id` there would be a rule nobody wrote.
    //
    // A repeated id is NOT a breach by itself: 8.3 says "To retry a request, the Personal Agent
    // sends it again to the same path with the same ID", so a retry is required to reuse it.
    // What the MUST forbids is the same id standing for a different request, which is why the
    // comparison is over path and body and not over the id alone.
    run(log) {
      // Four ways an earlier version of this rule accused a conforming agent, each now excluded
      // and each with its own test. They are listed because they are the whole difficulty of the
      // rule: a body we did not keep in full, a body that never arrived, two Users numbering
      // their own requests, and a retry whose JSON was rebuilt in a different order.
      //
      // A target this grader refused to classify is excluded too. Its record says in words that
      // no rule examined it, because the path we would judge is not provably the path the
      // Company serves, and judging it here would make the report contradict itself.
      const posts = log.filter(r => r.method === "POST" && r.conversationRoute
                                    && !r.unsafeTarget && !r.refused);
      if (!posts.length) return SKIP("the agent made no POST to a conversation route (8.2)");
      // 8.3 makes the id unique "for the User", so the comparison is per User and not global.
      const userOf = new Map(sessionRequests(log).map(({ r, jwt }) => [r, jwt.payload?.sub ?? null]));
      const noId = [], seenByUser = new Map(), clashing = [], unreadable = [];
      for (const r of posts) {
        // Our cap and a dropped socket are ours, not a breach. The jti rule skips the same way.
        if (r.bodyComplete === false || r.bodyTruncated) { unreadable.push(r); continue; }
        let parsed = null;
        try { parsed = JSON.parse(r.body ?? ""); } catch { parsed = null; }
        const id = typeof parsed?.id === "string" && parsed.id !== "" ? parsed.id : null;
        if (!id) { noId.push(r); continue; }
        // The User comes from the Session JWT. Without one this grader cannot tell two Users
        // apart, so it does not judge uniqueness for that request rather than guessing they are
        // one User. Sending no Session header on a destination is its own breach, and
        // session.header-sent is the rule that reports it.
        const user = userOf.get(r);
        if (user === null || user === undefined) continue;
        const key = `${user}\u0000${id}`;
        // "To retry a request, the Personal Agent sends it again to the same path with the same
        // ID", and 8.3 says nothing about member order, so the same request is recognised on a
        // canonical form rather than on raw bytes.
        const shape = `${r.path}\u0000${canonicalJson(parsed)}`;
        const seen = seenByUser.get(key);
        if (seen && seen !== shape) clashing.push(r); else if (!seen) seenByUser.set(key, shape);
      }
      if (noId.length)
        return FAIL("a POST to a conversation route carried no request id, or one that is not a non-empty string, which 8.3 requires",
                    noId.slice(0, 3).map(r => `${r.method} ${r.path}`), noId);
      if (clashing.length)
        return FAIL("one User sent the same request id for two different requests, so it is not unique for that User",
                    clashing.slice(0, 3).map(r => `${r.method} ${r.path}`), clashing);
      // Nothing was readable at all, so neither half of the sentence was examined.
      if (unreadable.length === posts.length)
        return SKIP(`${unreadable.length} conversation POST(s) arrived with a body this grader did not keep in full, so the id each carried cannot be read`, "grader");
      // The sentence has two halves and they are reachable separately: every POST carrying an
      // id is read from the body alone, while uniqueness for the User needs a Session to say
      // whose request it is. A PASS that did not compare the second half says so, rather than
      // leaving a reader to assume both were checked.
      const read = posts.length - unreadable.length;
      return PASS(seenByUser.size
        ? `${read} conversation POST(s) each carried a request id, and ${seenByUser.size} id(s) were compared per User with retries of the same request allowed to repeat one`
        : `${read} conversation POST(s) each carried a request id. Uniqueness for the User was not compared, because no Session header on them identified a User`);
    },
  },
  {
    id: "conversation.id-format",
    section: "8.2",
    quote: "Conversation IDs, request IDs, message IDs, and event IDs are strings of 1 to 256 characters from the URL-safe base64 alphabet",
    // The gap the README named before this rule existed: this Company answers `invalid_request`
    // for an id outside the alphabet, as 8.13 says it should, while no rule faulted it. A report
    // that shows a refused request beside a clean verdict leaves a builder unable to tell which
    // of the two to believe, and that disagreement is the thing this grader exists to prevent.
    //
    // Only the ids the AGENT chooses. 8.2: "The Company chooses Conversation IDs, event IDs, and
    // the IDs of its own messages. The Personal Agent chooses request IDs", so a Conversation ID
    // in a path is not the agent's to answer for. The same sentence ends "the side that chooses
    // an ID decides its format, and the other side MUST NOT depend on it", which is why nothing
    // here looks at anything beyond length and alphabet.
    //
    // A request with no id at all is left to conversation.request-id. Two rules faulting one
    // request for one mistake would count it twice and read as two defects.
    run(log) {
      const posts = log.filter(r => r.method === "POST" && r.conversationRoute
                                    && !r.unsafeTarget && !r.refused
                                    && r.bodyComplete !== false && !r.bodyTruncated);
      const ids = [];
      for (const r of posts) {
        let parsed = null;
        try { parsed = JSON.parse(r.body ?? ""); } catch { parsed = null; }
        // A usable string only. An id that is absent, empty, or not a string at all is one
        // mistake and `conversation.request-id` owns it; judging it here too failed the same
        // body under two sentences and reported one builder error as two defects.
        if (typeof parsed?.id === "string" && parsed.id !== "") ids.push({ r, id: parsed.id });
      }
      if (!ids.length) return SKIP("no POST to a conversation route carried a request id this grader could read");
      // The same alphabet and bound this Company's own conversation handler applies, so a status
      // code and a verdict about one request cannot disagree.
      const allowed = /^[A-Za-z0-9_-]{1,256}$/;
      const bad = ids.filter(({ id }) => typeof id !== "string" || !allowed.test(id));
      return bad.length
        ? FAIL("a request id is not 1 to 256 characters from the URL-safe base64 alphabet, which 8.2 defines",
               bad.slice(0, 3).map(({ r, id }) => `${r.method} ${r.path}: ${JSON.stringify(id).slice(0, 40)}`),
               bad.map(({ r }) => r))
        : PASS(`${ids.length} request id(s) are letters, digits, hyphen or underscore, 1 to 256 characters`);
    },
  },
  {
    id: "conversation.message-content",
    section: "8.4",
    quote: "A message MUST have at least one of `text`, `data`, `context`, or `extensions`.",
    // This Company already answers `invalid_request` for a message with none of them, as 8.13
    // says it should, while nothing here faulted it. A report that showed a request this Company
    // refused beside a verdict finding nothing wrong is the disagreement this grader exists to
    // prevent, and it was live on the main interface of the protocol.
    //
    // It asks for one of the four fields to be present and says nothing about what is in it, so
    // neither does this rule: an empty string is content the agent chose to send.
    run(log) {
      const { posts, messages, unreadable } = agentMessages(log);
      if (!messages.length)
        return posts.length && unreadable.length === posts.length
          ? SKIP(`${unreadable.length} conversation POST(s) arrived with a body this grader did not keep in full`, "grader")
          : SKIP("no POST to a conversation route carried a message this grader could read");
      const FIELDS = ["text", "data", "context", "extensions"];
      const empty = messages.filter(({ message }) => !FIELDS.some(k => message[k] !== undefined));
      return empty.length
        ? FAIL("a message carried none of text, data, context or extensions, which 8.4 requires",
               empty.slice(0, 3).map(({ r }) => `${r.method} ${r.path}`), empty.map(({ r }) => r))
        : PASS(`${messages.length} message(s) each carried at least one of text, data, context or extensions`);
    },
  },
  {
    id: "conversation.message-author",
    section: "8.8",
    quote: "the Personal Agent MUST set each message's `author.type`: `agent` when the Personal Agent wrote it, and `human` only when it carries the User's own words",
    // The one disclosure the protocol asks an agent to make about itself, and nothing here looked
    // at it: a message with no author at all was answered 201 and reported clean.
    //
    // What is judged is narrow on purpose. A Company can see whether the agent said `agent` or
    // `human`, and it can see a value 8.8 does not define. It cannot see WHICH is truthful,
    // because it never sees the User's own words, and 8.8 itself draws a line a Company cannot
    // check when it says a summary, paraphrase or translation of what the User said is `agent`.
    // So this rule reports presence and the allowed values, and says in the verdict what it
    // cannot know, rather than implying it verified the honesty of the answer.
    run(log) {
      const { posts, messages, unreadable } = agentMessages(log);
      if (!messages.length)
        return posts.length && unreadable.length === posts.length
          ? SKIP(`${unreadable.length} conversation POST(s) arrived with a body this grader did not keep in full`, "grader")
          : SKIP("no POST to a conversation route carried a message this grader could read");
      const ALLOWED = ["agent", "human"];
      const bad = messages.filter(({ message }) =>
        !message.author || typeof message.author !== "object" || !ALLOWED.includes(message.author.type));
      return bad.length
        ? FAIL("a message did not say whether a person or an AI wrote it: 8.8 defines `agent` and `human` and no other value",
               bad.slice(0, 3).map(({ r, message }) => `${r.method} ${r.path}: author.type ${JSON.stringify(message.author?.type)}`),
               bad.map(({ r }) => r))
        : PASS(`${messages.length} message(s) each said agent or human. Which of the two is truthful is not decidable from the wire, because this Company never sees the User's own words`);
    },
  },
  {
    id: "session.stops-after-refusal",
    section: "7",
    quote: "A new Session doesn't fix it: the Personal Agent stops sending the request until it fixes the cause",
    // A refusal is only worth anything if the agent acts on it, and a retry loop after a 400 is a
    // classic client bug. Section 7 says what an agent does with `invalid_session`: it stops
    // sending that request until it fixes the cause, and a fresh Session does not count as a fix.
    //
    // The accusation is kept narrow enough to be uncontestable. It needs the SAME request, by
    // method, URL and body, refused AGAIN by the SAME rule. An agent that fixed one cause and
    // tripped another changed something, which is what it was asked to do; a different request
    // that fails the same rule is not a retry; and a resend that was accepted proves nothing
    // about the agent. Bodies are compared as bytes rather than canonically, which lets an agent
    // that re-serialises escape: under-reach is the right direction for a public grader.
    //
    // Only refusals carrying a RULE count. This Company also answers 400 `invalid_session` on a
    // conversation route when it could not verify a delegation for its own reasons, and that
    // answer sets no `rejection`, so it cannot start this rule's clock. An agent resending after
    // our own fetch failure would otherwise be faulted for our problem.
    run(log) {
      const refused = log.filter(r => r.rejection?.error === "invalid_session" && r.rejection?.rule);
      if (!refused.length)
        return SKIP("this Company refused nothing under a rule, so the agent was never told to stop sending anything");
      const shapeOf = (r) => `${r.method} ${htuOf(r) ?? r.path} ${r.body ?? ""}`;
      const whole = (r) => r.bodyComplete !== false && !r.bodyTruncated;
      const resent = [];
      for (const r of refused) {
        if (!whole(r)) continue;                      // we cannot say what request it was
        const later = log.filter(x => x !== r && (x.seq ?? 0) > (r.seq ?? 0) && whole(x)
                                      && shapeOf(x) === shapeOf(r)
                                      && x.rejection?.rule === r.rejection.rule);
        if (later.length) resent.push(...later);
      }
      return resent.length
        ? FAIL("a request refused with invalid_session was sent again and refused for the same reason, which section 7 tells an agent not to do",
               resent.slice(0, 3).map(r => `${r.method} ${r.path} refused again under ${r.rejection.rule}`), resent)
        : PASS(`${refused.length} request(s) were refused and none was sent again to be refused for the same reason`);
    },
  },
];

// The cross-Company checks. These need logs from BOTH hostnames, and they are the reason
// the rig runs two Companies: nothing a single Company observes can establish them.
// RFC 7638 thumbprint, computed here rather than with jose so the checks stay synchronous
// and pure. Comparing JSON.stringify(cnf.jwk) hid a shared key behind member order or an
// extra `alg` member: measured, the same key with reordered members passed.
// Why this grader could not look, in the words the resolver used, so an abstention is never
// just silence.
function firstFetchReason(s) {
  for (const { r } of s) {
    const k = r.issuerKeys;
    if (k && (k.outcome === "grader" || k.outcome === "server") && k.detail) return k.detail;
  }
  return null;
}

// A stable form of a parsed JSON value, so two serialisations of the same request compare equal.
// 8.3 defines a retry by its path and its id and says nothing about member order, and the hosted
// Company compares the parsed body, so comparing raw bytes made this grader stricter than the
// Company it ships with.
// The agent's own messages, from the conversation POSTs of 8.2. Shared by the two rules about a
// message so they cannot disagree about what counts as one, and scoped exactly as the request id
// rules are, for the reasons those rules had to learn: a body this grader did not keep in full is
// our cap or a dropped socket and never a breach, and a target we refused to classify says in its
// own record that no rule examined it. A route that carries no message, such as close or cancel,
// is not a message with something missing.
function agentMessages(log) {
  const posts = log.filter(r => r.method === "POST" && r.conversationRoute
                                && !r.unsafeTarget && !r.refused);
  const messages = [], unreadable = [];
  for (const r of posts) {
    if (r.bodyComplete === false || r.bodyTruncated) { unreadable.push(r); continue; }
    let parsed = null;
    try { parsed = JSON.parse(r.body ?? ""); } catch { parsed = null; }
    const m = parsed?.message;
    if (m && typeof m === "object" && !Array.isArray(m)) messages.push({ r, message: m });
  }
  return { posts, messages, unreadable };
}

function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}

export function thumbprintOf(jwk) {
  if (!jwk || typeof jwk !== "object") return null;
  const required = jwk.kty === "EC" ? ["crv", "kty", "x", "y"]
                 : jwk.kty === "RSA" ? ["e", "kty", "n"]
                 : jwk.kty === "OKP" ? ["crv", "kty", "x"] : null;
  if (!required || required.some(k => typeof jwk[k] !== "string")) return null;
  const canonical = "{" + required.map(k => `${JSON.stringify(k)}:${JSON.stringify(jwk[k])}`).join(",") + "}";
  return createHash("sha256").update(canonical).digest("base64url");
}

// The cross-Company checks. These need logs from BOTH hostnames, and they are the reason
// the rig runs two Companies: nothing a single Company observes can establish them.
//
// They are also the most dangerous checks here, because a FAIL accuses an agent of a
// privacy defect in front of its users. So they take both contexts and refuse to judge when
// the two Companies are not actually two: 3.2 says "Several domains MAY have the same
// issuer... and they are then one Company: the same User IDs (5.1), Sessions, and refresh
// tokens apply to all of them", so a shared identifier makes a shared User ID REQUIRED and
// a FAIL would invert the rule.
export const PAIRWISE = [
  {
    id: "pairwise.user-id",
    section: "5.1",
    quote: "It is opaque and different for each Company, so Companies can't match Users with each other.",
    run(a, b, ctxA, ctxB) {
      if (!ctxA?.identifier || !ctxB?.identifier) return SKIP("both Company identifiers are needed to judge this", "grader");
      if (ctxA.identifier === ctxB.identifier)
        return SKIP(`both Companies are ${ctxA.identifier}, which 3.2 makes one Company, so the same User ID is required`, "grader");
      const subs = l => new Set(sessionRequests(l).map(x => x.jwt.payload.sub).filter(Boolean));
      const A = subs(a), B = subs(b);
      // Naming both Companies and the counts, because "did not send a Session to both" does
      // not tell a builder which one to drive next.
      if (!A.size || !B.size) return SKIP(
        `the agent did not send a Session to both Companies: ${sessionRequests(a).length} request(s) with a Session header at `
        + `${ctxA.identifier} and ${sessionRequests(b).length} at ${ctxB.identifier}`);
      const shared = [...A].filter(s => B.has(s));
      return shared.length
        ? FAIL(`the same User ID was used at ${ctxA.identifier} and ${ctxB.identifier}, which lets them match the User`,
               shared.map(s => String(s).slice(0, 16)).slice(0, 3))
        : PASS(`${A.size} User ID(s) at ${ctxA.identifier} and ${B.size} at ${ctxB.identifier}, none in common`);
    },
  },
  {
    id: "pairwise.delegated-key",
    section: "5.2",
    // The operative sentence, replacing a quote about cnf.jwk that merely described the
    // claim's format and said nothing about reuse.
    quote: "The Personal Agent MUST use each delegated key, and its delegation, for one User ID only: it signs with it only that User ID's Session JWTs.",
    run(a, b, ctxA, ctxB) {
      if (!ctxA?.identifier || !ctxB?.identifier) return SKIP("both Company identifiers are needed to judge this", "grader");
      if (ctxA.identifier === ctxB.identifier)
        return SKIP(`both Companies are ${ctxA.identifier}, which 3.2 makes one Company`, "grader");
      const dlgsOf = l => sessionRequests(l).map(x => decodeJwt(x.jwt.header.poppy_dlg)).filter(Boolean);
      const A = dlgsOf(a), B = dlgsOf(b);
      if (!A.length || !B.length) return SKIP(
        `the agent did not send a delegation to both Companies: ${A.length} at ${ctxA.identifier} and ${B.length} at ${ctxB.identifier}`);
      const keys = ds => new Set(ds.map(d => thumbprintOf(d.payload?.cnf?.jwk)).filter(Boolean));
      const jtis = ds => new Set(ds.map(d => d.payload?.jti).filter(Boolean));
      const kA = keys(A), kB = keys(B);
      if (!kA.size || !kB.size) return SKIP("a delegation carried no usable cnf.jwk, so keys cannot be compared", "grader");
      const sharedKey = [...kA].filter(k => kB.has(k));
      // 1.0 names the delegation's jti as the same linking vector as the key thumbprint.
      const sharedJti = [...jtis(A)].filter(j => jtis(B).has(j));
      const bad = []; const hits = [];
      if (sharedKey.length) bad.push(`${sharedKey.length} delegated key(s) in common`);
      if (sharedJti.length) bad.push(`${sharedJti.length} delegation jti(s) in common`);
      return bad.length
        ? FAIL(`the same delegated key or delegation was presented to ${ctxA.identifier} and ${ctxB.identifier}, which lets them match the User by its thumbprint or jti`, bad)
        : PASS(`${kA.size} delegated key(s) here and ${kB.size} there, no thumbprint and no jti in common`);
    },
  },
];

export function grade(log, ctx) {
  return CHECKS.map(c => ({ id: c.id, section: c.section, quote: c.quote, ...c.run(log, ctx) }));
}
export function gradePair(logA, logB, ctxA, ctxB) {
  return PAIRWISE.map(c => ({ id: c.id, section: c.section, quote: c.quote, ...c.run(logA, logB, ctxA, ctxB) }));
}
