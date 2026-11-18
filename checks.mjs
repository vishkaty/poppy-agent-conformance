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
function normalizeUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (!u.protocol || !u.host) return null;
  return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${u.pathname}`;   // URL drops a default port
}
const htuOf = r => normalizeUrl(r.url);

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
    id: "session.typ",
    section: "5.2",
    quote: "`typ` MUST be `poppy-session+jwt`, so the JWT can't be mistaken for a client assertion, delegation, or any other JWT",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = s.filter(x => x.jwt.header.typ !== "poppy-session+jwt");
      return bad.length
        ? FAIL(`typ was not poppy-session+jwt`, [...new Set(bad.map(x => JSON.stringify(x.jwt.header.typ)))].slice(0, 3), bad.map(x => x.r))
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
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = []; const hits = [];
      for (const { r, jwt } of s) {
        const iat = jwt.payload.iat;
        if (typeof iat !== "number") { note(bad, hits, r, `${r.method} ${r.path}: iat was ${JSON.stringify(iat)}, not a number`); continue; }
        const skew = Math.abs(r.at - iat);
        if (skew > WINDOW_SECONDS + SKEW_SECONDS) note(bad, hits, r, `${r.method} ${r.path}: iat was ${skew}s from when we saw it`);
      }
      return bad.length
        ? FAIL(`iat fell outside our acceptance window of ${WINDOW_SECONDS}s plus ${SKEW_SECONDS}s of clock skew`, bad.slice(0, 3), hits)
        : PASS(`iat was within ${WINDOW_SECONDS + SKEW_SECONDS}s on every request`);
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
      for (const { jwt } of s) {
        const sid = jwt.payload.sid;
        (bySid.get(sid) ?? bySid.set(sid, new Set()).get(sid)).add(JSON.stringify([jwt.payload.sub, jwt.payload.agent_id ?? null]));
      }
      const bad = [...bySid].filter(([, v]) => v.size > 1);
      if (!bySid.size) return SKIP("no sid was sent");
      return bad.length
        ? FAIL("sub or agent_id changed within one Session", bad.map(([sid, v]) => `sid ${String(sid).slice(0, 12)}: ${v.size} different values`), s.map(x => x.r))
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
        (byJti.get(j) ?? byJti.set(j, new Set()).get(j)).add(shape);
      }
      if (!byJti.size)
        return SKIP(incomplete
          ? `${incomplete} request(s) carried a jti but their bodies were never fully received, so none could be compared`
          : "no jti was sent");
      const replayed = [...byJti].filter(([, shapes]) => shapes.size > 1);
      const complete = s.length - incomplete;
      const note = incomplete
        ? `; ${incomplete} request(s) were left out because the body was never fully received, which a reset upload and its retry look like`
        : "";
      if (replayed.length) return FAIL(
        "one jti signed requests that differ, so a signature was replayed onto another request",
        replayed.map(([j, sh]) => `${String(j).slice(0, 16)} signed ${sh.size} different requests`).slice(0, 3), s.map(x => x.r));
      return byJti.size < complete
        ? PASS(`no jti signed two different requests; ${complete - byJti.size} identical resend(s) seen, which 5.3 leaves to the Company to reject${note}`)
        : PASS(`all ${byJti.size} jti values were distinct${note}`);
    },
  },
  {
    id: "delegation.typ",
    section: "5.2",
    quote: "`typ` MUST be `poppy-delegation+jwt`, so a delegation can't be used as a Session JWT.",
    run(log) {
      const s = sessionRequests(log);
      if (!s.length) return SKIP("no Session header was sent");
      const bad = [], none = [], hits = [];
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        if (!dlg) { none.push(`${r.method} ${r.path}`); continue; }
        if (dlg.header.typ !== "poppy-delegation+jwt") note(bad, hits, r, `${r.method} ${r.path}: ${JSON.stringify(dlg.header.typ)}`);
      }
      // Absence has its own check, delegation.present. Reporting it here was a
      // misattribution: the defect is that no delegation was sent at all, and 5.2 has its
      // own sentence for that.
      if (none.length && !bad.length) return SKIP("no delegation was sent, which delegation.present reports");
      return bad.length ? FAIL("a delegation did not declare poppy-delegation+jwt", bad.slice(0, 3), hits)
                        : PASS("every Session JWT carried a delegation declaring poppy-delegation+jwt");
    },
  },
  {
    id: "delegation.exp-24h",
    section: "5.2",
    quote: "`exp` MUST be at most 24 hours after `iat`.",
    run(log) {
      const s = sessionRequests(log);
      const dlgs = s.map(x => decodeJwt(x.jwt.header.poppy_dlg)).filter(Boolean);
      if (!dlgs.length) return SKIP("no delegation was sent");
      const bad = []; const hits = [];
      for (const d of dlgs) {
        const { iat, exp } = d.payload;
        if (typeof iat !== "number" || typeof exp !== "number") { bad.push(`iat or exp was not a number`); continue; }
        if (exp - iat > 86400) bad.push(`exp was ${Math.round((exp - iat) / 3600)}h after iat`);
      }
      return bad.length ? FAIL("a delegation lasted longer than 24 hours", [...new Set(bad)].slice(0, 3), s.map(x => x.r))
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
      const pairs = s.map(x => ({ dlg: decodeJwt(x.jwt.header.poppy_dlg), ses: x.jwt })).filter(p => p.dlg);
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
      for (const { dlg, ses } of pairs) {
        const payload = { ...dlg.payload };
        delete payload.iss;    // required by 5.2
        delete payload.cnf;    // the delegated key itself, random by construction
        const vals = new Set(leaves(payload));
        const hostOf = x => { try { return new URL(x).host.toLowerCase(); } catch { return null; } };
        for (const [what, value] of [["the User ID", ses.payload.sub], ["the Agent ID", ses.payload.agent_id],
                                     ["this Company's identifier", ctx.identifier]]) {
          if (value && vals.has(String(value))) bad.push(`the delegation contains ${what}`);
        }
        if (ctx.domain) for (const v of vals)
          if (v.toLowerCase() === String(ctx.domain).toLowerCase() || hostOf(v) === String(ctx.domain).toLowerCase())
            bad.push("the delegation names this Company's domain");
      }
      return bad.length ? FAIL("a delegation carried something it must not", [...new Set(bad)].slice(0, 4), s.map(x => x.r))
                        : PASS("no delegation carried a User ID, Agent ID, or anything naming this Company");
    },
  },
  {
    id: "version.constant",
    section: "3.4",
    quote: "On every request with the Session header (5.2), the Personal Agent sends the protocol version it implements, compatible with the chosen one, in `Poppy-Version`, as `major.minor`.",
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
      const withHeader = sessionRequests(log).filter(x => x.r.isResource);
      const any = resource.filter(r => r.headers?.["poppy-version"]);
      if (!any.length) return FAIL("no request carried a Poppy-Version header", [], resource);
      const bySid = new Map();
      for (const { r, jwt } of withHeader) {
        const sid = jwt.payload.sid;
        if (sid === undefined) continue;
        const v = r.headers?.["poppy-version"] ?? null;
        (bySid.get(sid) ?? bySid.set(sid, new Set()).get(sid)).add(String(v));
      }
      if (!bySid.size) return SKIP("no request carried both a Session header and a sid");
      const mixed = [...bySid].filter(([, v]) => v.size > 1);
      return mixed.length
        ? FAIL("Poppy-Version changed within one Session",
               mixed.map(([sid, v]) => `sid ${String(sid).slice(0, 12)}: ${[...v].join(", ")}`).slice(0, 3), withHeader.map(x => x.r))
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
      const bad = [], unknown = []; const hits = [];
      for (const { r, jwt } of s) {
        const dlg = decodeJwt(jwt.header.poppy_dlg);
        const jwk = dlg?.payload?.cnf?.jwk;
        if (!jwk) continue;                       // delegation.typ reports the absence
        const ok = verifyCompact(jwt.compact, jwk);
        if (ok === null) { unknown.push(`${r.method} ${r.path}: alg ${JSON.stringify(jwt.header.alg)}`); continue; }
        if (!ok) { note(bad, hits, r, `${r.method} ${r.path}: the signature does not verify against the delegation's cnf.jwk`); continue; }
        const thumb = thumbprintOf(jwk);
        if (thumb && jwt.header.kid && jwt.header.kid !== thumb)
          note(bad, hits, r, `${r.method} ${r.path}: kid is not the delegated key's thumbprint`);
      }
      if (bad.length) return FAIL("a Session JWT was not signed by the key its delegation names", bad.slice(0, 3), hits);
      if (unknown.length) return SKIP(`an algorithm this grader cannot verify: ${unknown[0]}`, "grader");
      return PASS(`every Session JWT verified against its delegation's key on ${s.length} request(s)`);
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
    id: "session.header-single",
    section: "5.2",
    quote: "The header holds a JWT that the Personal Agent signs for that one request, with a delegated key that a key from its `jwks_uri` vouches for",
    // One header, one JWT, one request. Two Poppy-Session headers are joined by Node into
    // one undecodable string, and left undetected that reads as "no Session header was
    // sent" on every claim check while session.header-sent passes: a self-contradicting
    // report that blames the agent for the wrong thing. record.mjs flags it instead.
    run(log) {
      const resource = log.filter(r => r.isResource);
      if (!resource.length) return SKIP("the agent made no request to a resource endpoint");
      const dupes = resource.filter(r => r.sessionHeaderDuplicated);
      return dupes.length
        ? FAIL("a request carried more than one Poppy-Session header, so no single JWT signs it",
               dupes.slice(0, 3).map(r => `${r.method} ${r.path}`), dupes)
        : PASS(`every one of ${resource.length} resource request(s) carried a single Session header`);
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
  }
];

// The cross-Company checks. These need logs from BOTH hostnames, and they are the reason
// the rig runs two Companies: nothing a single Company observes can establish them.
// RFC 7638 thumbprint, computed here rather than with jose so the checks stay synchronous
// and pure. Comparing JSON.stringify(cnf.jwk) hid a shared key behind member order or an
// extra `alg` member: measured, the same key with reordered members passed.
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
