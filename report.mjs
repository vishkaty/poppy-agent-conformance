// The report a builder reads after pointing their agent at the grader.
//
// Its failure modes are not the checks'. The two that matter are leaking one of the agent's
// secrets while reporting on it, and making an abstention read as a failure so a builder
// fixes something that was never broken. Everything below is shaped by those two.
//
// Pure: buildReport(run) -> object, renderHtml(report) -> string. A frozen run renders
// identically every time, because a report a builder saves must not change under them.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHECKS, PAIRWISE, grade, gradePair, decodeJwt, versionScopeOf, WINDOW_SECONDS, SKEW_SECONDS } from "./checks.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROV = JSON.parse(readFileSync(join(HERE, "spec/PROVENANCE.json"), "utf8"));
const REF_PROV = JSON.parse(readFileSync(join(HERE, "reference/PROVENANCE.json"), "utf8"));

// Which oracle judged this run, by its CONTENT.
//
// The obvious identifier, the sha256 of the kit archive we vendored from, is not one: it covers
// the whole kit, which changes whenever any of its ninety files changes, while the oracle here
// is three of them, so a report citing the archive would appear to cite a different oracle
// after a change to a file this grader never reads. So this digests the vendored files
// themselves, read from disk at report time, which also means an edited oracle changes the
// identity in every report rather than passing unnoticed.
function oracleIdentity() {
  const names = Object.keys(REF_PROV.files ?? {}).sort();
  const lines = names.map(n =>
    `${n}:${createHash("sha256").update(readFileSync(join(HERE, "reference", n))).digest("hex")}`);
  return { files: names.length, digest: createHash("sha256").update(lines.join("\n")).digest("hex").slice(0, 16),
           protocolVersion: REF_PROV.protocol_version_the_kit_validates ?? null };
}

// Section anchors, read from the capture rather than guessed, so a renamed anchor fails the
// suite instead of linking a builder to nothing.
const ANCHORS = (() => {
  const src = readFileSync(join(HERE, "spec/spec.mdx"), "utf8");
  const map = {};
  for (const m of src.matchAll(/^#{2,4}\s+([\d.]+)[^\n{]*\{#([a-z0-9-]+)\}/gim))
    map[m[1].replace(/\.$/, "")] = m[2];
  return map;
})();
export const anchorFor = section => ANCHORS[String(section)] ?? null;
const specLink = section => {
  const a = anchorFor(section);
  return a ? `https://personalagentprotocol.org/docs/1.0/spec#${a}` : "https://personalagentprotocol.org/docs/1.0/spec";
};

// What a builder must do to reach a rule this run did not. Kept here and not in checks.mjs,
// which stays a pure judgement of the text. `reachable: false` means this grader cannot
// offer the rule at all, which is our limit and must be said as ours.
export const REACH = Object.fromEntries([
  ...CHECKS.map(c => [c.id, { how: `Drive your agent through a signed-out task at this grader so that it sends a Session header on a listed destination, which is what rule ${c.id} reads.` }]),
  ...PAIRWISE.map(c => [c.id, { how: "Drive the same User through your agent at BOTH Companies, so at least one request with a Session header reaches each. Their identifiers differ, so the rule applies." }]),
]);
REACH["session.ath"] = { reachable: false,
  // Kept truthful after enforcement: a request carrying a token IS answered 401 now, because
  // section 7 makes a token this Company never issued an invalid_token, and 4.5 requires the
  // challenge. The rule is still judged, because the verdict comes from the recorded request
  // and not from what we answered.
  how: "This grader issues no access tokens, so a conforming agent has nothing to send here and this outcome is expected. You can still reach the rule by pointing a signed-in code path at it with a token of your own: the request is answered 401 invalid_token, because a token this Company never issued is invalid, and the rule is judged from the request anyway, comparing ath with the SHA-256 of whatever Authorization value arrived." };
REACH["session.not-on-documents"] = { how: "Let your agent do discovery against this grader: fetch /.well-known/poppy.json and the OAuth metadata. The rule reads whether a Session JWT went to any of them, which it must not." };
REACH["session.header-jwt"] = { how: "Send a request to a listed destination with a Poppy-Session header. The rule reads whether exactly one header arrived and whether its value is a JWT, so any such request judges it." };
REACH["delegation.alg"] = { how: "Send a request whose Session JWT carries a delegation. The rule reads the delegation's own alg, which 1.0 limits to ES256 and PS384." };

const PRIVATE_JWK = ["d", "p", "q", "dp", "dq", "qi", "k"];
const SHOWN_HEADERS = new Set(["host", "user-agent", "accept", "accept-encoding", "content-type",
  "content-length", "transfer-encoding", "poppy-version", "poppy-extensions", "signature-input", "x-request-id"]);

const sha = s => createHash("sha256").update(String(s)).digest("hex");
const iso = sec => new Date(sec * 1000).toISOString().replace(".000", "");

// Redaction. An allowlist, never a denylist: an unknown header is withheld by default,
// because the next header somebody invents could hold anything.
function redactJwk(jwk) {
  if (!jwk || typeof jwk !== "object") return jwk;
  const out = {};
  for (const [k, v] of Object.entries(jwk))
    out[k] = PRIVATE_JWK.includes(k)
      ? `<private member, ${String(v).length} chars, not shown>`   // the one place a FAIL could leak while reporting
      : v;
  return out;
}
function redactJwt(compact, { verified } = {}) {
  const d = decodeJwt(compact);
  if (!d) return { undecodable: true };
  const header = { ...d.header };
  if (header.poppy_dlg) header.poppy_dlg = "<delegation, shown below>";
  const payload = { ...d.payload };
  if (payload.cnf?.jwk) payload.cnf = { ...payload.cnf, jwk: redactJwk(payload.cnf.jwk) };
  // The signature is never shown: it is what would let this page re-sign a request, and no
  // check reads it as a value, only as a verification result.
  return { header, payload, signature: verified ?? "not shown; see the signature rule" };
}
function redactHeaders(h = {}, token) {
  const out = {};
  for (const [name, raw] of Object.entries(h)) {
    const v = String(raw);
    if (name === "poppy-session" || name === "dpop") { out[name] = "<JWT, decoded below>"; continue; }
    if (name === "authorization") {
      const bare = v.replace(/^(DPoP|Bearer)\s+/i, "");
      // The hash is exactly the `ath` the agent must compute, so it adds nothing an
      // observer of the request did not have, and it lets the builder compare by eye.
      out[name] = `${v.split(/\s/)[0]} <token not shown; sha256 base64url ${createHash("sha256").update(bare).digest("base64url")}; ${bare.length} chars>`;
      continue;
    }
    out[name] = SHOWN_HEADERS.has(name) ? v : `<${v.length} chars, not shown>`;
  }
  return out;
}
function redactUrl(url) {
  try {
    const u = new URL(url);
    // 5.6 forbids secrets in a URL, which is exactly why a value there may be one.
    for (const k of [...u.searchParams.keys()])
      u.searchParams.set(k, `<${String(u.searchParams.get(k)).length} chars>`);
    return u.toString();
  } catch { return "<unparseable url>"; }
}
function redactBody(r) {
  if (r.body === null || r.body === undefined) return "none";
  if (r.body === "") return "empty";
  const parts = [`${r.bodyBytes ?? r.body.length} bytes`];
  if (r.headers?.["content-type"]) parts.push(r.headers["content-type"]);
  parts.push(`sha256 ${(r.bodySha256 ?? sha(r.body)).slice(0, 8)}`);
  if (r.bodyTruncated) parts.push("truncated");
  parts.push(r.bodyComplete === false ? "incomplete" : "complete");
  return parts.join(", ");
}

function redactRecord(r, ordinal, runToken) {
  const ses = r.headers?.["poppy-session"];
  const jwt = ses ? decodeJwt(ses) : null;
  const dlg = jwt ? decodeJwt(jwt.header.poppy_dlg) : null;
  const note = r.rejected ? "rejected by the HTTP parser before a request existed, examined by no rule"
    : r.refused ? "refused: the target could be routed and classified differently, examined by no rule"
    : r.misdirected ? "misdirected: an absolute-form target for another authority, examined by no rule"
    : r.isResource ? null
    : r.mustNotCarry ? "a document that must not carry the Session header"
    : r.isPage ? "a website page, where the header is a SHOULD"
    : "not a Session destination, examined by no rule";
  return {
    ordinal, host: r.host ?? null, method: r.method ?? null, path: r.path ?? null,
    url: r.url ? redactUrl(r.url) : null,
    at: r.at ?? null, time: r.at ? iso(r.at) : null,
    isResource: !!r.isResource, isPage: !!r.isPage, mustNotCarry: !!r.mustNotCarry,
    classifiedAs: r.classifiedAs ?? null, note,
    headers: redactHeaders(r.headers, runToken),
    session: jwt ? redactJwt(ses) : null,
    delegation: dlg ? redactJwt(jwt.header.poppy_dlg) : null,
    jti: jwt?.payload?.jti ?? null,
    body: redactBody(r),
    // Lets a builder see that one request came from elsewhere, without this grader
    // publishing anybody's address. Salted with the run token so tags cannot be correlated
    // between runs.
    source: r.remoteAddress ? sha(runToken + r.remoteAddress).slice(0, 8) : null,
  };
}

// The verdict for a rule across two Companies: a FAIL anywhere is a FAIL; otherwise a PASS
// anywhere is a PASS; only if no Company could judge it at all is it an abstention.
//
// Taking the literal worst of the three made every rule abstain whenever one Company saw no
// traffic, which buried everything the other Company actually proved. The badges still show
// each Company separately, so a rule satisfied at one and unreached at the other reads as
// exactly that.
function worstOf(verdicts) {
  if (verdicts.includes("FAIL")) return "FAIL";
  if (verdicts.includes("PASS")) return "PASS";
  return "INCONCLUSIVE";
}

export function buildReport(run) {
  // One Company is a real shape, not two with a hole in it. A recorded run is judged from
  // whatever the builder recorded, and handing this function a faked empty second Company made
  // the fake visible: "recorded at shop.example and undefined", a per-Company badge reading
  // `undefined` beside every abstention, and a destinations sentence naming a Company nobody ran.
  const [A, B] = run.companies;
  const both = run.companies.filter(Boolean);
  const names = both.map(c => c.ctx?.domain).filter(Boolean);
  const runToken = run.token ?? "";
  // One index across both Companies, in time order, so an ordinal identifies a request.
  const all = both.flatMap(c => c.log.map(r => ({ r, origin: c.ctx.identifier })))
    .sort((x, y) => (x.r.at ?? 0) - (y.r.at ?? 0));
  // What was recorded and deliberately NOT judged, and why. 3.4 lets a Company serve several
  // versions at once, and this grader holds published 1.0 alone, so a request declaring a version
  // this Company serves under another text is read by no rule. Dropping those silently would be
  // worse than judging them wrongly: the reader could not see it happen, and a report that never
  // mentions the traffic reads as though it never arrived.
  const scopeOf = new Map();
  for (const c of both)
    for (const r of c.log) scopeOf.set(r, versionScopeOf(r, c.ctx));
  const outOfScope = [...scopeOf].filter(([, s]) => s === "out-of-scope").map(([r]) => r);
  // The absent header is its own case and reads badly in a list: a Company serving a version
  // older than 0.4, where `Poppy-Version` was introduced, cannot tell a conforming agent of that
  // version from a 1.0 agent that omitted it, so "declared 0.4, none" would misdescribe it.
  const declaredSet = new Set(outOfScope.map(r => r.headers?.["poppy-version"]));
  const declaredVersions = [...declaredSet].filter(v => typeof v === "string" && v !== "").sort();
  const someDeclaredNothing = outOfScope.some(r => {
    const v = r.headers?.["poppy-version"];
    return typeof v !== "string" || v === "";
  });
  const declaredPhrase = [declaredVersions.length ? declaredVersions.join(", ") : null,
                          someDeclaredNothing ? "no version at all" : null]
    .filter(Boolean).join(", or ");
  const servedVersions = [...new Set(both.flatMap(c => c.ctx?.servedVersions ?? []))].sort();

  const ordinalOf = new Map();
  const requests = all.map(({ r }, i) => { ordinalOf.set(r, i + 1); return redactRecord(r, i + 1, runToken); });

  // What this Company REFUSED, and whether its refusal is why the run stopped.
  //
  // Enforcement introduced a way for this report to lie. Section 7 tells an agent that gets
  // invalid_session to stop sending the request until it fixes the cause, so a run can end at
  // its first request, and every rule after it is unreached. The advice beside an unreached
  // rule tells the builder to drive their agent so that it reaches the rule, which they did:
  // we refused it. So a run whose LAST recorded request was refused, with nothing after it,
  // says so, and says it in place of that advice.
  const rejected = all.filter(({ r }) => r.rejection).length;
  const last = all.length ? all[all.length - 1].r : null;
  const stoppedBy = last?.rejection ?? null;
  const stopped = stoppedBy
    ? `The last request this grader saw, #${ordinalOf.get(last)}, was refused under ${stoppedBy.rule} with ${stoppedBy.error}, and nothing followed it. Section 7 tells a Personal Agent that receives ${stoppedBy.error} to stop sending the request until it fixes the cause, so the rules below that were not reached may be unreached because this Company stopped your agent there, and not because your agent does not implement them. Fix that one request and run again.`
    : null;

  const perEach = both.map(c => ({ identifier: c.ctx.identifier, verdicts: grade(c.log, c.ctx) }));
  const byId = id => perEach
    .map(c => ({ company: c.identifier, ...c.verdicts.find(x => x.id === id) }))
    .map(v => ({ company: v.company, verdict: v.verdict, cause: v.cause ?? null, why: v.why,
                evidence: v.evidence ?? [],
                decidedBy: (v.decidedBy ?? []).map(r => ordinalOf.get(r)).filter(Boolean) }));

  // A recorded run is judged against the builder's OWN Company, so advice written for the hosted
  // rig is not merely unhelpful there, it is wrong: it tells a builder to point a signed-in code
  // path at "this grader", which in a recorded run is their own service. Replaced, not appended.
  const recorded = run.mode === "recorded";
  const RECORDED_REACH = {
    "session.ath": { reachable: true, how: "Your own Company issues the access tokens here, so drive your agent through a signed-in task against it and this rule is judged for real, which a hosted run cannot do." },
    "session.not-on-documents": { reachable: true, how: "The recorder saw no fetch of a document 5.2 forbids a Session on. If your poppy.json or OpenAPI document is served by another host, record that host too and judge the files together: one issuer is one Company (3.2), so the logs join." },
    "pairwise.user-id": { reachable: true, how: "This needs two Companies with different identifiers. Record a second Company and pass both files to the judge." },
    "pairwise.delegated-key": { reachable: true, how: "This needs two Companies with different identifiers. Record a second Company and pass both files to the judge." },
  };
  const reachFor = (id) => {
    // In a recorded run the Company being driven is the builder's own, so advice that says
    // "this grader" is telling them to point their agent at themselves. The four rules whose
    // advice changes completely have overrides above; for the rest only the name is wrong.
    const named = (b) => (recorded && b?.how)
      ? { ...b, how: b.how.replace(/this grader/g, "your own Company") }
      : b;
    const base = named((recorded && RECORDED_REACH[id]) || REACH[id]);
    if (!stopped) return base;
    // Not appended to the old advice: the old advice is wrong here, so it is replaced. What is
    // kept is the note for a rule this grader cannot offer at all, which is our limit and not
    // a consequence of the refusal.
    if (base?.reachable === false) return base;
    return { ...base, how: stopped };
  };

  const rules = CHECKS.map(c => {
    const perCompany = byId(c.id);
    const worst = worstOf(perCompany.map(v => v.verdict));
    return { id: c.id, section: c.section, quote: c.quote, anchor: anchorFor(c.section),
             link: specLink(c.section), perCompany, worst,
             reach: worst === "INCONCLUSIVE" ? reachFor(c.id) : null,
             threshold: c.id === "session.iat-window" ? `${WINDOW_SECONDS} s plus ${SKEW_SECONDS} s of clock skew` : null };
  });
  const pairwise = gradePair(A.log, B?.log ?? [], A.ctx, B?.ctx ?? null).map(v => ({
    id: v.id, section: v.section, quote: v.quote, anchor: anchorFor(v.section), link: specLink(v.section),
    verdict: v.verdict, cause: v.cause ?? null, why: v.why, evidence: v.evidence ?? [],
    reach: v.verdict === "INCONCLUSIVE" ? reachFor(v.id) : null,
  }));

  // Requests this Company answered with an error that NO rule claimed. Found when conversation
  // requests were refused by the 5.3 state guard, which is not an enforced rule: `rejected`
  // stayed 0 and the report said nothing was refused while the agent had been told, in section
  // 7's words, to stop sending the request.
  //
  // Computed HERE, after the verdicts, because "no rule claims it" has to be a statement about
  // the verdicts rather than a guess. It was a guess, and it contradicted them: a conversation
  // POST with no request id is answered 400 by the conversation handler and is also the evidence
  // of the 8.3 FAIL, so the report said no rule claimed a request that a rule below cited by
  // number. A 502 from the recorder when a Company cannot be reached is excluded too, because
  // that is not an answer the Company gave.
  const claimedByARule = new Set();
  for (const c of perEach)
    for (const v of c.verdicts)
      if (v.verdict === "FAIL") for (const r of v.decidedBy ?? []) claimedByARule.add(r);
  const answeredWithError = all.filter(({ r }) =>
    !r.rejection && !claimedByARule.has(r)
    && (r.response?.status ?? 0) >= 400
    && r.response?.error !== "recorder_upstream_unreachable");

  const count = v => rules.filter(r => r.worst === v).length + pairwise.filter(p => p.verdict === v).length;
  const summary = {
    fail: count("FAIL"), pass: count("PASS"),
    unreached: [...rules.filter(r => r.worst === "INCONCLUSIVE" && r.perCompany.every(c => c.cause !== "grader")),
                ...pairwise.filter(p => p.verdict === "INCONCLUSIVE" && p.cause !== "grader")].length,
    unjudged: [...rules.filter(r => r.worst === "INCONCLUSIVE" && r.perCompany.some(c => c.cause === "grader")),
               ...pairwise.filter(p => p.verdict === "INCONCLUSIVE" && p.cause === "grader")].length,
    rules: rules.length + pairwise.length, requests: requests.length,
    // Requests this Company answered with an error that NO rule claimed. Found when conversation
    // requests were refused by the 5.3 state guard, which is not an enforced rule: `rejected`
    // stayed 0 and the report said nothing was refused while the agent had been told, in
    // section 7's words, to stop sending the request. A report that
    // shows "failed 0" beside a refusal it does not mention is the kind of quiet disagreement
    // this grader exists to prevent.
    answeredWithError: answeredWithError.length,
    // Requests this Company refused rather than answered. Counted here because a report whose
    // failures all come from refused requests is a different thing from one whose failures came
    // from requests that were served.
    rejected,
    // How many places this run's traffic came from. One is the ordinary case. More than one
    // means something that is not the builder's agent reached the grader while they held the
    // lease, which no amount of attribution can prevent and which they have to be told,
    // because a bare request from elsewhere is a failure on a rule they did not break.
    sources: new Set(all.map(({ r }) => r.remoteAddress).filter(Boolean)).size,
    // Recorded, examined by no rule, because the version it declared is one this Company serves
    // under a text this grader does not hold. Never folded into failed, passed or not reached:
    // those are verdicts and this is the absence of one.
    notJudgedForVersion: outOfScope.length,
  };

  // Counts, never adjectives, and never the word conform.
  const topSentence = requests.length === 0
    ? "No request reached the grader during this run, so no rule was judged."
    : `Of the ${summary.rules} rules this grader can judge, your agent failed ${summary.fail}, `
      + `passed ${summary.pass}, did not reach ${summary.unreached}, and ${summary.unjudged} `
      + `could not be judged by the grader, on ${summary.requests} requests recorded at `
      + `${names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0] ?? "this Company"}`
      + (run.started && run.ended ? ` between ${iso(run.started)} and ${iso(run.ended)}.` : ".")
      // Said in the first sentence rather than a footnote, because a reader who does not see it
      // there will read the counts above as covering everything that arrived.
      + (summary.notJudgedForVersion
          ? ` A further ${summary.notJudgedForVersion} request(s) were recorded and not judged:`
            + ` they declared ${declaredPhrase}, and this Company serves`
            + ` ${servedVersions.join(", ")}, so they were handled under a version whose text`
            + " this grader does not hold. They are counted here and examined by no rule."
          : "");

  const issuers = [...new Set(all.map(({ r }) => decodeJwt(r.headers?.["poppy-session"])?.payload?.iss).filter(Boolean))];

  return {
    spec: { version: PROV.version, published: PROV.published, commit: PROV.commit,
            specSha256: PROV.pages?.spec?.sha256 ?? null, verified: PROV.verified_against_authors_hashes },
    grader: { commit: run.graderCommit ?? "unknown", oracle: oracleIdentity(),
              clock: iso(Math.floor(Date.now() / 1000)) },
    run: { started: run.started ?? null, ended: run.ended ?? null, frozen: !!run.frozen,
           companies: both.map(c => c.ctx.identifier), issuers },
    summary, topSentence, rules, pairwise, requests,
    answeredWithError: answeredWithError.length
      ? `${answeredWithError.length} request(s) were answered with an error by this Company that no rule below claims: `
        + answeredWithError.slice(0, 3).map(({ r }) => `#${ordinalOf.get(r)} ${r.method} ${r.path} answered ${r.response.status}`
            + `${r.response.error ? ` ${r.response.error}` : ""}`).join(", ")
        + ". Those are this Company's own answers rather than a rule's verdict, so read them beside the verdicts and not instead of them."
      : null,
    // What kind of run this was, and what that costs. A recorded run is judged from a file its
    // owner could have edited, so it is evidence to its owner and to nobody else. Saying so is
    // the difference between a useful self-check and a certificate nobody should trust.
    selfRecorded: recorded
      ? `Self-recorded run. This log was recorded by a recorder in front of your own Company at ${A.origin ?? A.ctx?.identifier ?? "your origin"} and judged on this machine. Nothing in it was observed by anyone else, so it is evidence to you and not to a third party. If your agent and this recorder ran on one machine they share a clock, so a pass on session.iat-window says less here than it would across a network; and this grader did not fetch the documents of your agent, so delegation.signature abstains as its own limit rather than as anything about your agent.`
      : null,
    about: {
      judgedAgainst: `Personal Agent Protocol ${PROV.version} as published ${PROV.published}, from commit ${PROV.commit} of personal-agent-protocol/personal-agent-protocol, verified against the authors' own hashes.`,
      scope: `This grader judges ${summary.rules} rules of ${PROV.version}: ${CHECKS.length} that one Company can see and ${PAIRWISE.length} that need two. ${PROV.version} contains many more requirements. A PASS on a rule means the recorded requests satisfied that sentence. It is not a statement that your agent conforms to ${PROV.version}.`,
      destinations: `The grader saw only what reached ${names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}` : names[0] ?? "this Company"}. A request to any other origin was examined by no rule.`,
      notJudged: [
        // Conditional, because it stopped being true. A report whose own delegation.signature
        // verdict was decided from a fetched key set must not also list that rule as
        // unimplemented, and a deployment that fetches nothing must still say that it does not.
        // Three cases, not two. A deployment that fetched and succeeded says nothing here; one
        // that fetched and failed says why, in the words the resolver used, because blaming our
        // own configuration for the agent's unreachable identity sends a builder looking in the
        // wrong place; one that never fetches says so.
        ...(all.some(({ r }) => r.issuerKeys?.outcome === "ok")
          ? []
          : (() => {
              const tried = all.map(({ r }) => r.issuerKeys).find(k => k && k.outcome !== "ok" && k.detail);
              return [tried
                ? `A delegation's signature against the key published at the agent's jwks_uri. This deployment did fetch, and could not read a key set: ${tried.detail}. The delegation is shown as not verified for that reason.`
                : "A delegation's signature against the key published at the agent's jwks_uri. This deployment did not fetch the agent's documents, so the delegation is shown as not verified."];
            })()),
        "Whether a User ID or Agent ID was derived from personal information. 5.1 forbids it even with a keyed hash, and the guides allow an HMAC of an internal id, which a Company cannot tell apart on the wire.",
      ],
      recordedNotJudged: {
        // Requests that arrived after this run's per-Company limit. Counted and reported,
        // never silently dropped: absence that does not announce itself reads as conformance.
        beyondLimit: run.beyondLimit ?? 0,
        // Requests that reached the Companies in the window before this run was leased, and
        // so belong to no run. An agent that fetches a discovery document once at startup
        // and caches it does it here, which is why a rule about documents can abstain on a
        // run that did everything right.
        beforeLease: run.beforeLease ?? 0,
        misdirected: all.filter(({ r }) => r.misdirected).length,
        rejected: all.filter(({ r }) => r.rejected).length,
        refused: all.filter(({ r }) => r.refused).length,
        incompleteBodies: all.filter(({ r }) => r.bodyComplete === false).length,
      },
      warnings: run.warnings ?? [],
      // Said when this Company's own refusal is why the run ended, and null otherwise, so a
      // report never carries this excuse unless it earned it.
      stopped,
      sources: summary.sources > 1
        ? `This run's requests came from ${summary.sources} different sources. One agent is graded at a time, but anything that can reach these hostnames can send a request, so a request here may not be yours: a scanner probing the hostname, or an earlier run's agent still polling. The request index shows a salted source per request, so you can tell which are yours.`
        : null,
      beforeLease: (run.beforeLease ?? 0) > 0
        ? `${run.beforeLease} request(s) reached the Companies in the ${Math.round((run.beforeLeaseWindowSeconds ?? 600) / 60)} minutes before this run was leased and belong to no run, so no rule judged them. An agent that fetches a discovery document once at startup and caches it does it here, which is the usual reason a rule about documents is not reached by a run that did everything right.`
        : null,
      transport: "Verdicts are judged against the request as this grader received it. Anything in front of the grader that rewrites a request URL, for example normalising percent encoding or removing dot segments, would be judged as the agent's doing. The grader's own clock is shown above: a constant offset between it and your `iat` values is a clock, not a defect.",
      privacy: recorded
        ? "This report was built on your own machine from a log on your own disk. Nothing about this run reached anyone else, and nothing is published."
        : "This report is private to whoever holds its link. It is not listed anywhere and nothing about this run is published.",
      retention: recorded
        ? "This file lives wherever you put it, for as long as you keep it. Judge the same log again and you get the same verdicts."
        : "The report is held in memory for at most 24 hours, and until this grader process restarts, whichever comes first. After that its link answers exactly what an unknown link answers.",
      notReplayable: "Signatures, access tokens and bodies are not shown on this page, so the verdicts cannot be rerun from it. They are a pure function of the recorded requests at the grader commit above.",
    },
  };
}

const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const pre = o => `<pre>${esc(JSON.stringify(o, null, 1))}</pre>`;

const LABEL = { FAIL: "FAIL", PASS: "PASS" };
const skipLabel = cause => cause === "grader" ? "Not judged by this grader" : "Not reached by your agent";

// One rule, rendered ONCE, in the group of its worst verdict, with a badge per Company.
//
// Rendering it in every group a Company reached meant a rule that failed at one Company and
// abstained at the other appeared twice, and the abstention copy carried the other
// Company's FAIL badge. An abstention that shows the word FAIL is exactly the confusion the
// three-verdict split exists to prevent.
function ruleBlock(r) {
  const cls = v => v === "INCONCLUSIVE" ? "skip" : v.toLowerCase();
  const badges = r.perCompany.map(c =>
    `<span class="b b-${cls(c.verdict)}">${c.verdict === "INCONCLUSIVE" ? esc(skipLabel(c.cause)) : LABEL[c.verdict]}</span> <code>${esc(c.company)}</code>`).join("<br>");
  const body = r.perCompany.map(c => {
    const reqs = c.decidedBy.map(o => `<li>request #${o}</li>`).join("");
    return `<div><p><code>${esc(c.company)}</code>: ${esc(c.why)}</p>`
      + (r.threshold && c.verdict === "FAIL" ? `<p class="t">Threshold used by this grader: ${esc(r.threshold)}</p>` : "")
      + (c.evidence?.length ? `<ul>${c.evidence.map(e => `<li>${esc(e)}</li>`).join("")}</ul>` : "")
      + (reqs ? `<p>Decided by:</p><ul>${reqs}</ul>` : "")
      + `</div>`;
  }).join("");
  return `<section data-verdict="${r.worst}" class="v-${cls(r.worst)}">`
    + `<h3><code>${esc(r.id)}</code> <span class="s">spec ${esc(r.section)}</span></h3>`
    + `<p>${badges}</p><blockquote>${esc(r.quote)}</blockquote>`
    + `<p><a href="${esc(r.link)}">Read spec ${esc(r.section)}</a></p>${body}`
    + (r.worst === "INCONCLUSIVE" && r.reach ? `<p class="r">${esc(r.reach.how)}</p>` : "")
    + `</section>`;
}
function pairBlock(p) {
  const v = p.verdict;
  return `<section data-verdict="${v}" class="v-${v === "INCONCLUSIVE" ? "skip" : v.toLowerCase()}">`
    + `<h3><code>${esc(p.id)}</code> <span class="s">spec ${esc(p.section)}</span> `
    + `<span class="b b-${v === "INCONCLUSIVE" ? "skip" : v.toLowerCase()}">${v === "INCONCLUSIVE" ? esc(skipLabel(p.cause)) : LABEL[v]}</span></h3>`
    + `<blockquote>${esc(p.quote)}</blockquote><p><a href="${esc(p.link)}">Read spec ${esc(p.section)}</a></p>`
    + `<p>${esc(p.why)}</p>`
    + (v === "INCONCLUSIVE" && p.reach ? `<p class="r">${esc(p.reach.how)}</p>` : "");
}

export function renderHtml(rep) {
  const groups = ["FAIL", "INCONCLUSIVE", "PASS"];
  const rules = groups.map(g => rep.rules.filter(r => r.worst === g).map(ruleBlock).join("")
    + rep.pairwise.filter(p => p.verdict === g).map(pairBlock).join(""));
  const index = rep.requests.map(q =>
    `<section class="q"><h4>#${q.ordinal} ${esc(q.method ?? "?")} <code>${esc(q.url ?? q.path ?? "")}</code></h4>`
    + `<p>${esc(q.time ?? "")} (${esc(q.at ?? "")})${q.jti ? ` &middot; jti <code>${esc(q.jti)}</code>` : ""}`
    + `${q.source ? ` &middot; source ${esc(q.source)}` : ""}</p>`
    + `<p>${esc(q.classifiedAs ?? "")}${q.note ? ` &middot; ${esc(q.note)}` : ""}</p>`
    + `<p>Body: ${esc(q.body)}</p>${pre(q.headers)}`
    + (q.session ? `<p>Session JWT:</p>${pre(q.session)}` : "")
    + (q.delegation ? `<p>Delegation:</p>${pre(q.delegation)}` : "")
    + `</section>`).join("");
  const a = rep.about;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<title>Agent report</title><style>`
    + `body{font:14px/1.55 system-ui,sans-serif;margin:0 auto;padding:1.5rem;max-width:52rem;color:#111;background:#fff}`
    + `code,pre{font-family:ui-monospace,monospace;font-size:.92em}`
    + `pre{background:#f6f6f6;padding:.6rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all}`
    + `blockquote{margin:.5rem 0;padding:.4rem .8rem;border-left:3px solid #ccc;color:#333}`
    + `section{border-top:1px solid #e5e5e5;padding:.8rem 0}`
    + `.b{display:inline-block;padding:.05rem .4rem;border-radius:3px;font-weight:600;font-size:.85em}`
    + `.b-fail{background:#fde2e1;color:#8a1c13}.b-pass{background:#e2f3e5;color:#1d5c29}`
    + `.b-skip{background:#ececec;color:#444}`
    + `.s{color:#666;font-weight:400;font-size:.85em}.t,.r{color:#444}h1{font-size:1.3rem}h3{font-size:1rem;margin:.2rem 0}`
    + `h4{font-size:.95rem;margin:.2rem 0}summary{cursor:pointer;font-weight:600}`
    + `</style></head><body>`
    + `<h1>What your agent put on the wire</h1><p>${esc(rep.topSentence)}</p>`
    + (rep.selfRecorded ? `<p><strong>${esc(rep.selfRecorded)}</strong></p>` : "")
    + (rep.answeredWithError ? `<p>${esc(rep.answeredWithError)}</p>` : "")
    + `<p>${rep.run.frozen
        ? `This run has ended and is frozen. Save this page; it is not listed anywhere.`
        : `This run is open. Verdicts cover the requests seen so far and will change as more arrive.`}</p>`
    + (rep.run.issuers.length > 1
        ? `<p>Requests from ${rep.run.issuers.length} client_ids reached the grader during this run; verdicts cover all of them. The request index shows which.</p>` : "")
    // Both of these go ABOVE the verdicts rather than in the About section, because each is
    // an explanation of a verdict a builder is about to read and disagree with.
    + (a.stopped ? `<p><strong>${esc(a.stopped)}</strong></p>` : "")
    + (a.sources ? `<p>${esc(a.sources)}</p>` : "")
    + (a.beforeLease ? `<p>${esc(a.beforeLease)}</p>` : "")
    + `<h2>Failed</h2>${rules[0] || "<p>Nothing failed.</p>"}`
    + `<h2>Not judged</h2>${rules[1] || "<p>Every rule was judged.</p>"}`
    + `<details><summary>Passed</summary>${rules[2] || "<p>Nothing passed.</p>"}</details>`
    + `<h2>Requests</h2>${index || "<p>No request was recorded.</p>"}`
    + `<h2>About this report</h2><p>${esc(a.judgedAgainst)}</p>`
    + `<p>Grader commit ${esc(rep.grader.commit)}, judged with the authors own `
    + `${rep.grader.oracle.files} vendored files, content digest ${esc(rep.grader.oracle.digest)}. `
    + `That digest is of the files themselves and not of the archive they came from, which `
    + `changes between downloads of identical content.</p>`
    + `<p>${esc(a.scope)}</p><p>${esc(a.destinations)}</p>`
    + `<p>Not judged by this grader at all:</p><ul>${a.notJudged.map(x => `<li>${esc(x)}</li>`).join("")}</ul>`
    + `<p>Recorded but not judged: ${esc(JSON.stringify(a.recordedNotJudged))}.</p>`
    + (a.warnings.length ? `<ul>${a.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul>` : "")
    + `<p>Grader clock when this page was built: ${esc(rep.grader.clock)}.</p>`
    + `<p>${esc(a.transport)}</p>`
    + `<p>${esc(a.privacy)}</p><p>${esc(a.retention)}</p><p>${esc(a.notReplayable)}</p></body></html>`;
}
