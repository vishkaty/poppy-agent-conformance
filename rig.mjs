// The run model: two Companies, one exclusive lease, one private report.
//
// Two Companies because several sentences of 1.0 can only be judged across two of them: that
// a User ID differs per Company (5.1) and that a delegated key is not shared between them
// (5.2). Locally they are two loopback ports; in production two hostnames with one tunnel
// ingress rule each, so each Company keeps its own configured public origin and the public
// URL is never derived from a Host header.
//
// Attribution is by LEASE, not by the `iss` of the Session JWT. The headline failure this
// grader exists to catch is a request carrying no Session JWT at all, which has no iss to
// attribute by; charging another builder's bare request to this run would produce a wrong
// FAIL, and a wrong FAIL is the most expensive output this instrument can produce. The cost
// of the choice is that one builder runs at a time, and that is the right way round.
import { createGrader } from "./server.mjs";
import { buildReport, renderHtml } from "./report.mjs";
import { CHECKS, PAIRWISE } from "./checks.mjs";
import { randomBytes, createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

export const CONTROL_PREFIX = "/grader/";
const LEASE_SECONDS = 15 * 60;
const RETENTION_SECONDS = 24 * 3600;
const MAX_PER_COMPANY = 2000;

// The rules the canary is built to make PASS, written out rather than computed.
//
// A computed list would silently absorb the next check added to checks.mjs, and a canary
// that expects nothing passes for free, which is this project's commonest recorded defect.
// Every id in CHECKS and PAIRWISE must appear here or in CANARY_EXCLUDED, and a test
// enforces that, so a new check cannot be forgotten by either.
export const CANARY_RULES = [
  "session.header-sent", "session.header-jwt", "session.iss-https", "session.typ", "session.alg", "session.aud", "session.htm-htu",
  "session.iat-window", "session.claims-present", "session.sub-stable", "session.jti-unique",
  "session.signature", "session.not-on-documents",
  "delegation.present", "delegation.typ", "delegation.alg", "delegation.exp-24h",
  "delegation.not-expired", "delegation.iss-matches", "delegation.no-identifiers",
  "delegation.no-private-key", "version.constant", "version.sent",
  // The canary's own conversation POST carries a request id (8.3), so this rule is exercised
  // by the control rather than excluded from it.
  "conversation.request-id", "conversation.id-format",
  "conversation.message-content", "conversation.message-author",
  "pairwise.user-id", "pairwise.delegated-key",
];

// Rules the canary expects to ABSTAIN, with the cause each must carry.
//
// `delegation.signature` is here rather than above because a deployment that does not fetch
// the agent's documents cannot verify a delegation, and the honest outcome is an abstention
// with cause "grader". Requiring a PASS would be satisfied by a grader that fetched nothing
// and said everything was fine, which is the vacuous pass this gate exists to prevent, and
// excluding it entirely would let the rule rot into an abstention nobody notices. So both
// branches assert: PASS when this deployment fetches, this cause when it does not.
export const CANARY_ABSTAINS = {
  "delegation.signature": "grader",
};
export const CANARY_EXCLUDED = {
  "session.ath": "This grader issues no access tokens, so the canary has none to bind and a "
    + "conforming agent would send no ath here. The rule is judged only for a builder who "
    + "points a signed-in code path at it with a token of their own.",
};

const sha = s => createHash("sha256").update(String(s)).digest("hex");
const token22 = () => randomBytes(16).toString("base64url");       // 22 chars, 128 bits
const realNow = () => Math.floor(Date.now() / 1000);

// What the Company says it is, read from its OWN published document rather than from the
// configuration behind it. The grader judges htu and aud against the configured origin, so
// taking the canary's expectations from the published document makes a disagreement between
// the two visible instead of self-confirming.
function ctxOf(discovery) {
  return { identifier: discovery?.auth?.issuer, domain: discovery?.organization?.domain };
}
const publicOriginOf = d => { try { return new URL(d.auth.issuer).origin; } catch { return null; } };

// A loopback origin and a public one are the same request by construction, so the public leg
// below carries information only when the configured origin is a real hostname. An IP literal
// in 127.0.0.0/8 or ::1 is the case where it does not.
const isLoopbackLiteral = host => /^(\[::1\]|::1|127(\.\d{1,3}){3})$/.test(String(host));

// The first leg of the canary this deployment refused.
//
// The rule verdicts are one guard on a misconfigured deployment. This is a second and a
// blunter one: whatever the rules say, a non 2xx answer to traffic the protocol authors' own
// code built means this Company would stop a conforming agent at its first request. It also
// catches answers no rule covers, such as a 405 from a method mismatch, a 404 from a
// destination we do not actually serve, or a 500 from our own code.
export function firstRefusedLeg(legs) {
  for (const leg of legs ?? []) if (!(leg.status >= 200 && leg.status < 300)) return leg;
  return null;
}

// A conforming agent, driven by the protocol authors' own signing code.
//
// Their TypeScript is imported directly, as their own validator runs it. An import failure
// is not caught and skipped: a control that quietly opts out is the vacuous pass this file
// exists to prevent, so the gate above turns it into a refusal to grade.
async function driveCanary(graders, ports, collector, { publicBase, module: mod, verifies,
                                                        send: sendRequest = globalThis.fetch }) {
  const ref = await import(mod);
  for (let i = 0; i < graders.length; i++) {
    const d = graders[i].config.discovery;
    const pub = publicOriginOf(d);
    const ctx = ctxOf(d);
    const sendBase = `http://127.0.0.1:${ports[i]}`;

    // One identity per Company, which is what a correct agent does: its own User ID and its
    // own delegated key, which is exactly what the two pairwise rules read.
    const operator = await ref.generateKey();
    const key = await ref.generateKey();

    // Where this canary's client metadata lives. When this deployment verifies delegations
    // against the agent's jwks_uri, the canary PUBLISHES its operator key on the Company it
    // drives and names that URL as its iss, so the verifier fetches it exactly as it fetches a
    // builder's. Otherwise the iss stays a name that resolves nowhere, and the gate requires
    // delegation.signature to abstain rather than pass, which is the other half of the
    // assertion: a pass with no key set would be a statement about nothing.
    const clientId = verifies ? graders[i].canaryClientId : CANARY_CLIENT_ID;
    if (verifies) {
      const kid = await ref.thumbprint(operator.publicJwk);
      graders[i].setCanaryIdentity({
        "agent.json": { client_id: clientId, jwks_uri: new URL("./jwks.json", clientId).toString() },
        "jwks.json": { keys: [{ ...operator.publicJwk, kid }] },
      });
    }

    const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk,
                                                  iss: clientId });
    const sub = ref.randomId(16), sid = ref.randomId(16);

    // The exclusion of 5.2: documents carry no Session header.
    await sendRequest(`${sendBase}/.well-known/poppy.json`).catch(() => {});

    const op = (graders[i].config.apiOperations ?? []).find(o => String(o.method).toUpperCase() === "GET");
    // No compiled OpenAPI operation means the canary cannot send an API request at all, so
    // every rule it still reaches would pass while it examined a fraction of what it
    // believes it does. Reported, not worked around.
    if (!op) { collector.shortfall ??= []; collector.shortfall[i] = "no GET operation is configured, so the canary sent no API request"; }

    const targets = [
      ...(op ? [{ method: "GET", path: op.template.replace(/\{[^}]*\}/g, "1") }] : []),
      ...(op ? [{ method: "GET", path: op.template.replace(/\{[^}]*\}/g, "2") }] : []),
      // A conforming 8.3 body: a request `id`, which 8.2 requires of every POST, and a message
      // with at least one of text, data, context or extensions, which 8.4 requires. It used to
      // send neither, so this Company answered its own canary with 400 invalid_request once
      // section 8 was implemented. The status guard in the gate is what caught it, which is the
      // case that guard exists for: every rule passed and the answer was still an error.
      { method: "POST", path: new URL(d.agent.protocols.find(p => p.type === "poppy").endpoint).pathname,
        body: JSON.stringify({ id: `canary_${ref.randomId(8)}`,
                               message: { author: { type: "agent" }, text: "canary check from the grader's own control" } }) },
    ];
    collector.intended[i] = targets.length;

    const leg = async (base, t) => {
      // The htu claim is built from the PUBLISHED origin, while the grader compares it with
      // the CONFIGURED one. Those are one variable in production, which is why the public
      // leg below exists: it is the only part of this control that is not a function of the
      // same configuration it is checking.
      const jwt = await ref.signSessionJwt({ key, delegation, iss: clientId,
        aud: ctx.identifier, sid, sub, method: t.method, url: `${pub}${t.path}` });
      collector.minted.add(jwt);
      try {
        const res = await sendRequest(`${base}${t.path}`, {
          method: t.method, body: t.body,
          headers: { "poppy-session": jwt, "poppy-version": d.protocol_version,
                     ...(t.body ? { "content-type": "application/json" } : {}) },
        });
        let error = null;
        try { error = (await res.clone().json())?.error ?? null; } catch { /* not JSON */ }
        collector.legs.push({ status: res.status, path: t.path, method: t.method,
                              origin: graders[i].config.origin, error });
      } catch (err) { collector.sendError[i] = String(err?.cause?.code ?? err?.message ?? err); }
      return jwt;
    };

    for (const t of targets) await leg(sendBase, t);

    // The public leg. One request through the hostname a builder is given, asserted below to
    // have arrived at THIS Company with the Host it was sent to. It is what catches a tunnel
    // whose ingress rules are swapped, a hostname pointing at nothing, and a hostname still
    // pointing at an older process: none of which a loopback request can see.
    const configured = new URL(graders[i].config.origin);
    if (!isLoopbackLiteral(configured.hostname)) {
      collector.publicLeg[i] = {
        host: configured.host,
        jwt: await leg(publicBase?.[i] ?? configured.origin, targets.at(-1)),
      };
    }
  }
}
const CANARY_CLIENT_ID = "https://grader.invalid/canary.json";

export function createRig(cfg = {}) {
  const companies = cfg.companies ?? [];
  if (companies.length !== 2) throw new Error(`a run needs exactly two Companies, got ${companies.length}`);
  const leaseSeconds = cfg.leaseSeconds ?? LEASE_SECONDS;
  const retentionSeconds = cfg.retentionSeconds ?? RETENTION_SECONDS;
  const maxPerCompany = cfg.maxRequestsPerCompany ?? MAX_PER_COMPANY;
  const graderCommit = cfg.graderCommit ?? process.env.POPPY_GRADER_COMMIT ?? "unknown";
  // Injectable so a test can prove the lease is live AT its expiry second and dead one
  // second later. A zero-second lease would prove neither.
  const now = cfg.now ?? realNow;
  const canaryRules = cfg.canaryRules ?? CANARY_RULES;
  // When this deployment fetches the agent's documents, delegation.signature must PASS like
  // any other rule; when it does not, it must abstain for the reason named above.
  const fetches = (cfg.companies ?? []).some(c => c.verifyDelegations);
  const canaryAbstains = cfg.canaryAbstains ?? (fetches ? {} : CANARY_ABSTAINS);
  const canaryAlsoPasses = fetches ? Object.keys(CANARY_ABSTAINS) : [];
  const canaryModule = cfg.canaryModule ?? "./reference/jose.ts";
  // Where the public leg is sent. Production uses each Company's configured origin; a test
  // overrides it to put a hostname in front of the wrong listener on purpose.
  let canaryPublicBase = null;

  // Frozen reports on disk, when a deployment asks for it.
  //
  // They are in memory otherwise, so a restart answered every builder's link with exactly what
  // a typo answers. /grader/health lets them tell those apart, which is the least that could be
  // done; this is the rest. The file is named by the HASH of the token, so a directory listing
  // hands nobody a report, and the token is not inside the file either.
  const reportsDir = cfg.reportsDir ?? null;
  const reportPath = (runId) => join(reportsDir, `${runId}.json`);

  const runs = new Map();                 // sha256(token) -> run. The raw token is never stored.
  let active = null;                      // the run holding the lease, at most one
  let granting = false;                   // a second POST while the canary runs gets 409, not a second lease
  let collector = null;                   // set only while the canary drives, see keepFor
  let ports = [];
  const startedAt = now();
  // When requests arrived while no run was open. An agent that fetched poppy.json on startup
  // and cached it did so before the lease, so the rule about documents has nothing to judge
  // and would otherwise abstain with advice the builder had already followed.
  const beforeWindow = cfg.beforeLeaseWindowSeconds ?? 600;
  const arrivals = [[], []];
  const noteArrival = (i) => {
    const a = arrivals[i];
    a.push(now());
    if (a.length > 500) a.splice(0, a.length - 500);
  };

  const keepFor = i => (record) => {
    // The canary's own traffic, matched by the exact JWT it minted so a stray request from a
    // previous builder cannot join the control log and fail it for us.
    if (collector) {
      const raw = record.headers?.["poppy-session"];
      const isDoc = raw === undefined
        && (String(record.path ?? "").startsWith("/.well-known/")
            // the verifier fetching the canary's own published identity, from this process
            || String(record.path ?? "").startsWith("/canary/"));
      if (isDoc || collector.minted.has(raw)) collector.logs[i].push(record);
      else noteArrival(i);               // a stray during the canary belongs to no run either
      return false;
    }
    const run = liveRun();
    // Nothing is retained that does not belong to a live run: a request before any lease, or
    // after a freeze, is examined by no rule and said to be examined by no rule.
    //
    // There is deliberately no seq comparison here. A mark is taken when the lease is
    // granted, so a record arriving during the run always has a higher seq and the
    // comparison could never be false: it was a guard no mutation could kill, which is
    // either dead code or an untested check. Attribution happens in sliceOf, where the mark
    // decides which run a retained record belongs to and a test can break it.
    if (!run) { noteArrival(i); return false; }
    if (run.kept[i] >= maxPerCompany) { run.beyondLimit[i]++; return false; }
    run.kept[i]++;
    return true;
  };

  const graders = companies.map((c, i) => createGrader({
    ...c, controlPrefix: CONTROL_PREFIX, keep: keepFor(i),
    // A fetch of a stranger's URL happens only for traffic that belongs to a run, or for the
    // gate's own control. Outside that, nothing this process does reaches outward.
    verifyWhen: () => !!collector || !!liveRun(),
    ...(i === 0 ? { control: (req, res, target) => control(req, res, target) } : {}),
  }));

  function liveRun() {
    if (!active) return null;
    if (now() <= active.expires) return active;
    freeze(active);                       // a builder who closed the tab does not hold the grader
    return null;
  }

  function sliceOf(run) {
    return graders.map((g, i) => ({
      ctx: ctxOf(g.config.discovery),
      log: g.records.filter(r => r.seq > run.marks[i]),
    }));
  }

  function reportOf(run) {
    if (run.stored) return run.stored;
    return buildReport({
      token: run.token, started: run.started, ended: run.ended, frozen: run.frozen,
      graderCommit, warnings: graders.flatMap(g => g.warnings),
      beyondLimit: run.beyondLimit.reduce((a, b) => a + b, 0),
      beforeLease: run.beforeLease, beforeLeaseWindowSeconds: beforeWindow,
      companies: sliceOf(run),
    });
  }

  function freeze(run) {
    if (run.frozen) return;
    run.ended = now(); run.frozen = true;
    const json = reportOf(run);
    run.stored = json;
    run.html = renderHtml(json);
    run.storedAt = now();
    if (reportsDir) {
      try {
        mkdirSync(reportsDir, { recursive: true });
        writeFileSync(reportPath(run.id), JSON.stringify({ storedAt: run.storedAt, json, html: run.html }));
      } catch (err) {
        // A report that could not be written is not a reason to lose the one in memory, and the
        // builder still has their link until this process stops.
        warnOnce(`could not write the frozen report: ${err.message}`);
      }
    }
    if (active === run) active = null;
    // Drop the records of EARLIER runs and keep this run's own.
    //
    // Clearing everything here would have made attribution correct for a second reason, and
    // the seq mark below would then have been a guard no test could kill. Keeping this run's
    // records means the mark is what decides which run a request belongs to, which is a
    // thing a test can break. Memory stays bounded: a request outside a live run is never
    // retained, so at most two runs' records exist at once.
    for (let i = 0; i < graders.length; i++) {
      const keepers = graders[i].records.filter(r => r.seq > run.marks[i]);
      graders[i].records.length = 0;
      graders[i].records.push(...keepers);
    }
  }

  const warned = new Set();
  const warnOnce = (msg) => { if (!warned.has(msg)) { warned.add(msg); console.error(msg); } };

  function sweep() {
    const cutoff = now() - retentionSeconds;
    for (const [id, run] of runs) if (run.frozen && run.storedAt <= cutoff) runs.delete(id);
    if (!reportsDir) return;
    try {
      for (const name of readdirSync(reportsDir)) {
        if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
        try {
          const saved = JSON.parse(readFileSync(join(reportsDir, name), "utf8"));
          if ((saved.storedAt ?? 0) <= cutoff) rmSync(join(reportsDir, name), { force: true });
        } catch { rmSync(join(reportsDir, name), { force: true }); }   // unreadable is expired
      }
    } catch { /* the directory may not exist yet */ }
  }

  // A frozen report this process did not build, from a process that did.
  function fromDisk(runId) {
    if (!reportsDir) return null;
    try {
      const saved = JSON.parse(readFileSync(reportPath(runId), "utf8"));
      if (!saved?.json || (saved.storedAt ?? 0) <= now() - retentionSeconds) return null;
      return { id: runId, frozen: true, storedAt: saved.storedAt, stored: saved.json, html: saved.html };
    } catch { return null; }
  }

  // One 404 for a wrong token and for an unknown path, same bytes and same headers, so the
  // existence of a report cannot be probed. Runs are keyed by the hash of the token and the
  // raw token is never stored or compared, which is what makes the lookup not a comparison
  // of secrets; no claim is made here about the timing of a Map lookup.
  const PRIVATE_HEADERS = {
    "cache-control": "no-store", "referrer-policy": "no-referrer",
    "x-robots-tag": "noindex, nofollow", "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
  };
  function notFound(res) {
    const body = JSON.stringify({ error: "not_found" });
    res.writeHead(404, { "content-type": "application/json", ...PRIVATE_HEADERS });
    res.end(body);
  }
  const json = (res, status, obj, extra = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...PRIVATE_HEADERS, ...extra });
    res.end(JSON.stringify(obj));
  };

  async function startRun(res) {
    if (granting || liveRun()) {
      const run = liveRun();
      // Never the holder's token, and never anything derived from it.
      return json(res, 409, { error: "busy",
        retry_after_seconds: run ? Math.max(1, run.expires - now()) : 5,
        detail: "One agent is graded at a time, so a request with no Session JWT is never charged to the wrong run." },
        { "retry-after": String(run ? Math.max(1, run.expires - now()) : 5) });
    }
    granting = true;
    try {
      const bad = await runCanary();
      if (bad) return json(res, 503, { error: "grader_control_failed", ...bad,
        detail: "Before grading anyone this grader drives itself with the protocol authors' own signing code. That control did not pass, so this deployment is misconfigured and nothing here would be a statement about your agent." });

      const token = token22();
      const since = now() - beforeWindow;
      const run = { token, id: sha(token), started: now(), ended: null, frozen: false,
                    expires: now() + leaseSeconds, marks: graders.map(g => g.seq),
                    kept: [0, 0], beyondLimit: [0, 0], stored: null, html: null,
                    beforeLease: arrivals.reduce((n, a) => n + a.filter(t => t >= since).length, 0) };
      runs.set(run.id, run);
      active = run;
      // The budget is per run, which is what its own message claims. Nothing called this, so
      // it was a per-process budget that outsiders could spend and that never reset.
      for (const g of graders) g.issuerKeys?.newRun?.();
      sweep();
      const origins = graders.map(g => g.config.origin);
      return json(res, 201, {
        token, companies: origins, report: `${origins[0]}${CONTROL_PREFIX}report/${token}`,
        expires_in: leaseSeconds, grader_commit: graderCommit,
        warnings: graders.flatMap(g => g.warnings),
      });
    } finally { granting = false; }
  }

  // Returns null when the control passed, or the first rule that did not.
  async function runCanary() {
    // The canary's identity lives at a STABLE url and is republished with a new key on every
    // gate run, so anything remembered about it from a previous run is wrong by construction:
    // a cached key set verifies this run's delegation against last run's key, and a remembered
    // failure (from a 404 when the identity was not mounted) denies every later lease. Both
    // were measured. So the gate forgets its own issuer before it drives.
    for (const g of graders) g.issuerKeys?.forget?.(g.canaryClientId);

    const c = collector = { minted: new Set(), logs: [[], []], intended: [0, 0],
                            publicLeg: [], sendError: [], shortfall: [], legs: [] };
    try {
      await driveCanary(graders, ports, c, { publicBase: canaryPublicBase, module: canaryModule,
                                            verifies: fetches, send: cfg.canaryFetch });
    } catch (err) {
      const why = String(err?.message ?? err);
      return { rule: "canary.drive", verdict: "ERROR",
               why: /Unknown file extension "\.ts"/.test(why)
                 ? `${why}. The canary runs the protocol authors' own TypeScript, so start the grader with --experimental-strip-types, or on Node 22.18 or later where stripping is the default.`
                 : why };
    } finally {
      collector = null;
      // The identity exists only while the gate runs, so a builder cannot fetch it afterwards
      // and nothing about it outlives the control.
      for (const g of graders) g.setCanaryIdentity?.(null);
    }
    const logs = c.logs;

    // 1. Did our own traffic reach us, at the right Company, with the Host we sent it to?
    for (let i = 0; i < graders.length; i++) {
      const where = graders[i].config.origin;
      if (c.shortfall[i])
        return { rule: "canary.reach", verdict: "FAIL", why: `at ${where}, ${c.shortfall[i]}` };
      const got = logs[i].filter(r => r.isResource).length;
      if (got < c.intended[i])
        return { rule: "canary.reach", verdict: "FAIL",
                 why: `at ${where} the canary sent ${c.intended[i]} requests to listed destinations and ${got} were classified as destinations, so this grader would examine less of a real agent than it reports` };
      const leg = c.publicLeg[i];
      if (!leg) continue;
      const arrived = logs[i].find(r => r.headers?.["poppy-session"] === leg.jwt);
      if (!arrived)
        return { rule: "canary.public-route", verdict: "FAIL",
                 why: `a request sent through the public hostname of ${where} did not arrive at that Company${c.sendError[i] ? ` (${c.sendError[i]})` : ""}, so the hostname a builder is given does not reach this process` };
      if (arrived.headers?.host !== leg.host)
        return { rule: "canary.public-route", verdict: "FAIL",
                 why: `a request sent to Host ${leg.host} arrived with Host ${arrived.headers?.host}, so the public URL this grader compares htu against is not the URL a builder reaches` };
    }

    // 2. Does our own traffic pass every rule the canary is built to exercise?
    const { grade, gradePair } = await import("./checks.mjs");
    const ctxA = ctxOf(graders[0].config.discovery), ctxB = ctxOf(graders[1].config.discovery);
    const verdicts = new Map();
    for (const v of grade(logs[0], ctxA)) verdicts.set(v.id, v);
    for (const v of grade(logs[1], ctxB)) {
      const a = verdicts.get(v.id);
      // Both Companies must pass. The worse of the two is what the gate reads.
      if (v.verdict !== "PASS") verdicts.set(v.id, v); else if (a?.verdict !== "PASS") verdicts.set(v.id, a);
    }
    for (const v of gradePair(logs[0], logs[1], ctxA, ctxB)) verdicts.set(v.id, v);
    for (const id of [...canaryRules, ...canaryAlsoPasses]) {
      const v = verdicts.get(id);
      if (!v || v.verdict !== "PASS")
        return { rule: id, verdict: v?.verdict ?? "MISSING", why: v?.why ?? "the canary did not reach this rule" };
    }
    // 2b. And a rule this deployment cannot decide must ABSTAIN for the stated reason, not
    //     pass. A rule that is neither required to pass nor required to abstain is one that
    //     could quietly stop reaching anything, which is this project's recorded quiet failure.
    for (const [id, cause] of Object.entries(canaryAbstains)) {
      const v = verdicts.get(id);
      if (!v) return { rule: id, verdict: "MISSING", why: "the canary did not reach this rule at all" };
      if (v.verdict === "PASS")
        return { rule: id, verdict: "PASS",
                 why: `this deployment does not fetch the agent's documents, so a pass here would be a statement about nothing: ${v.why}` };
      if (v.verdict !== "INCONCLUSIVE" || v.cause !== cause)
        return { rule: id, verdict: v.verdict,
                 why: `expected an abstention with cause ${cause} from a deployment that does not fetch the agent's documents: ${v.why}` };
    }

    // 3. Last, and deliberately: did this Company REFUSE its own conforming traffic for a
    //    reason no rule above covers? A specific diagnosis beats a status code, which is why
    //    the routing, reach and rule checks come first: putting this guard first replaced
    //    three useful sentences with "we answered 400". What is left for it is the residue it
    //    is actually good at, an answer no rule explains: a 405 from a method mismatch, a 404
    //    from a destination we do not serve, a 500 from our own code.
    const refused = firstRefusedLeg(c.legs);
    if (refused)
      return { rule: "canary.refused", verdict: "FAIL",
               why: `every rule passed, yet this Company answered ${refused.method} ${refused.path} at ${refused.origin} with ${refused.status}`
                    + `${refused.error ? ` and ${refused.error}` : ""}, on a request built by the protocol authors' own signing code, so this deployment would stop a conforming agent for a reason no rule here explains` };

    return null;
  }

  function control(req, res, target) {
    const path = (() => { try { return new URL(target, "http://x").pathname.replace(/\/+$/, "") || "/"; }
                          catch { return null; } })();
    if (path === null || (path !== "/grader" && !path.startsWith(CONTROL_PREFIX))) return false;
    sweep();
    const m = String(req.method ?? "GET").toUpperCase();

    if (path === CONTROL_PREFIX + "health" && (m === "GET" || m === "HEAD")) {
      // Reports live in memory, so a restart answers every token with the bytes of an
      // unknown path. This is how a builder tells those apart. It names no token.
      // `clock` is here because session.iat-window compares an agent's iat with this
      // process's own clock, and the canary signs with that same clock, so a drifted
      // deployment fails every conforming agent while its own control passes. Nothing inside
      // can detect that; an operator comparing this number with any other can.
      json(res, 200, { ok: true, started_at: startedAt, clock: now(), grader_commit: graderCommit,
                       protocol_version: "1.0", lease_held: !!liveRun(),
                       companies: graders.map(g => g.config.origin) });
      return true;
    }

    if (path === CONTROL_PREFIX + "runs" && m === "POST") {
      // Never fire and forget. An exception inside the gate used to leave the request with
      // no response at all, so a builder's POST hung until their client gave up and the
      // grader looked slow rather than broken. Found by a mutation that made the gate throw.
      startRun(res).catch(err => {
        if (res.headersSent) { res.end(); return; }
        json(res, 500, { error: "grader_error", detail: String(err?.message ?? err) });
      });
      return true;
    }

    const end = path.match(/^\/grader\/runs\/([A-Za-z0-9_-]{22})\/end$/);
    if (end && m === "POST") {
      const run = runs.get(sha(end[1]));
      if (!run) { notFound(res); return true; }
      freeze(run);
      json(res, 200, { frozen: true, report: `${graders[0].config.origin}${CONTROL_PREFIX}report/${end[1]}` });
      return true;
    }

    const rep = path.match(/^\/grader\/report\/([A-Za-z0-9_-]{22})(\.json)?$/);
    if (rep && (m === "GET" || m === "HEAD")) {
      const run = runs.get(sha(rep[1])) ?? fromDisk(sha(rep[1]));
      if (!run) { notFound(res); return true; }
      const body = run.frozen ? run.stored : reportOf(run);
      if (rep[2]) { json(res, 200, body); return true; }
      const html = run.frozen ? run.html : renderHtml(body);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", ...PRIVATE_HEADERS });
      res.end(html);
      return true;
    }
    notFound(res);
    return true;
  }

  return {
    graders,
    get origins() { return graders.map(g => g.config.origin); },
    get activeToken() { return active ? active.token : null },
    setOrigins(list) { graders.forEach((g, i) => g.setOrigin(list[i])); },
    setCanaryPublicBase(list) { canaryPublicBase = list; },
    async listen(list = [0, 0]) {
      ports = await Promise.all(graders.map((g, i) => g.listen(list[i] ?? 0)));
      return ports;
    },
    async close() { await Promise.all(graders.map(g => g.close())); },
  };
}
