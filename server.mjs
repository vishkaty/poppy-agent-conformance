// The Company that records what an agent put on the wire.
//
// It serves just enough to be a destination, and its job is to miss nothing. A request that
// is not recorded is a request no rule examines, which reads as conformance, so the two
// failures this file guards against are stamping the wrong time and never making a record
// at all.
import { createServer } from "node:http";
import { decodeJwt } from "./checks.mjs";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { recordOf, classify, pathOf, allowedMethodsFor, conversationRouteOf } from "./record.mjs";
import { createConversations } from "./conversations.mjs";
import { resourceMetadataFor, authServerMetadataFor, authServerMetadataPath, discoveryFor,
         openapiFor, operationsToTemplates, DEFAULT_OPERATIONS, identifierOf,
         authServerEndpointsFor } from "./discovery.mjs";
import { enforce, tokenChallenge } from "./enforce.mjs";

const DEFAULT_MAX_BODY = 256 * 1024;
const DEFAULT_TEST_AGENT_PREFIX = "/test-agent";

// The only two files a hosted test agent identity exposes.
//
// An allowlist of exact names, never a directory served by path, because `keygen` writes the
// signing key into the same directory and a path-based map would publish it. The prefix is
// also why this is not a general static file server: it exists so the authors' own validator,
// which is the independent control on this Company, can run past discovery.
const TEST_AGENT_FILES = ["agent.json", "jwks.json"];

// Refuse a configuration that would make every verdict a statement about our deployment
// rather than about the agent, and report destinations this grader cannot see.
//
// Returns warnings; throws on anything that makes the run meaningless.
export function validateConfig(cfg) {
  const origin = String(cfg.origin ?? "");
  let parsed;
  try { parsed = new URL(origin); } catch { throw new Error(`origin is not a URL: ${origin}`); }
  if (parsed.origin !== origin)
    throw new Error(`origin must be a bare origin with no path, trailing slash or uppercase host: ${origin} should be ${parsed.origin}`);

  const d = cfg.discovery ?? {};
  const listed = [];
  for (const p of d.agent?.protocols ?? []) if (p?.endpoint) listed.push(["agent.protocols[].endpoint", p.endpoint]);
  for (const a of d.apis ?? []) if (a?.url) listed.push(["apis[].url", a.url]);
  if (d.web?.browser_session_endpoint) listed.push(["web.browser_session_endpoint", d.web.browser_session_endpoint]);
  if (d.tasks?.endpoint) listed.push(["tasks.endpoint", d.tasks.endpoint]);
  for (const e of cfg.extensionEndpoints ?? []) listed.push(["extension endpoint", e]);
  // The same lists record.mjs reads, so nothing the classifier knows about is unchecked here.
  // An earlier version walked a shorter list and a feedback endpoint, an OAuth endpoint or a
  // version document could sit under the control-plane prefix unnoticed.
  if (cfg.feedbackEndpoint) listed.push(["feedbackEndpoint", cfg.feedbackEndpoint]);
  for (const e of cfg.authServerEndpoints ?? []) listed.push(["authServerEndpoints[]", e]);
  for (const [v, url] of Object.entries(d.supported_versions ?? {}))
    if (url) listed.push([`supported_versions[${v}]`, url]);

  // A destination under the caller's control-plane prefix would be answered by the control
  // plane and examined by no rule, which reads as conformance. Refused, not shadowed.
  const prefix = cfg.controlPrefix;
  const idPrefix = cfg.testAgentIdentity ? (cfg.testAgentPrefix ?? DEFAULT_TEST_AGENT_PREFIX) : null;
  if (idPrefix && prefix && (idPrefix + "/").startsWith(prefix))
    throw new Error(`testAgentPrefix is ${idPrefix}, under the control-plane prefix ${prefix}: the control plane would answer it`);
  const warnings = [];
  for (const [where, url] of listed) {
    let x;
    try { x = new URL(url); } catch { throw new Error(`${where} is not a URL: ${url}`); }
    // A query or fragment makes the 8.2 route syntax meaningless and is silently dropped by
    // the classifier, so it is refused rather than tolerated.
    if (x.search || x.hash) throw new Error(`${where} must have no query or fragment: ${url}`);
    if (x.origin !== parsed.origin)
      warnings.push(`${where} is ${url}, on ${x.origin}, which this grader does not serve: requests there are examined by no rule`);
    if (prefix && x.origin === parsed.origin && x.pathname.startsWith(prefix))
      throw new Error(`${where} is ${url}, under the control-plane prefix ${prefix}: the control plane would answer it and no rule would examine it`);
    if (idPrefix && x.origin === parsed.origin && x.pathname.startsWith(idPrefix + "/"))
      throw new Error(`${where} is ${url}, under the hosted test agent prefix ${idPrefix}: the identity files would answer it`);
  }
  return warnings;
}

export function createGrader(cfg) {
  // The discovery document is DERIVED from the current origin, never stored as a snapshot.
  // A snapshot taken before the public origin was known disagreed with the metadata built
  // from it, and 3.2 makes an agent refuse a Company whose issuer metadata does not match
  // its poppy.json character for character. Pass a function to override, or an object to
  // pin one deliberately.
  // Always from the ORIGINAL cfg. Reading the derived value back meant the second call
  // returned its own stale output, so setOrigin left poppy.json naming an issuer the
  // metadata did not, which is precisely the 3.2 mismatch that makes an agent refuse a
  // Company. The test asserting the three documents agree is what caught it.
  const derive = (origin) => (typeof cfg.discovery === "function" ? cfg.discovery(origin)
                             : cfg.discovery ?? discoveryFor(origin));
  // One declaration of what this Company offers. `operations` builds BOTH the OpenAPI
  // document an agent reads and the templates the classifier matches against, so the two
  // cannot drift apart. `apiOperations` is still accepted for a test that wants to set the
  // classifier's view on its own, which is how a disagreement between them is tested.
  const operations = cfg.operations ?? (cfg.apiOperations ? null : DEFAULT_OPERATIONS);
  const withApi = (origin, base) => ({
    ...base,
    openapi: operations ? openapiFor(origin, operations) : null,
    apiOperations: cfg.apiOperations ?? (operations ? operationsToTemplates(operations) : []),
    // The OAuth endpoints this Company serves, from the same builder the metadata comes from,
    // so the classifier cannot disagree with the document about what is an OAuth endpoint.
    authServerEndpoints: cfg.authServerEndpoints
      ?? (base.discovery?.auth?.issuer ? authServerEndpointsFor(origin) : []),
  });
  let config = withApi(cfg.origin, { ...cfg, discovery: derive(cfg.origin) });
  const warnings = validateConfig(config);
  const records = [];
  const maxBody = config.maxBodyBytes ?? DEFAULT_MAX_BODY;

  // Every record gets a sequence number, assigned whether or not it is retained.
  //
  // A caller identifies a span of traffic by seq rather than by an array index, so pruning
  // old records cannot silently shift what a span means. `config.keep` lets the caller
  // decline to retain one, which is how a bounded run is possible; the count of declined
  // records is kept HERE as well, because the whole point of this file is that a request
  // nothing recorded is a request no rule examines, and that must never be silent.
  // Section 8 state, per Company. A conversation belongs to a client_id and a User ID and can
  // outlast the Session that started it (8.2), so it is not per run; it is bounded instead.
  const conversations = createConversations({ max: cfg.maxConversations ?? 200 });

  let seq = 0, dropped = 0;
  const push = (record) => {
    record.seq = ++seq;
    if (config.keep && !config.keep(record)) { dropped++; return record; }
    records.push(record);
    return record;
  };

  const server = createServer((req, res) => {
    // Stamped here, synchronously, before any await and before a byte of body is read. A
    // long poll or a slow upload would otherwise show up as clock skew in the agent's iat.
    const at = Math.floor(Date.now() / 1000);

    // A target containing dot segments or a backslash is refused rather than reconciled.
    // Node hands the raw target to the router while new URL() resolves dot segments, so
    // /poppy/conversations/../token would be served as one path and classified as another,
    // and that disagreement is how a request reaches a destination while being judged as
    // something else.
    const rawTarget = String(req.url ?? "/");
    const unsafe = /(^|\/)\.\.?(\/|$)/.test(rawTarget) || rawTarget.includes("\\");

    // The caller's own control plane, if it shares this listener. Checked AFTER the dot
    // segment refusal above, so a target like /grader/../v1/orders cannot be answered by
    // one of the two and judged as the other. A handled request is never recorded, which is
    // deliberate and is the single exception to the guarantee in the header comment: it is
    // our traffic, not the agent's. A configured destination under the same prefix is
    // refused by validateConfig rather than shadowed here.
    if (config.control && config.control(req, res, rawTarget)) return;

    const record = recordOf(req, config, { at, body: null, bodyComplete: true });
    record.rawTarget = rawTarget;
    if (unsafe) {
      record.refused = true;
      record.isResource = false; record.isPage = false; record.mustNotCarry = false;
      record.classifiedAs = "refused: the target has dot segments or a backslash, so routing and classification could disagree";
      push(record);
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_request" }));
      return;
    }
    // Push now, so an abort cannot lose it. The body is filled in below, in place.
    push(record);

    const hasBody = req.headers["content-length"] !== undefined || req.headers["transfer-encoding"] !== undefined;
    if (!hasBody) { respond(req, res, record); return; }

    const chunks = []; let bytes = 0; const hash = createHash("sha256");
    record.body = ""; record.bodyComplete = false;
    req.on("data", c => {
      hash.update(c); bytes += c.length;
      if (bytes <= maxBody) chunks.push(c);
      else record.bodyTruncated = true;
    });
    req.on("end", () => {
      record.body = Buffer.concat(chunks).toString("utf8");
      record.bodySha256 = hash.digest("hex");
      record.bodyBytes = bytes;
      record.bodyComplete = true;
      respond(req, res, record);
    });
    // aborted, reset, or the socket closed before `end`: the record stays incomplete and
    // says so, rather than disappearing.
    req.on("aborted", () => { record.bodySha256 = hash.digest("hex"); record.bodyBytes = bytes; });
    req.on("error", () => { record.bodyComplete = false; });
  });

  // Requests Node refuses before the handler runs. Without this listener they are answered
  // by Node and never seen, so the grader could not honestly say it recorded everything.
  // Attaching it means we own the response.
  server.on("clientError", (err, socket) => {
    push({
      rejected: true, code: err.code ?? "UNKNOWN", at: Math.floor(Date.now() / 1000),
      bytes: err.rawPacket?.length ?? null,
      classifiedAs: "rejected before the request could be parsed, so nothing about it is known",
      isResource: false, isPage: false, mustNotCarry: false,
      sessionHeaderCount: 0, sessionHeaderDecodable: false, sessionHeaderDuplicated: false,
    });
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    else socket.destroy();
  });

  // What this Company IS, as the checks read it: its own published document decides, never a
  // Host header, for the reason record.mjs gives.
  function contextOf(cfg) {
    const d = cfg.discovery ?? {};
    return { identifier: identifierOf(d), domain: d.organization?.domain,
             protocolVersion: d.protocol_version };
  }

  // Every response goes through here, so a record always says what the agent was told. The
  // report shows it, and a test asserts the record's response matches what enforcement
  // decided for that same record.
  function answer(res, record, status, body, headers = {}) {
    record.response = { status, error: body?.error ?? null };
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  }

  function respond(req, res, record) {
    // Just enough to be a destination. The grader's purpose is what the agent sent, not
    // what we return, so the bodies are minimal and documented as fixtures.
    const delay = config.delayMs ?? 0;
    const send = () => {
      if (record.rejected) return;
      if (record.misdirected) { res.writeHead(421).end(); return; }      // RFC 9110 15.5.20
      // The three documents a conforming agent fetches before it will use the Company at
      // all. 3.2 makes the agent refuse poppy.json unless the issuer metadata matches and
      // protected_resources names the domain, so a grader that 404s these records nothing
      // and reports every rule as not reached, which reads as the builder's fault.
      const docs = {
        "/.well-known/poppy.json": () => config.discovery,
        // The document poppy.json advertises. Served from the same list the classifier uses,
        // so an agent that follows it can only reach destinations rules examine.
        ...(config.openapi ? { [pathOf(config.discovery.apis?.find(a => a.type === "openapi")?.url ?? "") ?? "/poppy/openapi.json"]: () => config.openapi } : {}),
        "/.well-known/oauth-protected-resource": () => resourceMetadataFor(config.origin),
        [authServerMetadataPath(config.origin)]: () => authServerMetadataFor(config.origin),
      };
      // The two files of a hosted test agent identity, by exact name.
      const idPrefix = config.testAgentIdentity
        ? (config.testAgentPrefix ?? DEFAULT_TEST_AGENT_PREFIX) : null;
      if (idPrefix && record.path?.startsWith(idPrefix + "/")) {
        const name = record.path.slice(idPrefix.length + 1);
        if (TEST_AGENT_FILES.includes(name)) {
          try {
            const body = readFileSync(join(config.testAgentIdentity, name));
            res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
            res.end(body);
            return;
          } catch { /* fall through to the 404 below */ }
        }
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not_found" }));
        return;
      }

      // 3.2: a Company with auth.disabled that has never issued a refresh token "answers every
      // refresh with `invalid_grant` (RFC 6749 §5.2) and every revocation with success
      // (RFC 7009 §2.2). It MAY do so without verifying the client assertion (4.1)." Both were
      // advertised in the OAuth metadata and answered 404 before, which is the same dead end
      // as advertising an OpenAPI document nothing serves.
      const oauth = config.discovery?.auth?.issuer ? authServerEndpointsFor(config.origin) : [];
      const [tokenEndpoint, revocationEndpoint] = oauth.map(u => pathOf(u));
      if (record.path === tokenEndpoint || record.path === revocationEndpoint) {
        if (record.method !== "POST") {
          answer(res, record, 405, { error: "invalid_request", detail: "this endpoint takes POST" },
                 { allow: "POST" });
          return;
        }
        if (record.path === revocationEndpoint) {
          // RFC 7009 §2.2: a successful response is 200 with an empty body.
          record.response = { status: 200, error: null };
          res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
          res.end("");
          return;
        }
        // 3.2 says a Company in this state "answers every refresh with `invalid_grant`". A
        // REFRESH. Answering invalid_grant to everything was wrong for the other cases, and
        // RFC 6749 §5.2 names them: `unsupported_grant_type` is "The authorization grant type
        // is not supported by the authorization server", and `invalid_request` covers a
        // missing required parameter. The issuer's metadata lists only refresh_token, so any
        // other grant is unsupported by this Company's own declaration.
        const form = new URLSearchParams(record.body ?? "");
        const grant = form.get("grant_type");
        if (!grant)
          answer(res, record, 400, { error: "invalid_request", error_description: "grant_type is required (RFC 6749 §4.1.3)" }, { "cache-control": "no-store" });
        else if (grant !== "refresh_token")
          answer(res, record, 400, { error: "unsupported_grant_type", error_description: "this issuer lists refresh_token only (3.2, RFC 6749 §5.2)" }, { "cache-control": "no-store" });
        else if (!form.get("refresh_token"))
          answer(res, record, 400, { error: "invalid_request", error_description: "refresh_token is required (RFC 6749 §6)" }, { "cache-control": "no-store" });
        else
          answer(res, record, 400, { error: "invalid_grant", error_description: "this Company has issued no refresh token, and declares auth.disabled (3.2)" }, { "cache-control": "no-store" });
        return;
      }

      if (docs[record.path]) {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(docs[record.path]()));
        return;
      }
      if (!record.isResource) {
        // A method mismatch on a real destination, which 404 would misreport as a wrong path.
        const allow = allowedMethodsFor(record.url, config);
        if (allow.length) {
          answer(res, record, 405, { error: "invalid_request",
            detail: `this endpoint takes ${allow.join(" or ")}` }, { allow: allow.join(", ") });
          return;
        }
        answer(res, record, 404, { error: "not_found" });
        return;
      }

      // A destination. Decided HERE, after the body has fully arrived, from the same check
      // implementations the report uses, so the status and the verdict cannot disagree.
      //
      // Deciding earlier was possible, since every enforced rule reads headers only, but
      // answering with the body unread resets the client mid upload, leaves bodyComplete
      // false on the record, and makes the retry look like the reset upload that
      // session.jti-unique deliberately excuses.
      const ctx = contextOf(config);
      const refusal = config.enforce === false ? null : enforce(record, ctx);
      if (refusal) {
        record.rejection = { rule: refusal.rule, error: refusal.body.error };
        answer(res, record, refusal.status, refusal.body, refusal.headers);
        return;
      }

      // The Session stands. An access token can only now be the problem, and it is an OAuth
      // error rather than a Session one: 5.3's steps are what a Company "MUST complete before
      // relying on Session claims", so a request failing both is told about its Session first.
      if (config.enforce !== false && record.headers?.authorization) {
        const c = tokenChallenge(config.origin);
        record.rejection = { rule: "token.not-issued", error: c.body.error };
        answer(res, record, c.status, c.body, c.headers);
        return;
      }

      // A conversation route of 8.2. The route is parsed beside the classifier, so the thing
      // that decides a request is a destination and the thing that decides which route it is
      // cannot disagree.
      const route = conversationRouteOf(record.url, record.method, config);
      if (route) {
        let body;
        if (record.body !== null && record.body !== "") {
          try { body = JSON.parse(record.body); }
          catch { answer(res, record, 400, { error: "invalid_request",
                    error_description: "every POST carries a JSON body (8.2)" }); return; }
        } else if (route.route !== "events") {
          body = undefined;                      // handled as a missing request id below
        }
        const outcome = conversations.handle(
          { route: route.route, convId: route.id },
          { jwt: decodeJwt(record.headers?.["poppy-session"]), body,
            query: new URL(record.url).searchParams, path: record.path });
        if (outcome) { answer(res, record, outcome.status, outcome.body); return; }
      }

      answer(res, record, 200, { ok: true });
    };
    if (delay > 0) setTimeout(send, delay); else send();
  }

  return {
    server, records, warnings,
    get seq() { return seq; },
    get dropped() { return dropped; },
    // The configured origin must be the one actually served, or every htu comparison is
    // wrong for our deployment and not for the agent. Used by tests on an ephemeral port
    // and by the rig once the public hostname is known.
    setOrigin(origin) {
      // Re-derive, unless an object was pinned on purpose, or the documents go stale.
      config = withApi(origin, { ...config, origin, discovery: derive(origin) });
      validateConfig(config);
    },
    get config() { return config; },
    listen(port = 0) {
      return new Promise(r => server.listen(port, "127.0.0.1", () => r(server.address().port)));
    },
    close() { return new Promise(r => server.close(() => r())); },
  };
}
