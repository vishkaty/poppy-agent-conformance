// The Company that records what an agent put on the wire.
//
// It serves just enough to be a destination, and its job is to miss nothing. A request that
// is not recorded is a request no rule examines, which reads as conformance, so the two
// failures this file guards against are stamping the wrong time and never making a record
// at all.
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { recordOf, classify, pathOf } from "./record.mjs";
import { resourceMetadataFor, authServerMetadataFor, authServerMetadataPath, discoveryFor,
         openapiFor, operationsToTemplates, DEFAULT_OPERATIONS } from "./discovery.mjs";

const DEFAULT_MAX_BODY = 256 * 1024;

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
      if (docs[record.path]) {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(docs[record.path]()));
        return;
      }
      res.writeHead(record.isResource ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(record.isResource ? { ok: true } : { error: "not_found" }));
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
