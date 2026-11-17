// The Company that records what an agent put on the wire.
//
// It serves just enough to be a destination, and its job is to miss nothing. A request that
// is not recorded is a request no rule examines, which reads as conformance, so the two
// failures this file guards against are stamping the wrong time and never making a record
// at all.
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { recordOf, classify, pathOf } from "./record.mjs";

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

  const warnings = [];
  for (const [where, url] of listed) {
    let x;
    try { x = new URL(url); } catch { throw new Error(`${where} is not a URL: ${url}`); }
    // A query or fragment makes the 8.2 route syntax meaningless and is silently dropped by
    // the classifier, so it is refused rather than tolerated.
    if (x.search || x.hash) throw new Error(`${where} must have no query or fragment: ${url}`);
    if (x.origin !== parsed.origin)
      warnings.push(`${where} is ${url}, on ${x.origin}, which this grader does not serve: requests there are examined by no rule`);
  }
  return warnings;
}

export function createGrader(cfg) {
  let config = { ...cfg };
  const warnings = validateConfig(config);
  const records = [];
  const maxBody = config.maxBodyBytes ?? DEFAULT_MAX_BODY;

  const server = createServer((req, res) => {
    // Stamped here, synchronously, before any await and before a byte of body is read. A
    // long poll or a slow upload would otherwise show up as clock skew in the agent's iat.
    const at = Math.floor(Date.now() / 1000);

    const record = recordOf(req, config, { at, body: null, bodyComplete: true });
    // Push now, so an abort cannot lose it. The body is filled in below, in place.
    records.push(record);

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
    records.push({
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
      if (record.mustNotCarry && record.path === "/.well-known/poppy.json") {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(config.discovery));
        return;
      }
      res.writeHead(record.isResource ? 200 : 404, { "content-type": "application/json" });
      res.end(JSON.stringify(record.isResource ? { ok: true } : { error: "not_found" }));
    };
    if (delay > 0) setTimeout(send, delay); else send();
  }

  return {
    server, records, warnings,
    // The configured origin must be the one actually served, or every htu comparison is
    // wrong for our deployment and not for the agent. Used by tests on an ephemeral port
    // and by the rig once the public hostname is known.
    setOrigin(origin) { config = { ...config, origin }; validateConfig(config); },
    get config() { return config; },
    listen(port = 0) {
      return new Promise(r => server.listen(port, "127.0.0.1", () => r(server.address().port)));
    },
    close() { return new Promise(r => server.close(() => r())); },
  };
}
