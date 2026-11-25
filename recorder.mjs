// The recorder: a reverse proxy a builder runs in front of their OWN Company.
//
// Why this exists. Until now the only way to be judged by this grader was to point an agent at
// the hostnames it hosts, which asks a builder to send their traffic to a stranger. The
// recorder removes that: the log is made and judged on the builder's own machine, and nothing
// about their agent reaches anyone. What it does NOT change is who the report convinces. A log
// its owner could have edited is evidence to its owner and to nobody else, which is why a
// recorded report says so about itself.
//
// Three rules shape the code.
//
//  1. THE RECORD MUST BE THE RECORD A COMPANY WOULD MAKE. Every field comes from `recordOf`
//     and `readBody`, the same functions the hosted Company uses, over the same raw request.
//     A second capture path would make every verdict a statement about which path ran, so
//     there is not one: tests/recorder.test.mjs asserts field equality against the Company on
//     identical bytes.
//  2. IT FORWARDS WHAT IT WAS GIVEN. Raw headers, duplicates included, the Host unchanged, and
//     the body streamed rather than buffered. A proxy that tidies the request hides exactly the
//     breaches 5.2 is about, and a Company that never sees the real bytes cannot answer for
//     them either.
//  3. IT REFUSES NOTHING. `rejection` means "this Company refused under rule X" and the
//     recorder is not the Company. Writing an upstream refusal into that field would make a
//     report claim this grader did the refusing.
import { createServer, request as upstreamRequest } from "node:http";
import { appendFileSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { recordOf, readBody, isUnsafeTarget } from "./record.mjs";
import { contextOf } from "./discovery.mjs";
import { buildReport } from "./report.mjs";
import { validateConfig } from "./server.mjs";

// Hop by hop headers belong to one connection and are the proxy's own business (RFC 9110 7.6.1).
// Everything else, including every duplicate, goes through untouched.
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-connection",
                            "transfer-encoding", "te", "trailer", "upgrade"]);
const DEFAULT_MAX_BODY = 256 * 1024;
// Enough for any OAuth style error body; past this the answer is a payload, not an error.
const MAX_ERROR_BODY = 64 * 1024;

// `req.rawHeaders` is a flat [name, value, name, value] list, which is how a duplicate header
// survives: `req.headers` has already joined duplicates with ", " and cannot be un-joined.
function forwardableHeaders(rawHeaders) {
  const out = [];
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (HOP_BY_HOP.has(String(rawHeaders[i]).toLowerCase())) continue;
    out.push(rawHeaders[i], rawHeaders[i + 1]);
  }
  return out;
}

// Is anything the classifier recognises on the origin this recorder fronts? API templates are
// paths and so are on it by construction; everything else is compared by origin, and the
// organization domain counts because a page on it can legitimately carry a Session (5.2).
function somethingIsListedOn(cfg) {
  const origin = (() => { try { return new URL(String(cfg.origin)).origin; } catch { return null; } })();
  if (!origin) return false;
  if ((cfg.apiOperations ?? []).length) return true;
  const d = cfg.discovery ?? {};
  const urls = [
    ...(d.agent?.protocols ?? []).map(p => p?.endpoint),
    ...(d.apis ?? []).map(a => a?.url),
    d.web?.browser_session_endpoint, d.tasks?.endpoint, cfg.feedbackEndpoint,
    ...(cfg.extensionEndpoints ?? []), ...(cfg.authServerEndpoints ?? []),
  ].filter(Boolean);
  for (const u of urls) {
    try { if (new URL(u).origin === origin) return true; } catch { /* validateConfig refuses it */ }
  }
  const host = d.organization?.domain;
  return typeof host === "string" && host !== "" && new URL(origin).host === host;
}

export function createRecorder(cfg) {
  const records = [];
  // The same checks the hosted Company runs on itself: a malformed origin is refused, and a
  // listed destination this process will never see is a warning naming it.
  const warnings = validateConfig(cfg);
  // And the one check only a recorder needs. If nothing in the builder's own document is on the
  // origin this recorder fronts, every request classifies as not a destination, every rule
  // abstains as unreached, and the report says nothing failed. A builder reads that as a pass.
  // It is the same failure the canary's reach leg exists to prevent, so it is refused here too.
  if (!somethingIsListedOn(cfg))
    throw new Error(`nothing in this Company's document is listed on ${cfg.origin}: every request would be `
      + "classified as not a Session destination and every rule would abstain, which reads as conformance. "
      + "Set `origin` to the public origin your agent actually uses for this host, and give the recorder "
      + "the OpenAPI document for the APIs it serves.");
  let seq = 0;
  const emitted = new WeakSet();
  const emit = (record) => {
    if (emitted.has(record)) return;
    emitted.add(record);
    cfg.onRecord?.(record);
  };
  const maxBody = cfg.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const up = new URL(cfg.upstream);

  const server = createServer((req, res) => {
    // Stamped before anything can await, because `at` is when the request arrived and
    // `session.iat-window` compares the agent's own clock against it.
    const at = Math.floor(Date.now() / 1000);
    const record = recordOf(req, cfg, { at });
    record.seq = ++seq;
    record.rawTarget = req.url ?? "/";
    // Forwarded, because the builder's Company decides what to do with it, and claimed by no
    // rule, because the path we would classify is not provably the path they will serve.
    if (isUnsafeTarget(record.rawTarget)) {
      record.unsafeTarget = true;
      record.isResource = false; record.isPage = false; record.mustNotCarry = false;
      record.classifiedAs = "the target has dot segments or a backslash, so classification and your "
        + "Company's routing could disagree: forwarded and examined by no rule";
    }
    records.push(record);

    const hasBody = req.headers["content-length"] !== undefined
      || req.headers["transfer-encoding"] !== undefined;
    // The body is teed: `readBody` fills the record while `pipe` sends the same bytes on. The
    // record's copy stops at the cap; what the Company receives never does.
    if (hasBody) readBody(req, record, maxBody, () => {});

    const fwd = upstreamRequest(
      { host: up.hostname, port: up.port, method: req.method, path: req.url,
        headers: forwardableHeaders(req.rawHeaders) },
      answer => {
        // The Company's own status and error code are part of what happened, and a report that
        // shows a Session breach beside the answer it drew is the useful thing. It goes in
        // `response`, never in `rejection`: that field means this grader refused under a rule,
        // and the recorder refuses nothing.
        record.response = { status: answer.statusCode, error: null };
        if (/json/i.test(String(answer.headers["content-type"] ?? ""))) {
          let text = "", over = false;
          answer.on("data", c => {
            if (over) return;
            if (text.length + c.length > MAX_ERROR_BODY) { over = true; return; }
            text += c;
          });
          answer.on("end", () => {
            if (over) return;
            try {
              const parsed = JSON.parse(text);
              if (typeof parsed?.error === "string") record.response.error = parsed.error;
            } catch { /* not an OAuth style error body, and not ours to insist on */ }
          });
        }
        res.writeHead(answer.statusCode, answer.rawHeaders);
        answer.pipe(res);
      });
    // Emitted when the exchange is over, which is the first moment the record is complete: the
    // body has arrived and the Company has answered. "close" rather than "finish" so an aborted
    // exchange is emitted too, as the incomplete record it is. `emit` is idempotent, so the
    // flush at shutdown cannot write a record twice.
    res.on("close", () => emit(record));
    fwd.on("error", () => {
      record.response = { status: 502, error: "recorder_upstream_unreachable" };
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "recorder_upstream_unreachable" }));
      }
    });
    req.pipe(fwd);
  });

  // Requests Node refuses before the handler runs, kept for the same reason the hosted Company
  // keeps them: a request nothing recorded is a request no rule examined, and a log that quietly
  // holds less than the hosted one is a selection rather than a log. The Company cannot answer
  // these because the recorder never gets a parseable request to forward.
  server.on("clientError", (err, socket) => {
    const row = { rejected: true, code: err.code ?? "UNKNOWN", at: Math.floor(Date.now() / 1000),
                  bytes: err.rawPacket?.length ?? null, isResource: false, isPage: false,
                  mustNotCarry: false, headers: {}, body: null,
                  classifiedAs: "refused by the HTTP parser before any rule could see it" };
    row.seq = ++seq;
    records.push(row);
    emit(row);
    if (!socket.destroyed) socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n");
  });

  return {
    server, records, warnings,
    get seq() { return seq; },
    // Anything still in flight when the recorder is told to stop: emitted as it stands, because
    // an unfinished request is still evidence about the agent.
    flush() { for (const r of records) emit(r); },
    listen(port = 0, host = "127.0.0.1") {
      return new Promise(r => server.listen(port, host, () => r(server.address().port)));
    },
    // `closeAllConnections` first, because Node's close() waits for live connections and an agent
    // holding a long poll on the events route of 8.6 then keeps the recorder alive for ever. The
    // documented flow is to stop it with Ctrl-C and get the report, and without this the first
    // Ctrl-C hung and the report was never written.
    close() {
      return new Promise(r => {
        server.closeAllConnections?.();
        server.close(() => r());
      });
    },
  };
}

// ---------------------------------------------------------------------------------------
// The log file, and judging from it.
//
// A recorded verdict is worth something only if it can be produced again from the file alone,
// with no network, no config and not this process. So the first line of the file carries
// everything the classification depended on: the public origin, the Company context, the
// discovery document and the API templates. Judge it tomorrow, on another machine, and you get
// the same verdicts or the file is at fault.
// ---------------------------------------------------------------------------------------

// JSON Lines, because a run is appended to while it happens and must survive the recorder being
// killed. A JSON array would need rewriting on every record and would be truncated garbage if
// the process died mid-run; a line is either complete or it is the last one and discarded.
export function openRunFile(path, header) {
  writeFileSync(path, JSON.stringify({ kind: "poppy-recorded-run", version: 1, ...header }) + "\n");
  return { path };
}

export function appendRecord(file, record) {
  appendFileSync(file.path, JSON.stringify(record) + "\n");
}

export function readRun(path) {
  const lines = readFileSync(path, "utf8").split("\n").filter(l => l.trim() !== "");
  if (!lines.length) throw new Error(`${path} is empty, so there is no run in it`);
  const header = JSON.parse(lines[0]);
  if (header.kind !== "poppy-recorded-run")
    throw new Error(`${path} does not start with a recorded run header`);
  const records = [];
  for (const line of lines.slice(1)) {
    // A truncated last line is the recorder having been killed mid write, which is expected and
    // is not a reason to refuse the rest of the run.
    try { records.push(JSON.parse(line)); } catch { break; }
  }
  return { header, records };
}

// Group recordings into Companies and judge them.
//
// 3.2: "Several domains MAY have the same issuer... and they are then one Company: the same User
// IDs (5.1), Sessions, and refresh tokens apply to all of them." So the identifier decides, not
// the hostname: a builder whose documents are on the apex and whose API is on another host
// records both and judges them together, and `session.not-on-documents` can then see both halves.
// Two identifiers are two Companies, which is what the pairwise rules need. Three is refused
// rather than quietly reduced to two, because a report that silently dropped a third would be a
// statement about a Company nobody chose.
export function judge(runs, { graderCommit = "unknown", token = "" } = {}) {
  if (!Array.isArray(runs) || runs.length === 0) throw new Error("no recorded runs to judge");
  const byIdentifier = new Map();
  for (const run of runs) {
    // Rebuilt from the Company's own document in the header rather than taken from the context
    // stored beside it, so a log recorded before a context field existed judges exactly like one
    // recorded after. The served version set arrived that way: without this, every run captured
    // earlier would abstain on every version rule. The document is in the log, so judge still
    // needs no network and no configuration.
    const ctx = run.header?.discovery ? contextOf(run.header.discovery) : run.header?.ctx;
    if (!ctx?.identifier) throw new Error("a recorded run has no Company identifier in its header");
    const got = byIdentifier.get(ctx.identifier);
    if (got) got.log.push(...run.records);
    else byIdentifier.set(ctx.identifier, { ctx, log: [...run.records], origin: run.header.origin });
  }
  if (byIdentifier.size > 2)
    throw new Error(`these recordings are of ${byIdentifier.size} Companies, and this grader judges one or two: `
      + [...byIdentifier.keys()].join(", "));

  const companies = [...byIdentifier.values()];
  // Ordinals are assigned across the whole run in time order, so a log appended out of order
  // still reads as one timeline.
  for (const c of companies) c.log.sort((x, y) => (x.at ?? 0) - (y.at ?? 0));
  const run = { companies, token, graderCommit, mode: "recorded" };
  return { run, report: buildRecordedReport(run) };
}

// A recorded run has whatever the builder recorded, one Company or two, and buildReport takes it
// as it is. An earlier version padded it to two with an empty Company so the old two-Company
// shape would not crash, and the padding leaked into the page: a top sentence reading "recorded
// at shop.example and undefined", and a per-Company badge printing that word beside every
// abstention. The pairwise rules abstain on their own when there is no second context.
//
// `frozen`, because a file cannot receive more requests. Without it every recorded report said
// "This run is open. Verdicts cover the requests seen so far and will change as more arrive."
function buildRecordedReport(run) {
  const report = buildReport({ ...run, frozen: true, ended: run.ended ?? Math.floor(Date.now() / 1000) });
  report.mode = run.mode;
  report.recordedCompanies = run.companies.length;
  return report;
}
