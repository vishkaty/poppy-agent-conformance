// Record your own agent, and judge it yourself.
//
//   node record-cli.mjs config.json              record: a proxy in front of your own Company
//   node record-cli.mjs judge run.jsonl [b.jsonl]   judge: rebuild the report from the file
//   ... judge run.jsonl --attribution by-issuer   one report per claimed client_id, and an index
//
// The point of the two commands being separate is that the second needs nothing: no network, no
// config, not the process that recorded. A verdict you cannot produce again from the file is a
// verdict about a moment, and this grader's whole claim is that a verdict is a pure function of
// a recorded log.
//
// The config, one Company per recorder:
//
//   {
//     "origin": "https://api.shop.example",      the PUBLIC origin your agent uses for this host
//     "upstream": "http://127.0.0.1:3000",       your Company, where the recorder forwards
//     "listen": "127.0.0.1:8790",                where the recorder listens
//     "discovery": "./poppy.json",               your own document, as a file
//     "openapi": ["./openapi.json"],             the documents describing your APIs
//     "auth_server_metadata": "./as.json",       optional, so leaks to OAuth endpoints are judged
//     "log": "./runs/today.jsonl"
//   }
//
// `origin` is the URL your agent uses, never the address the recorder binds: behind any TLS
// terminator those differ, and `htu` is compared against the former. Getting it wrong is the
// likeliest way to make this report wrong about a conforming agent, so the recorder refuses to
// start when nothing in your own document is on it.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { createRecorder, openRunFile, appendRecord, readRun, judge } from "./recorder.mjs";
import { templatesOfOpenapi, contextOf } from "./discovery.mjs";
import { renderHtml } from "./report.mjs";

function graderCommit() {
  if (process.env.POPPY_GRADER_COMMIT) return process.env.POPPY_GRADER_COMMIT;
  try {
    const sha = execFileSync("git", ["rev-parse", "--short=12", "HEAD"],
                             { cwd: import.meta.dirname, encoding: "utf8" }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain"],
                               { cwd: import.meta.dirname, encoding: "utf8" }).trim();
    return dirty ? `${sha}+local-changes` : sha;
  } catch { return "unknown"; }
}

function readJson(path, what) {
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch (err) { throw new Error(`${what} could not be read from ${path}: ${err.message}`); }
}

function writeReport(outDir, report, name) {
  const jsonPath = join(outDir, `${name}.json`);
  const htmlPath = join(outDir, `${name}.html`);
  writeFileSync(jsonPath, JSON.stringify(report, null, 1));
  writeFileSync(htmlPath, renderHtml(report));
  return { jsonPath, htmlPath };
}

async function record(configPath) {
  const cfg = readJson(configPath, "the recorder config");
  const base = dirname(resolve(configPath));
  const at = (p) => resolve(base, p);
  for (const required of ["origin", "upstream", "discovery", "log"])
    if (!cfg[required]) throw new Error(`the config has no \`${required}\``);

  const discovery = readJson(at(cfg.discovery), "your poppy.json");
  // Every API document the builder names, read for the method and template pairs 5.2 counts as
  // destinations. Counted per document, because one that yields nothing is the quiet failure that
  // matters: every API call then classifies as not a destination and the rules that matter most
  // abstain. A `servers[].url` carrying a template variable, such as https://{env}.shop.example,
  // is the common cause and cannot be resolved without knowing the variable.
  const apiOperations = [];
  const emptyDocs = [];
  for (const file of cfg.openapi ?? []) {
    const templates = templatesOfOpenapi(readJson(at(file), "an OpenAPI document"), cfg.origin);
    if (!templates.length) emptyDocs.push(file);
    apiOperations.push(...templates);
  }
  // Optional, and worth saying plainly: without it a Session JWT sent to the token endpoint is
  // not judged, because the recorder does not know where that endpoint is.
  const asMeta = cfg.auth_server_metadata ? readJson(at(cfg.auth_server_metadata), "your authorization server metadata") : null;
  const authServerEndpoints = asMeta
    ? [asMeta.token_endpoint, asMeta.revocation_endpoint, asMeta.authorization_endpoint].filter(Boolean)
    : [];

  const logPath = at(cfg.log);
  const ctx = contextOf(discovery);
  const file = openRunFile(logPath, { origin: cfg.origin, ctx, discovery, apiOperations,
                                      authServerEndpoints, graderCommit: graderCommit() });

  const recorder = createRecorder({
    origin: cfg.origin, upstream: cfg.upstream, discovery, apiOperations, authServerEndpoints,
    feedbackEndpoint: cfg.feedback_endpoint ?? null,
    extensionEndpoints: cfg.extension_endpoints ?? [],
    trustForwardedFor: cfg.trust_forwarded_for === true,
    maxBodyBytes: cfg.max_body_bytes,
    onRecord: (rec) => appendRecord(file, rec),
  });

  // Split on the LAST colon, because an IPv6 listen address is full of them and splitting on the
  // first gave `::1` a host of "" and a port of "".
  const listen = String(cfg.listen ?? "127.0.0.1:8790");
  const cut = listen.lastIndexOf(":");
  const host = cut === -1 ? listen : listen.slice(0, cut).replace(/^\[|\]$/g, "");
  const port = cut === -1 ? 8790 : Number(listen.slice(cut + 1));
  const bound = await recorder.listen(port, host);
  for (const w of recorder.warnings) console.log(`warning: ${w}`);
  for (const file of emptyDocs)
    console.log(`warning: ${file} describes no operation on ${cfg.origin}, so calls to its APIs are`
      + " examined by no rule. Check its `servers` entries: a URL with a template variable in it"
      + " cannot be resolved here.");
  if (!asMeta)
    console.log("warning: no auth_server_metadata, so a Session JWT sent to your token or revocation endpoint is examined by no rule");
  console.log(`recording http://${host}:${bound} for ${cfg.origin} upstream ${cfg.upstream} log ${logPath}`);
  console.log("point your agent at the public origin above, then stop this with Ctrl-C to write the report");

  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    recorder.flush();
    await recorder.close();
    const { report } = judge([readRun(logPath)], { graderCommit: graderCommit() });
    const written = writeReport(dirname(logPath), report, "report");
    console.log(`\n${report.topSentence}`);
    console.log(`report ${written.htmlPath}`);
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

// One option taken out of the argument list, with its value.
function takeOption(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return { value: null, rest: args };
  return { value: args[i + 1] ?? null, rest: [...args.slice(0, i), ...args.slice(i + 2)] };
}

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// The index for a run judged per claimed client_id: one line per group with its page, the claim
// caveat once, and the count of requests attributed to nobody. No verdict across groups appears
// here, because a total across agents is a verdict about nobody.
function renderIndex(out) {
  const rows = out.agents.map(g =>
    `<li><a href="agents/${g.tag}.html"><code>${esc(g.iss)}</code></a>: ${g.requests} request(s); `
    + `${g.report.summary.fail} failed, ${g.report.summary.pass} passed, ${g.report.summary.unreached} not reached, `
    + `${g.report.summary.unjudged} not judged by the grader</li>`).join("\n");
  return `<!doctype html><meta charset="utf-8"><title>Recorded run, by claimed client_id</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}code{font-size:.9em}</style>
<h1>Recorded run, judged by claimed client_id</h1>
<p>${out.agents.length} claimed client_id(s). ${esc(out.unattributed.sentence)}</p>
<p>${esc(out.agents[0]?.claim ?? "Grouped by the client_id each Session JWT claimed. This recorder verified nothing about that claim.")}</p>
<ul>${rows}</ul>
<p>Each page is the same report this grader writes for a single agent, over that client_id's records alone. Nothing here totals across them.</p>
`;
}

function judgeFiles(args0) {
  const { value: out, rest: args1 } = takeOption(args0, "--out");
  const { value: attribution, rest: files } = takeOption(args1, "--attribution");
  if (attribution && attribution !== "by-issuer" && attribution !== "single-agent")
    throw new Error(`--attribution takes by-issuer or single-agent, not ${attribution}`);
  if (!files.length) throw new Error("judge needs at least one recorded run file");
  const runs = files.map(f => readRun(resolve(f)));
  const dir = out ? resolve(out) : dirname(resolve(files[0]));
  const judged = judge(runs, { graderCommit: graderCommit(), attribution: attribution ?? "single-agent" });
  if (!judged.agents) {
    const { report } = judged;
    const written = writeReport(dir, report, "report");
    console.log(report.topSentence);
    if (report.selfRecorded) console.log(report.selfRecorded);
    console.log(`report ${written.htmlPath}`);
    return;
  }
  // By claimed client_id: one page per group under agents/, and an index in place of the report.
  mkdirSync(join(dir, "agents"), { recursive: true });
  for (const g of judged.agents) writeReport(join(dir, "agents"), g.report, g.tag);
  writeFileSync(join(dir, "report.json"), JSON.stringify({ index: judged.index, agents: judged.agents.map(g => ({ iss: g.iss, tag: g.tag, requests: g.requests, claim: g.claim })) }, null, 1));
  writeFileSync(join(dir, "report.html"), renderIndex(judged));
  console.log(`${judged.agents.length} claimed client_id(s), one page each under ${join(dir, "agents")}; ${judged.unattributed.sentence}`);
  console.log(`index ${join(dir, "report.html")}`);
}

const [first, ...rest] = process.argv.slice(2);
try {
  if (!first) {
    console.error("usage: record-cli.mjs config.json | record-cli.mjs judge run.jsonl [other.jsonl] [--out dir]");
    process.exit(2);
  } else if (first === "judge") {
    judgeFiles(rest);
  } else {
    await record(first);
  }
} catch (err) {
  console.error(String(err?.message ?? err));
  process.exit(1);
}
