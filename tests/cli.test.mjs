// The whole thing, through the entry point a builder actually runs.
//
// Every other test in this suite imports a module. This one spawns `grade.mjs` as a process,
// reads the origins it prints, drives it over real sockets with traffic signed by the
// protocol authors' own code, and reads the report back. A pipeline can be green at every
// module and broken at the seam: the entry point is where the configuration, the two
// listeners, the canary gate and the report meet for the first time.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ref = await import("../reference/jose.ts");

// Start the grader and wait for the line that says where it is listening.
async function grader(config) {
  const dir = mkdtempSync(join(tmpdir(), "poppy-grader-"));
  const file = join(dir, "grader.json");
  writeFileSync(file, JSON.stringify(config));
  const child = spawn(process.execPath, ["--experimental-strip-types", "grade.mjs", file],
                      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  const ready = await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`grade.mjs printed no ready line in 20s:\n${out}`)), 20_000);
    child.stdout.on("data", d => {
      out += d;
      const m = out.match(/^ready (\S+) (\S+) control (\S+)$/m);
      if (m) { clearTimeout(t); resolve({ a: m[1], b: m[2], control: m[3] }); }
    });
    child.stderr.on("data", d => { out += d; });
    child.on("exit", code => { clearTimeout(t); reject(new Error(`grade.mjs exited ${code}:\n${out}`)); });
  });
  return { ...ready, child, output: () => out,
           stop: () => new Promise(r => { child.on("exit", r); child.kill("SIGTERM"); }) };
}

// A conforming agent, built with the authors' helpers, driven at a real origin.
async function agent(origin) {
  const doc = await (await fetch(`${origin}/.well-known/poppy.json`)).json();
  const operator = await ref.generateKey();
  const key = await ref.generateKey();
  const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk,
                                                iss: "https://agent.example/agent.json" });
  const sid = ref.randomId(16), sub = ref.randomId(16);
  const send = async (method, path) => {
    const url = `${origin}${path}`;
    const jwt = await ref.signSessionJwt({ key, delegation, iss: "https://agent.example/agent.json",
      aud: doc.auth.issuer, sid, sub, method, url });
    return fetch(url, { method, headers: { "poppy-session": jwt, "poppy-version": doc.protocol_version } });
  };
  return { doc, send };
}

test("a builder can start the grader, drive an agent at it, and read a report", async () => {
  const g = await grader({ companies: [{ port: 0 }, { port: 0 }] });
  try {
    // 1. the grader says it is alive, and which process it is
    const health = await (await fetch(`${g.control}/grader/health`)).json();
    assert.equal(health.ok, true);
    assert.equal(health.lease_held, false);

    // 2. a lease, which only happens if the canary passed against this live deployment
    const made = await fetch(`${g.control}/grader/runs`, { method: "POST" });
    // The body is read once. An assertion message is evaluated eagerly, so `await res.text()`
    // as the message consumes the body the next line wants.
    const madeText = await made.text();
    assert.equal(made.status, 201, madeText);
    const run = JSON.parse(madeText);
    assert.deepEqual(run.companies, [g.a, g.b], "the origins printed are not the origins handed out");

    // 3. an agent drives BOTH Companies, which is what the pairwise rules need
    for (const origin of [g.a, g.b]) {
      const a = await agent(origin);
      // the OpenAPI document poppy.json advertises, followed as an agent would
      const api = await fetch(a.doc.apis.find(x => x.type === "openapi").url);
      assert.equal(api.status, 200, "the advertised OpenAPI document was not served");
      const paths = Object.keys((await api.json()).paths);
      assert.ok(paths.length > 0);
      const r1 = await a.send("GET", paths.find(p => !p.includes("{")));
      assert.equal(r1.status, 200, `a destination the document describes answered ${r1.status}`);
      await a.send("GET", paths.find(p => p.includes("{"))?.replace(/\{[^}]*\}/, "7") ?? "/poppy/orders");
    }

    // 4. the report, as data and as a page
    await fetch(`${g.control}/grader/runs/${run.token}/end`, { method: "POST" });
    const rep = await (await fetch(`${g.control}/grader/report/${run.token}.json`)).json();
    assert.equal(rep.run.frozen, true);
    assert.ok(rep.requests.length >= 6, `only ${rep.requests.length} requests were recorded`);

    const fails = rep.rules.flatMap(r => r.perCompany.filter(c => c.verdict === "FAIL")
                                          .map(c => `${r.id} at ${c.company}: ${c.why}`));
    assert.deepEqual(fails, [], "the grader failed a conforming agent end to end");
    for (const p of rep.pairwise)
      assert.equal(p.verdict, "PASS", `${p.id}: ${p.verdict} ${p.why}`);

    // the rules a conforming agent reaches must actually be judged, or this proves nothing
    const passed = rep.rules.filter(r => r.worst === "PASS").length;
    assert.ok(passed >= 18, `only ${passed} rules passed, so most were never reached`);

    const html = await (await fetch(`${g.control}/grader/report/${run.token}`)).text();
    assert.match(html, /What your agent put on the wire/);
    assert.ok(!html.includes(run.token), "the page contains its own token");
    assert.ok(!g.output().includes(run.token), "the grader printed a run token");
  } finally { await g.stop(); }
});

test("the grader refuses to start on a configuration that cannot grade", async () => {
  // Better to fail at startup than to serve a deployment whose every verdict is about us.
  await assert.rejects(
    () => grader({ companies: [{ port: 0, origin: "http://127.0.0.1:1/with/a/path" }, { port: 0 }] }),
    /exited [^0]/, "a bad origin was accepted at startup");
  await assert.rejects(() => grader({ companies: [{ port: 0 }] }),
    /exited [^0]/, "a single Company was accepted, so the pairwise rules could never be judged");
});

// The recorder, through the entry point a builder runs. Same reason as the test above: the
// config file, the proxy, the log file and the judge meet for the first time here, and a
// pipeline can be green at every module and broken at the seam.
test("record it yourself: a conforming agent through the recorder, judged from the file", async () => {
  const { createServer } = await import("node:http");
  const { discoveryFor, openapiFor, DEFAULT_OPERATIONS } = await import("../discovery.mjs");
  const { readRun, judge } = await import("../recorder.mjs");
  const { readFileSync } = await import("node:fs");

  const dir = mkdtempSync(join(tmpdir(), "poppy-recorder-"));
  const log = join(dir, "run.jsonl");
  // The recorder's own address is the public origin the agent will use, so the documents name
  // it: that is exactly the configuration a builder has when the recorder is the front door.
  const listenPort = 18_793;
  const origin = `http://127.0.0.1:${listenPort}`;

  // The builder's own Company. It serves its own documents, because the agent discovers through
  // the recorder and a Company that answered {} to its own poppy.json would be refused by the
  // agent for the agent's own good reasons, which would prove nothing about the recorder.
  const company = createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0];
    res.writeHead(200, { "content-type": "application/json" });
    if (path === "/.well-known/poppy.json") res.end(JSON.stringify(discoveryFor(origin)));
    else if (path === "/poppy/openapi.json") res.end(JSON.stringify(openapiFor(origin, DEFAULT_OPERATIONS)));
    else res.end("{}");
  });
  await new Promise(r => company.listen(0, "127.0.0.1", r));
  const companyPort = company.address().port;
  writeFileSync(join(dir, "poppy.json"), JSON.stringify(discoveryFor(origin)));
  writeFileSync(join(dir, "openapi.json"), JSON.stringify(openapiFor(origin, DEFAULT_OPERATIONS)));
  writeFileSync(join(dir, "config.json"), JSON.stringify({
    origin, upstream: `http://127.0.0.1:${companyPort}`, listen: `127.0.0.1:${listenPort}`,
    discovery: join(dir, "poppy.json"), openapi: [join(dir, "openapi.json")], log,
  }));

  const child = spawn(process.execPath, ["--experimental-strip-types", "record-cli.mjs", join(dir, "config.json")],
                      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  try {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`record-cli.mjs printed no recording line in 20s:\n${out}`)), 20_000);
      child.stdout.on("data", d => { out += d; if (/^recording /m.test(out)) { clearTimeout(t); resolve(); } });
      child.stderr.on("data", d => { out += d; });
      child.on("exit", c => { clearTimeout(t); reject(new Error(`record-cli.mjs exited ${c}:\n${out}`)); });
    });
    assert.match(out, new RegExp(`for ${origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
      "the recording line must say which public origin it is recording for");

    // A conforming agent, built with the protocol authors' own helpers, through the recorder.
    const a = await agent(origin);
    const got = await a.send("GET", "/poppy/orders");
    // Read once, then assert. An assertion message that awaits .text() consumes the body
    // whether or not the assertion fails, which this project has been bitten by three times.
    const text = await got.text();
    assert.equal(got.status, 200, `the Company's answer did not come back through the recorder: ${text}`);
  } finally {
    // The child may already be gone (a failed start), and waiting for an exit that has
    // happened waits for ever. This bit the first run of this test.
    if (child.exitCode === null && child.signalCode === null)
      await new Promise(r => { child.on("exit", r); child.kill("SIGINT"); });
    await new Promise(r => company.close(r));
  }

  const run = readRun(log);
  assert.ok(run.records.length >= 1, `nothing was written to the log:\n${out}\n${readFileSync(log, "utf8")}`);
  const { report } = judge([run], { graderCommit: "test" });
  assert.equal(report.mode, "recorded");
  const failed = report.rules.filter(r => r.worst === "FAIL").map(r => r.id);
  assert.deepEqual(failed, [], `a conforming agent failed through the recorder: ${failed.join(", ")}`);
  assert.ok(report.selfRecorded?.includes("Self-recorded"), "the report must label itself");
});
