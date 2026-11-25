// What a recording has to survive over weeks in front of a real store.
//
// Three defects, each reproduced before it was fixed. A restart destroyed the log, because
// openRunFile truncated the file it opened: a crash on day nine erased nine days. A corrupt line
// in the MIDDLE silently dropped every record after it, because readRun stopped at the first
// parse failure, which is right for a truncated LAST line and wrong anywhere else. And a body
// sent with a content encoding was stored as utf8 of the compressed bytes, so JSON.parse failed
// and the rule about 8.3 request ids faulted a conforming agent for sending no id.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync, deflateSync, brotliCompressSync } from "node:zlib";
import { createHash } from "node:crypto";
import { openRunFile, appendRecord, readRun } from "../recorder.mjs";
import { recordOf, readBody } from "../record.mjs";
import { discoveryFor, templatesOfOpenapi, openapiFor, authServerEndpointsFor, DEFAULT_OPERATIONS } from "../discovery.mjs";
import { CHECKS } from "../checks.mjs";
import * as f from "./fixture.mjs";

const DISCOVERY = { protocol_version: "1.0", organization: { domain: "shop.example" },
                    auth: { issuer: "https://shop.example/poppy", disabled: true } };
const HEADER = { origin: "https://shop.example", discovery: DISCOVERY };
const dir = () => mkdtempSync(join(tmpdir(), "poppy-robust-"));

test("reopening a log appends to it, and keeps the salt, so a restart loses nothing", async () => {
  const keys = await f.agentKeys();
  const path = join(dir(), "run.jsonl");
  const first = openRunFile(path, HEADER);
  appendRecord(first, { ...(await f.request(keys, { sub: "day-one", seq: 1 })), remoteAddress: "203.0.113.1" });
  const saltBefore = JSON.parse(readFileSync(path, "utf8").split("\n")[0]).addressSalt;

  // The recorder is restarted: same path, same Company.
  const second = openRunFile(path, HEADER);
  appendRecord(second, { ...(await f.request(keys, { sub: "day-two", seq: 2 })), remoteAddress: "203.0.113.1" });

  const run = readRun(path);
  assert.equal(run.records.length, 2, "the record from before the restart is still there");
  assert.deepEqual(run.records.map(r => r.headers["poppy-session"] ? "session" : "bare").length, 2);
  assert.equal(run.header.addressSalt, saltBefore,
    "the salt is kept, so a source tag means the same thing across a restart");
});

test("reopening a log for a DIFFERENT Company refuses rather than mixing two runs", () => {
  const path = join(dir(), "run.jsonl");
  openRunFile(path, HEADER);
  assert.throws(() => openRunFile(path, { ...HEADER, origin: "https://other.example" }),
    /other\.example|another Company|different/i,
    "two Companies in one file would make every verdict ambiguous");
});

test("a corrupt line in the middle is skipped and counted, not a silent end of the run", async () => {
  const keys = await f.agentKeys();
  const path = join(dir(), "run.jsonl");
  const file = openRunFile(path, HEADER);
  appendRecord(file, await f.request(keys, { sub: "u", seq: 1 }));
  appendFileSync(path, '{"this line was half written when the disk fill\n');
  appendRecord(file, await f.request(keys, { sub: "u", seq: 2 }));
  const run = readRun(path);
  assert.equal(run.records.length, 2, "the records after the corrupt line are read");
  assert.equal(run.unreadableLines, 1, "and the corrupt line is counted rather than hidden");
});

test("a truncated LAST line is still the recorder being killed mid write, and is not counted twice", async () => {
  const keys = await f.agentKeys();
  const path = join(dir(), "run.jsonl");
  const file = openRunFile(path, HEADER);
  appendRecord(file, await f.request(keys, { sub: "u", seq: 1 }));
  appendFileSync(path, '{"half');
  const run = readRun(path);
  assert.equal(run.records.length, 1);
  assert.equal(run.unreadableLines, 1);
});

const ORIGIN = "https://shop.example";
const OPS = [...DEFAULT_OPERATIONS, { method: "POST", path: "/poppy/orders", summary: "Place one" }];
const CFG = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
              apiOperations: templatesOfOpenapi(openapiFor(ORIGIN, OPS), ORIGIN),
              authServerEndpoints: authServerEndpointsFor(ORIGIN) };

function captured(method, target, raw, headers) {
  const rec = recordOf({ method, url: target, headers: { host: "shop.example", ...headers } }, CFG, { at: 1 });
  const req = { on(ev, fn) { if (ev === "data") fn(raw); if (ev === "end") fn(); return req; } };
  readBody(req, rec, 256 * 1024, () => {});
  return rec;
}

test("a compressed conversation body is decoded, so a conforming agent is not faulted for 8.3", () => {
  const body = JSON.stringify({ id: "r1", message: { author: { type: "human" }, text: "hello" } });
  for (const [name, encode] of [["gzip", gzipSync], ["deflate", deflateSync], ["br", brotliCompressSync]]) {
    const raw = encode(Buffer.from(body, "utf8"));
    const rec = captured("POST", "/poppy/conversations", raw,
                         { "content-type": "application/json", "content-encoding": name });
    assert.equal(rec.body, body, `${name}: the body a rule reads must be the decoded text`);
    assert.equal(rec.contentEncoding, name, "and the record says how it arrived");
    // The hash still covers the bytes that ARRIVED, which is what identifies the request on the wire.
    assert.equal(rec.bodySha256, createHash("sha256").update(raw).digest("hex"),
                 `${name}: the hash is over the compressed bytes, as sent`);
    const v = CHECKS.find(c => c.id === "conversation.request-id").run([{ ...rec, headers: { ...rec.headers, "poppy-session": "x" } }], f.ctx);
    assert.notEqual(v.verdict, "FAIL", `${name}: a conforming id must not be read as absent`);
  }
});

test("a body this grader cannot decode is declared, not guessed", () => {
  const rec = captured("POST", "/poppy/conversations", Buffer.from("not really gzip", "utf8"),
                       { "content-type": "application/json", "content-encoding": "gzip" });
  assert.equal(rec.bodyKept, true, "the route still keeps bodies");
  assert.equal(rec.bodyDecoded, false, "and the record says the text was not recovered");
  assert.equal(rec.body, "", "rather than offering bytes that are not the body");
});
