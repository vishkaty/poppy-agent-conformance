// The pin, against a real TLS server on a real socket.
//
// It is tested this way because the previous pin was tested against a fake fetch that merely
// recorded an option Node ignores, so the suite proved the fixture and not the connection.
// Here a certificate is generated, a server is started on loopback, and the pin is asked to
// reach it by a hostname that resolves to nothing: if the pin works, the connection still
// lands on the server; if it does not, the request fails to resolve.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { pinnedGet } from "../fetch-pinned.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// A self-signed certificate for a name that does not exist in DNS.
const NAME = "pinned.invalid";
const dir = mkdtempSync(join(tmpdir(), "poppy-tls-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
  "-subj", `/CN=${NAME}`, "-addext", `subjectAltName=DNS:${NAME}`,
  "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem")], { stdio: "ignore" });
const key = readFileSync(join(dir, "k.pem")), cert = readFileSync(join(dir, "c.pem"));

async function server(handler) {
  const s = createServer({ key, cert }, handler);
  const port = await new Promise(r => s.listen(0, "127.0.0.1", () => r(s.address().port)));
  return { port, close: () => new Promise(r => s.close(() => r())) };
}

test("the connection goes to the pinned address, not to whatever DNS would say", async () => {
  // pinned.invalid resolves nowhere, so this can only succeed if `lookup` was honoured.
  const s = await server((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, host: req.headers.host }));
  });
  try {
    const res = await pinnedGet(`https://${NAME}:${s.port}/agent.json`,
      { address: "127.0.0.1", ca: cert });
    assert.equal(res.status, 200);
    const body = await res.json();
    // the Host header and SNI keep the NAME, so a certificate is checked against the name
    assert.match(body.host, new RegExp(NAME), `Host was ${body.host}`);
    assert.equal(res.remoteAddress, "127.0.0.1");
  } finally { await s.close(); }
});

test("without the pin the same request cannot resolve, which is what makes the test above mean something", async () => {
  // The control. If pinned.invalid happened to resolve, the test above would pass whether or
  // not the pin worked.
  await assert.rejects(() => pinnedGet(`https://${NAME}/agent.json`, { address: "" }),
    (err) => /ENOTFOUND|EAI_AGAIN|not a URL|address/i.test(String(err.message)) || err.code === "ERR_INVALID_ARG_TYPE",
    "a hostname that resolves nowhere was reachable without a pinned address");
});

test("a body over the cap is aborted as it arrives, not after it is buffered", async () => {
  let sent = 0;
  const s = await server((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const chunk = "x".repeat(16 * 1024);
    const timer = setInterval(() => { sent += chunk.length; res.write(chunk); }, 1);
    res.on("close", () => clearInterval(timer));
  });
  try {
    await assert.rejects(
      () => pinnedGet(`https://${NAME}:${s.port}/jwks.json`, { address: "127.0.0.1", ca: cert, maxBytes: 50_000 }),
      (err) => err.overCap === true, "an oversize body was not refused");
    assert.ok(sent < 5_000_000, `it kept reading: ${sent} bytes`);
  } finally { await s.close(); }
});

test("a server that never answers is given up on, with a reason", async () => {
  const s = await server(() => { /* never responds */ });
  try {
    await assert.rejects(
      () => pinnedGet(`https://${NAME}:${s.port}/agent.json`, { address: "127.0.0.1", ca: cert, timeoutMs: 300 }),
      (err) => err.timedOut === true && /300ms/.test(err.message),
      "a request that got no answer was not timed out");
  } finally { await s.close(); }
});

test("a certificate that does not match the name is refused", async () => {
  // The pin changes which ADDRESS is connected to and must not weaken what is verified.
  const s = await server((req, res) => res.end("{}"));
  try {
    await assert.rejects(
      () => pinnedGet(`https://other.invalid:${s.port}/agent.json`, { address: "127.0.0.1" }),
      (err) => /altname|certificate|self-signed|unable to verify/i.test(String(err.message)),
      "a certificate for the wrong name was accepted");
  } finally { await s.close(); }
});
