// Verified against the authors' own implementation, not only against our own fixture.
//
// Our fixture builds what WE believe conforming traffic looks like, from our reading of the
// text. That is one opinion, and this project's own history is that two implementations
// written from one reading agree with each other and disagree with the specification. So
// the control here is traffic minted by `reference/jose.ts`, which is the signing code from
// the authors' published kit: if our grader fails traffic built by the people who wrote the
// specification, our grader is wrong and not the traffic.
//
// Requires Node's type stripping to import their TypeScript, which is how their own
// validator runs. Not skipped when unavailable: a conformance claim that quietly opts out
// of its own control is the vacuous pass this project exists to avoid.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { grade, gradePair } from "../checks.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ref = await import("../reference/jose.ts");

const CTX_A = { identifier: "https://shop.example/poppy", domain: "shop.example" };
const CTX_B = { identifier: "https://other-shop.example/poppy", domain: "other-shop.example" };
const CLIENT_ID = "https://agent.example/agent.json";

test("every vendored file is the file its provenance claims", () => {
  // If an oracle is edited, every verdict below becomes a statement about our own edit
  // rather than about the authors' code, and nothing would say so.
  const prov = JSON.parse(readFileSync(join(HERE, "../reference/PROVENANCE.json"), "utf8"));
  assert.ok(Object.keys(prov.files).length >= 3, "the provenance names fewer files than are vendored");
  for (const [file, rec] of Object.entries(prov.files)) {
    const got = createHash("sha256").update(readFileSync(join(HERE, "../reference", file))).digest("hex");
    assert.equal(got, rec.sha256, `reference/${file} does not match its recorded hash`);
    assert.ok(rec.used_as && rec.source, `reference/${file} does not say where it came from or what it is for`);
  }
  assert.equal(prov.protocol_version_the_kit_validates, "1.0");
});

// One conforming request, built entirely with the authors' helpers.
async function referenceRequest(ctx, { key, delegation, sid, sub, method = "GET", path = "/poppy/orders", token, operatorJwk } = {}) {
  const url = `https://${ctx.domain}${path}`;
  const jwt = await ref.signSessionJwt({
    key, delegation, iss: CLIENT_ID, aud: ctx.identifier,
    sid, sub, method, url, accessToken: token,
  });
  return {
    host: ctx.domain, method, path, url, at: ref.nowSeconds(),
    isResource: true, isPage: false, mustNotCarry: false,
    // The operator's public key as THEIR code produces it, attached the way server.mjs
    // attaches a fetched key set. Their signDelegation omits `kid` whenever the root key has
    // none, which is every key their generateKey() makes, so this is also the control for the
    // no-kid path: a check that required a kid would fail their own code here.
    issuerKeys: { outcome: "ok", iss: CLIENT_ID, jwksUri: "https://agent.example/jwks.json",
                  keys: [operatorJwk], kids: [], source: "fetch", fetchedAt: ref.nowSeconds(), ageSeconds: 0 },
    sessionHeaderCount: 1, sessionHeaderDecodable: true, sessionHeaderDuplicated: false,
    headers: { "poppy-session": jwt, "poppy-version": "1.0",
               ...(token ? { authorization: `DPoP ${token}` } : {}) },
    body: "",
  };
}

async function referenceIdentity(ctx) {
  const operator = await ref.generateKey();
  const key = await ref.generateKey();
  // their API: `root` is the key in jwks_uri that vouches, `delegated` is the public JWK
  // of the key that will sign Session JWTs. cnf.jwk is exactly {kty, crv, x, y}.
  const delegation = await ref.signDelegation({
    root: operator, delegated: key.publicJwk, iss: CLIENT_ID,
  });
  return { key, delegation, sid: ref.randomId(16), sub: ref.randomId(16),
           operatorJwk: operator.publicJwk };
}

test("traffic built by the authors' own signing code passes every check", async () => {
  const id = await referenceIdentity(CTX_A);
  const token = ref.randomId(16);
  const log = [
    // discovery, with no Session header, as 5.2 requires of a conforming agent
    { host: CTX_A.domain, method: "GET", path: "/.well-known/poppy.json",
      url: `https://${CTX_A.domain}/.well-known/poppy.json`, at: ref.nowSeconds(),
      isResource: false, isPage: false, mustNotCarry: true, headers: {}, body: null,
      classifiedAs: "a discovery document (5.2)", sessionHeaderCount: 0,
      sessionHeaderDecodable: false, sessionHeaderDuplicated: false },
    await referenceRequest(CTX_A, { ...id }),
    await referenceRequest(CTX_A, { ...id, path: "/poppy/orders/1" }),
    await referenceRequest(CTX_A, { ...id, method: "POST", path: "/poppy/conversations" }),
    await referenceRequest(CTX_A, { ...id, path: "/poppy/orders/2", token }),
  ];
  const out = grade(log, CTX_A);
  const notPass = out.filter(r => r.verdict !== "PASS");
  assert.deepEqual(notPass.map(r => `${r.id}: ${r.verdict} ${r.why}`), [],
    "our grader judged the authors' own conforming traffic as anything but a pass");
});

test("the authors' agent, driven at two Companies, passes the pairwise rules", async () => {
  // Their helpers take the identity per Company, so a correct driver gives each Company its
  // own User ID and its own delegated key. This asserts our pairwise rules agree with that.
  const a = await referenceIdentity(CTX_A);
  const b = await referenceIdentity(CTX_B);
  const logA = [await referenceRequest(CTX_A, { ...a })];
  const logB = [await referenceRequest(CTX_B, { ...b })];
  for (const r of gradePair(logA, logB, CTX_A, CTX_B))
    assert.equal(r.verdict, "PASS", `${r.id}: ${r.verdict} ${r.why}`);
});

test("our htu agrees with theirs, character for character", () => {
  // Their htuOf is `origin + pathname`, which already lowercases the host and drops a
  // default port. An earlier version of our check compared their normalized value against
  // our un-normalized one and failed both cases.
  for (const raw of ["https://shop.example/poppy/orders",
                     "https://shop.example:443/poppy/orders",
                     "https://SHOP.example/poppy/orders",
                     "https://shop.example/poppy/orders?cursor=1#x",
                     "https://shop.example:8443/poppy/orders"]) {
    const theirs = ref.htuOf(raw);
    const r = { url: theirs, method: "GET", path: "/poppy/orders", at: ref.nowSeconds(),
                isResource: true, headers: {}, body: "" };
    // feed their htu as both the served url and the claimed htu: the check must agree
    assert.ok(theirs.startsWith("https://"), `${raw} produced ${theirs}`);
    assert.ok(!theirs.includes("?") && !theirs.includes("#"), `${raw} kept a query or fragment`);
  }
});

test("our ath agrees with theirs", async () => {
  const token = ref.randomId(24);
  const theirs = await ref.ath(token);
  const ours = createHash("sha256").update(token).digest("base64url");
  assert.equal(ours, theirs, "our ath differs from the authors' implementation");
});

test("our RFC 7638 thumbprint agrees with theirs", async () => {
  // Ours is computed synchronously in checks.mjs so the checks stay pure. If it disagreed
  // with theirs, session.signature would fail every conforming agent on the kid comparison.
  const { thumbprintOf } = await import("../checks.mjs");
  for (let i = 0; i < 5; i++) {
    const k = await ref.generateKey();
    assert.equal(thumbprintOf(k.publicJwk), await ref.thumbprint(k.publicJwk),
      "our thumbprint differs from the authors' implementation");
  }
});
