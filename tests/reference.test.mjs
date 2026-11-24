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
async function referenceRequest(ctx, { key, delegation, sid, sub, method = "GET", path = "/poppy/orders", token, operatorJwk, body = "", conversationRoute = null } = {}) {
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
    conversationRoute,
    headers: { "poppy-session": jwt, "poppy-version": "1.0",
               ...(token ? { authorization: `DPoP ${token}` } : {}) },
    body,
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

test("traffic built by the authors' own signing code passes every check it can reach", async () => {
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
    // 8.3 requires a request id on every conversation POST. Without one here the control would
    // abstain on that rule, and a control that abstains proves less than one that passes.
    await referenceRequest(CTX_A, { ...id, method: "POST", path: "/poppy/conversations",
                                    conversationRoute: "start",
                                    body: JSON.stringify({ id: `ref_${ref.randomId(8)}`,
                                                           message: { author: { type: "agent" }, text: "hello",
                                                                      context: { locale: "en-US", user_available: true } } }) }),
    await referenceRequest(CTX_A, { ...id, path: "/poppy/orders/2", token }),
  ];
  const out = grade(log, CTX_A);
  // Same allowance as the conforming control, and for the same reason: a rule about what an agent
  // does after this Company refuses a request cannot be reached by traffic that is never refused.
  // The list is declared beside the fixture, and the check below proves each listed rule really
  // is unreached here rather than quietly failing.
  const { REFERENCE_UNREACHED } = await import("./breaches.mjs");
  const notPass = out.filter(r => r.verdict !== "PASS" && !REFERENCE_UNREACHED[r.id]);
  assert.deepEqual(notPass.map(r => `${r.id}: ${r.verdict} ${r.why}`), [],
    "our grader judged the authors' own conforming traffic as anything but a pass");
  for (const [id, why] of Object.entries(REFERENCE_UNREACHED)) {
    assert.ok(String(why).length > 40, `the reason given for ${id} says nothing`);
    const v = out.find(r => r.id === id);
    assert.equal(v.verdict, "INCONCLUSIVE", `${id} is declared unreachable by this control and reached a verdict`);
  }
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

test("the README and the provenance record do not disagree about the archive measurement", () => {
  // One fact, two files, and they drifted: the README said the recorded archive hash differs
  // from a download on one date while the provenance note named another, so a reader checking
  // the claim would download the wrong day's archive and could not reproduce either sentence.
  // The measurement is also required to be self-evidencing: "differs" is only a statement if
  // the hash it was compared against is written down next to the one it differs from.
  const prov = JSON.parse(readFileSync(join(HERE, "../reference/PROVENANCE.json"), "utf8"));
  const readme = readFileSync(join(HERE, "../README.md"), "utf8").replace(/\s+/g, " ");

  const inNote = /downloaded on (\d{4}-\d{2}-\d{2})/.exec(prov.kit_zip_sha256_note);
  assert.ok(inNote, "the provenance note no longer dates the archive it compared against");
  const inReadme = /differs from the archive downloaded on (\d{4}-\d{2}-\d{2})/.exec(readme);
  assert.ok(inReadme, "the README no longer states the archive comparison this test protects");
  assert.equal(inReadme[1], inNote[1],
    "the README and the provenance note name different downloads for the same measurement");

  const cmp = prov.kit_zip_sha256_compared;
  assert.ok(cmp?.downloaded && cmp?.sha256,
    "the provenance records no hash for the archive it says the recorded one differs from");
  assert.equal(cmp.downloaded, inNote[1], "the recorded comparison is dated differently from the note");
  assert.notEqual(cmp.sha256, prov.kit_zip_sha256_downloaded_once,
    "the two archive hashes are equal, so the claim that they differ is false");
});
