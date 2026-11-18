// Traffic that published 1.0 forbids and the checks let through.
//
// Each of these was measured passing every check before the fix. The worst, and the reason
// this file exists: a Session JWT with a destroyed signature passed all thirteen. A grader
// that accepts a forged signature tells a builder with a broken signer that they conform,
// which is the opposite of its purpose and the "check that cannot fail" defect in the one
// place it cannot be tolerated.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { randomUUID } from "node:crypto";
import { grade, gradePair } from "../checks.mjs";
import * as f from "./fixture.mjs";

const keys = await f.agentKeys();
const CTX_A = { identifier: "https://shop.example/poppy", domain: "shop.example" };
const CTX_B = { identifier: "https://other-shop.example/poppy", domain: "other-shop.example" };
const failed = (log, ctx = f.ctx) => grade(log, ctx).filter(x => x.verdict === "FAIL").map(x => x.id);

test("a forged Session JWT signature is caught", async () => {
  // 5.3 step 3: "Verify the Session JWT's signature with the key in the delegation's
  // cnf.jwk". Nothing verified any signature, so this passed thirteen of thirteen.
  const r = await f.request(keys, {});
  const parts = r.headers["poppy-session"].split(".");
  parts[2] = "A".repeat(parts[2].length);
  r.headers["poppy-session"] = parts.join(".");
  assert.ok(failed([r]).includes("session.signature"),
    `a destroyed signature was not caught; FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a Session JWT signed by a key the delegation does not name is caught", async () => {
  // The substance of 5.3 step 3: the delegation is what binds the signer, so a valid
  // signature by an unnamed key is exactly the forgery the step exists to stop.
  const other = await f.agentKeys();
  const dlg = await f.delegation(keys);                      // delegation names keys.jwk
  const jwt = await new SignJWT({
    iss: f.CLIENT_ID, aud: f.IDENTIFIER, sid: "s" + randomUUID(), sub: "u" + randomUUID(),
    htm: "GET", htu: "https://shop.example/poppy/orders",
    iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
  }).setProtectedHeader({ alg: "ES256", typ: "poppy-session+jwt", kid: keys.thumb, poppy_dlg: dlg })
    .sign(other.delegated.privateKey);                       // signed by a different key
  const r = await f.request(keys, {});
  r.headers["poppy-session"] = jwt;
  assert.ok(failed([r]).includes("session.signature"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a delegation carrying a private key member is caught", async () => {
  // 5.2: "It MUST NOT contain private key members."
  const priv = await exportJWK(keys.delegated.privateKey);   // carries `d`
  const dlgCompact = await f.delegation(keys, { payload: { cnf: { jwk: priv } } });
  const r = await f.request(keys, { dlgCompact });
  assert.ok(failed([r]).includes("delegation.no-private-key"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a Session JWT signed after its delegation expired is caught", async () => {
  const now = Math.floor(Date.now() / 1000);
  const dlgCompact = await f.delegation(keys, { iat: now - 7200, exp: now - 3600 });
  const r = await f.request(keys, { dlgCompact, at: now, iat: now });
  assert.ok(failed([r]).includes("delegation.not-expired"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a delegation whose iss differs from the Session's iss is caught", async () => {
  // 5.2: the delegation's "`iss` is the Personal Agent's `client_id`", the same client the
  // Session JWT names, so a mismatch means one of them is somebody else's.
  const dlgCompact = await f.delegation(keys, { payload: { iss: "https://other.example/agent.json" } });
  const r = await f.request(keys, { dlgCompact });
  assert.ok(failed([r]).includes("delegation.iss-matches"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("an empty-string required claim is caught", async () => {
  // Only `=== undefined` was tested, so "" passed as present.
  const r = await f.request(keys, { sub: "", sid: "", jti: "" });
  assert.ok(failed([r]).includes("session.claims-present"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a shared delegated key is caught even when its JWK members are reordered", async () => {
  // Comparing JSON.stringify(cnf.jwk) hid a shared key behind member order or an extra
  // member. RFC 7638 thumbprints are over a fixed set in a fixed order, so they cannot be.
  const jwk = keys.jwk;
  const reordered = { alg: "ES256", y: jwk.y, x: jwk.x, kty: jwk.kty, crv: jwk.crv, kid: "z" };
  const dlgA = await f.delegation(keys);
  const dlgB = await f.delegation(keys, { payload: { cnf: { jwk: reordered } } });
  const a = [await f.request(keys, { dlgCompact: dlgA, sub: "user-a" })];
  const b = [await f.request(keys, { dlgCompact: dlgB, sub: "user-b" })];
  const v = gradePair(a, b, CTX_A, CTX_B).find(x => x.id === "pairwise.delegated-key");
  assert.equal(v.verdict, "FAIL", `a reordered JWK hid a shared key: ${v.why}`);
});

test("ath that does not match the access token is caught", async () => {
  // 5.2: "`ath` is the SHA-256 hash of the access token, base64url-encoded".
  const r = await f.request(keys, { token: "tok-" + randomUUID(), ath: "not-the-hash" });
  assert.ok(failed([r]).includes("session.ath"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a conforming ath is accepted", async () => {
  const token = "tok-" + randomUUID();
  const r = await f.request(keys, { token, ath: f.athOf(token) });
  const v = grade([r], f.ctx).find(x => x.id === "session.ath");
  assert.equal(v.verdict, "PASS", `a correct ath was rejected: ${v.why}`);
});

test("a delegation signed with an algorithm 1.0 does not allow is caught", async () => {
  // 5.2: "`alg` is `ES256` or `PS384`." Nothing checked the delegation's own algorithm, so
  // a delegation signed RS256 passed, which is neither of the two a Company must accept.
  const rsa = await generateKeyPair("RS256", { extractable: true });
  const dlg = await new SignJWT({
    iss: f.CLIENT_ID, iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, jti: randomUUID(), cnf: { jwk: keys.jwk },
  }).setProtectedHeader({ alg: "RS256", typ: "poppy-delegation+jwt" }).sign(rsa.privateKey);
  const r = await f.request(keys, { dlgCompact: dlg });
  assert.ok(failed([r]).includes("delegation.alg"), `FAILs were ${failed([r]).join(", ") || "none"}`);
});

test("a PS384 delegation is accepted, because a Company MUST accept one", async () => {
  // The control for the check above. 5.2: "Companies MUST accept delegations signed with
  // `ES256` and with `PS384`. `PS384` lets a Personal Agent have its delegations signed
  // blindly (10.7)." Failing one would fail a conforming agent using blind signing.
  const rsa = await generateKeyPair("PS384", { extractable: true });
  const now = Math.floor(Date.now() / 1000);
  const dlg = await new SignJWT({
    iss: f.CLIENT_ID, iat: now, exp: now + 3600, jti: randomUUID(), cnf: { jwk: keys.jwk },
  }).setProtectedHeader({ alg: "PS384", typ: "poppy-delegation+jwt" }).sign(rsa.privateKey);
  const r = await f.request(keys, { dlgCompact: dlg });
  const v = grade([r], f.ctx).find(x => x.id === "delegation.alg");
  assert.equal(v.verdict, "PASS", `a PS384 delegation was rejected: ${v.why}`);
});

test("a Session JWT with no delegation is reported under its own rule", async () => {
  // It was reported as a typ failure, which is a misattribution: the defect is that no
  // delegation was sent at all, and 5.2 has its own sentence for it.
  const r = await f.request(keys, { noDlg: true });
  const ids = failed([r]);
  assert.ok(ids.includes("delegation.present"), `FAILs were ${ids.join(", ") || "none"}`);
  assert.ok(!ids.includes("delegation.typ"), "absence must not be reported as a wrong typ");
});
