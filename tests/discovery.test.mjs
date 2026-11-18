// Our own discovery document, judged by the authors' schema validator and their schema.
//
// Not by our reading of section 3.1. An earlier Company of ours was refused whole, twice,
// for document defects our own tests could not see: an extension declared as an object
// where 1.0 wants an array of version entries, and a missing description on a conversation
// protocol entry. Both times the cause was the same, that nothing of ours read their
// schema. This test is that.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { discoveryFor } from "../discovery.mjs";
import { get, post } from "./http.mjs";
import { createGrader } from "../server.mjs";
import { classify } from "../record.mjs";

// What a Company declares once: the operations it offers. The OpenAPI document an agent
// reads and the classifier that judges where the agent went are both built from this, so
// they cannot disagree about what a destination is.
const OPERATIONS = [
  { method: "GET", path: "/poppy/orders", summary: "List the orders of the signed-out session" },
  { method: "GET", path: "/poppy/orders/{id}", summary: "One order" },
  { method: "POST", path: "/poppy/feedback", summary: "Leave feedback about this grader" },
];

const HERE = dirname(fileURLToPath(import.meta.url));
const { validateSchema, formatSchemaErrors } = await import("../reference/schema.ts");
// Their signature is validateSchema(schema, value, refs). Getting it the wrong way round
// validates the schema against the document, which produced no errors and read as a pass:
// a vacuous check of exactly the kind this project exists to catch. The strictness control
// below is what caught it, which is the argument for writing controls before trusting a
// green result.
const SCHEMA = JSON.parse(readFileSync(join(HERE, "../reference/poppy.schema.json"), "utf8"));
// The third argument is a registry keyed by file name, as their own check() passes it.
const REFS = { "poppy.schema.json": SCHEMA };

test("the vendored schema and validator are the files their provenance claims", () => {
  const prov = JSON.parse(readFileSync(join(HERE, "../reference/PROVENANCE.json"), "utf8"));
  for (const [file, rec] of Object.entries(prov.files)) {
    const got = createHash("sha256").update(readFileSync(join(HERE, "../reference", file))).digest("hex");
    assert.equal(got, rec.sha256, `reference/${file} does not match its recorded hash`);
  }
});

test("our poppy.json satisfies the authors' schema", () => {
  const errors = validateSchema(SCHEMA, discoveryFor("https://shop.example"), REFS);
  assert.deepEqual(formatSchemaErrors(errors), [],
    "their schema refuses our document, so their validator would refuse it whole");
});

test("it satisfies the schema on a non-default port too", () => {
  // 3.1 requires the port in `domain` when it is not 443, and their domain pattern accepts
  // one since 1.0. A rig on a port must still produce a valid document.
  const errors = validateSchema(SCHEMA, discoveryFor("https://shop.example:8443"), REFS);
  assert.deepEqual(formatSchemaErrors(errors), []);
  assert.equal(discoveryFor("https://shop.example:8443").organization.domain, "shop.example:8443");
});

test("the schema is strict enough to catch the two defects that caught us before", () => {
  // The control. If their schema accepted these, this test would prove nothing about it.
  const asObject = discoveryFor("https://shop.example");
  asObject.extensions = { operations: { version: "3" } };          // object, not an array
  assert.notDeepEqual(formatSchemaErrors(validateSchema(SCHEMA, asObject, REFS)), [],
    "their schema did not catch an extension declared as an object");

  const noDescription = discoveryFor("https://shop.example");
  delete noDescription.agent.protocols[0].description;
  assert.notDeepEqual(formatSchemaErrors(validateSchema(SCHEMA, noDescription, REFS)), [],
    "their schema did not catch a protocol entry with no description");
});

// The two documents a conforming agent fetches BEFORE it will use poppy.json at all.
//
// 3.2: "Before using a Company's poppy.json, the Personal Agent fetches the metadata and
// MUST check that its issuer exactly matches the issuer it found, character for character.
// It MUST also check that protected_resources includes https://{organization.domain}."
//
// Our Company declared auth.issuer and answered 404 to both, so a conforming agent would
// have refused the document and sent no Session JWT at all. The grader would have recorded
// nothing and reported every rule as not reached, which reads as the builder's fault.
import { resourceMetadataFor, authServerMetadataFor } from "../discovery.mjs";

test("the domain's protected resource metadata names the domain exactly", () => {
  const m = resourceMetadataFor("https://shop.example");
  assert.equal(m.resource, "https://shop.example",
    "3.2: its resource MUST be exactly https://{organization.domain}, with no path or trailing slash");
  assert.deepEqual(m.authorization_servers, ["https://shop.example/poppy"],
    "and its authorization_servers, when nonempty, names the issuer");
});

test("it carries the port when the host has one, like the domain does", () => {
  const m = resourceMetadataFor("https://shop.example:8443");
  assert.equal(m.resource, "https://shop.example:8443");
});

test("the issuer metadata matches the issuer character for character", () => {
  const m = authServerMetadataFor("https://shop.example");
  assert.equal(m.issuer, "https://shop.example/poppy");
});

test("the issuer metadata lists the domain in protected_resources with no trailing slash", () => {
  // The guides call this "the required field an existing issuer is most likely to be
  // missing", so a grader that omitted it would be modelling the common defect rather than
  // the rule.
  const m = authServerMetadataFor("https://shop.example");
  assert.ok(m.protected_resources.includes("https://shop.example"),
    `protected_resources is ${JSON.stringify(m.protected_resources)}`);
  for (const r of m.protected_resources)
    assert.ok(!r.endsWith("/") && !new URL(r).pathname.replace(/^\//, ""),
      `${r} has a path or trailing slash, which 3.2 forbids`);
});

test("the issuer metadata declares no sign-in grant, because this grader offers none", () => {
  // 3.2 ties the offered sign-in types to grant_types_supported, so advertising a grant we
  // do not implement would make the grader itself nonconformant and send a builder's agent
  // down a path that cannot complete.
  const m = authServerMetadataFor("https://shop.example");
  assert.ok(!m.grant_types_supported.includes("authorization_code"));
  assert.ok(!m.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:device_code"));
});

test("the OpenAPI document the discovery advertises is actually served", async () => {
  // Without it a conforming agent fetches poppy.json, follows apis[].url, gets 404, and has
  // no operation to call. Every API rule would then be unreachable for our reason.
  const g = createGrader({ origin: "http://127.0.0.1", operations: OPERATIONS });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const url = g.config.discovery.apis.find(a => a.type === "openapi").url;
    const res = await fetch(url);
    assert.equal(res.status, 200, `${url} is advertised and not served`);
    assert.match(res.headers.get("content-type"), /json/);
    const doc = await res.json();
    assert.match(doc.openapi, /^3\./);
    assert.ok(Object.keys(doc.paths ?? {}).length > 0, "the document describes no operation");
    assert.equal(doc.servers?.[0]?.url, `http://127.0.0.1:${port}`,
      "the document names a different server than the one serving it");
  } finally { await g.close(); }
});

test("the document and the classifier cannot disagree about what a destination is", async () => {
  // 5.2 counts "the request URLs its listed APIs describe", so these are one fact. Held as
  // two, a path in the document that the classifier does not recognise is a destination an
  // agent is invited to call and no rule examines, and the reverse fails an agent for
  // calling something never advertised.
  const g = createGrader({ origin: "http://127.0.0.1:8080", operations: OPERATIONS });
  try {
    const doc = g.config.openapi;
    const described = [];
    for (const [path, ops] of Object.entries(doc.paths))
      for (const method of Object.keys(ops)) described.push([method.toUpperCase(), path]);
    assert.ok(described.length >= 2, `the document describes only ${described.length} operations`);

    for (const [method, template] of described) {
      const url = `http://127.0.0.1:8080${template.replace(/\{[^}]*\}/g, "1")}`;
      const c = classify(url, method, g.config);
      assert.equal(c.isResource, true, `${method} ${template} is described and not classified: ${c.why}`);
    }
    // and the control, so this is not just "everything is a destination"
    assert.equal(classify("http://127.0.0.1:8080/not-described", "GET", g.config).isResource, false);
    assert.equal(classify(`http://127.0.0.1:8080${described[0][1]}`, "DELETE", g.config).isResource, false,
      "a method the document does not describe was classified as a destination");
  } finally { await g.close(); }
});

test("every URL this Company publishes on its own origin is served", async () => {
  // The general form of a defect the authors' own validator found in us twice: poppy.json
  // advertised an OpenAPI document that nothing served, and a browser session endpoint that
  // nothing served. An agent that follows our document and gets a 404 has reached a dead end
  // we created, and every rule beyond it is reported as not reached by the agent.
  const g = createGrader({ origin: "http://127.0.0.1", operations: OPERATIONS });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const d = g.config.discovery;
    const urls = [
      `${g.config.origin}/.well-known/poppy.json`,
      ...(d.apis ?? []).map(a => a.url),
      ...(d.agent?.protocols ?? []).map(p => p.endpoint),
      ...(d.web?.browser_session_endpoint ? [d.web.browser_session_endpoint] : []),
      ...(d.tasks?.endpoint ? [d.tasks.endpoint] : []),
      ...Object.values(d.extensions ?? {}).flat().map(e => e.endpoint),
      ...Object.values(d.supported_versions ?? {}),
    ].filter(u => u && u.startsWith(g.config.origin));

    const dead = [];
    for (const url of urls) {
      // A GET on a POST-only endpoint is not a dead end, so 405 and 404 are told apart.
      const res = await fetch(url);
      if (res.status === 404) dead.push(`${url} -> 404`);
    }
    assert.deepEqual(dead, [], "this Company advertises URLs it does not serve");
  } finally { await g.close(); }
});

test("a Company with no issuer still has an identifier, and it is the one 3.2 names", async () => {
  // 3.2: "The Company's identifier is its issuer when it has one, and otherwise
  // `https://{organization.domain}`, with the host in lowercase and no trailing slash."
  // 3.2 also allows having no issuer at all: "A Company without one can offer signed-out
  // Sessions, including APIs, conversations, feedback, and browser join, without running an
  // authorization server." Reading only `auth.issuer` meant such a Company compared every
  // `aud` against undefined, which fails every conforming agent for our reason.
  const { identifierOf } = await import("../discovery.mjs");
  assert.equal(identifierOf({ organization: { domain: "shop.example" },
                              auth: { issuer: "https://shop.example/poppy" } }),
               "https://shop.example/poppy", "an issuer must win when there is one");
  assert.equal(identifierOf({ organization: { domain: "Shop.Example" } }),
               "https://shop.example", "no issuer: the https domain, lowercased");
  assert.equal(identifierOf({ organization: { domain: "shop.example:8443" } }),
               "https://shop.example:8443", "a port belongs to the domain (3.1)");
  assert.equal(identifierOf({ organization: { domain: "shop.example" }, auth: {} }),
               "https://shop.example");
  assert.equal(identifierOf({}), null, "nothing to go on must be null, not a broken string");
});

test("a conforming agent at a Company with no issuer is not failed on aud", async () => {
  // The consequence, end to end through the recorder and the checks.
  const { grade } = await import("../checks.mjs");
  const ref = await import("../reference/jose.ts");
  const { identifierOf } = await import("../discovery.mjs");
  const noIssuer = (origin) => {
    const d = discoveryFor(origin);
    const { auth, ...rest } = d;
    return rest;
  };
  const g = createGrader({ origin: "http://127.0.0.1", discovery: noIssuer, operations: OPERATIONS });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const d = g.config.discovery;
    assert.equal(d.auth, undefined, "the fixture still declares an issuer");
    const id = identifierOf(d);
    const operator = await ref.generateKey(), key = await ref.generateKey();
    const delegation = await ref.signDelegation({ root: operator, delegated: key.publicJwk,
                                                  iss: "https://agent.example/agent.json" });
    const jwt = await ref.signSessionJwt({ key, delegation, iss: "https://agent.example/agent.json",
      aud: id, sid: ref.randomId(16), sub: ref.randomId(16),
      method: "GET", url: `${g.config.origin}/poppy/orders` });
    await fetch(`${g.config.origin}/poppy/orders`,
                { headers: { "poppy-session": jwt, "poppy-version": "1.0" } });
    const v = grade([g.records.at(-1)], { identifier: id, domain: d.organization.domain })
      .find(x => x.id === "session.aud");
    assert.equal(v.verdict, "PASS", `${v.verdict}: ${v.why}`);
  } finally { await g.close(); }
});

test("sign-in is declared off the way 3.2 says, and the token endpoint behaves as 3.2 allows", async () => {
  // This Company has an issuer, so that `aud` is an issuer like the ones builders will meet,
  // and offers no sign-in at all. 3.2 has a field for exactly that: "A Company that has an
  // issuer but offers Personal Agents no sign-in sets `auth.disabled` to `true`."
  //
  // And it says what such a Company does at its token endpoint: "A Company that sets
  // `auth.disabled` and has never issued a refresh token to a Personal Agent has no tokens to
  // protect: it answers every refresh with `invalid_grant` (RFC 6749 §5.2) and every
  // revocation with success (RFC 7009 §2.2). It MAY do so without verifying the client
  // assertion (4.1)." Before this, both endpoints were advertised in the OAuth metadata and
  // answered 404, which is the same dead end as an unserved OpenAPI document.
  const g = createGrader({ origin: "http://127.0.0.1", operations: OPERATIONS });
  const port = await g.listen(0);
  g.setOrigin(`http://127.0.0.1:${port}`);
  try {
    const d = g.config.discovery;
    assert.equal(d.auth.disabled, true, "poppy.json does not declare sign-in off");
    assert.ok(d.auth.issuer, "the issuer is still needed, because it is the Company's identifier");

    const meta = await (await fetch(`${g.config.origin}/.well-known/oauth-authorization-server/poppy`)).json();
    const token = await post(meta.token_endpoint, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=refresh_token&refresh_token=whatever",
    });
    assert.equal(token.status, 400, token.text);
    assert.equal(token.body?.error, "invalid_grant", token.text);

    const revoke = await post(meta.revocation_endpoint, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "token=whatever",
    });
    assert.equal(revoke.status, 200, `revocation answered ${revoke.status}, and RFC 7009 §2.2 makes it a success`);

    // 5.2: "Discovery and description documents and OAuth endpoints don't carry this header."
    // So a Session header arriving here is a breach session.not-on-documents must judge, which
    // means these paths have to be classified as OAuth endpoints and not as nothing.
    for (const url of [meta.token_endpoint, meta.revocation_endpoint]) {
      const c = classify(url, "POST", g.config);
      assert.equal(c.mustNotCarry, true, `${url} is not classified as an OAuth endpoint: ${c.why}`);
      assert.equal(c.isResource, false, `${url} was classified as a Session destination`);
    }
  } finally { await g.close(); }
});
