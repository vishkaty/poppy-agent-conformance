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
