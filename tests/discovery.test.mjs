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
