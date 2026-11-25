// The fixture must carry every field the recorder produces.
//
// It builds records by hand, and five times it silently omitted a field the recorder had just
// started producing, so a rule reading that field saw undefined and the test that depended on it
// passed for free. The last two were isAuthServer and bodyKept, each at two construction sites.
// A field added to record.mjs now fails here until the fixture carries it, or until it is named
// below with the reason a hand built record may leave it out.
import { test } from "node:test";
import assert from "node:assert/strict";
import { recordOf } from "../record.mjs";
import { discoveryFor, templatesOfOpenapi, openapiFor, authServerEndpointsFor } from "../discovery.mjs";
import * as f from "./fixture.mjs";

// Fields a hand built record may legitimately lack, each with its reason.
const MAY_OMIT = {
  remoteAddress: "the fixture models no socket; the report hashes it and no rule reads it",
  misdirected: "an absolute form target for another authority is a capture concern, not a rule input",
  classifiedAs: "prose for the report; rules read the flags beside it",
  host: "the report reads it; rules read path and url",
};

test("a fixture record carries every field recordOf produces, or names why not", async () => {
  const ORIGIN = "https://shop.example";
  const cfg = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
                apiOperations: templatesOfOpenapi(openapiFor(ORIGIN), ORIGIN),
                authServerEndpoints: authServerEndpointsFor(ORIGIN) };
  const real = recordOf({ method: "GET", url: "/poppy/orders", headers: { host: "shop.example" } }, cfg, { at: 1 });
  const keys = await f.agentKeys();
  const built = await f.request(keys, {});
  const missing = Object.keys(real).filter(k => !(k in built) && !(k in MAY_OMIT));
  assert.deepEqual(missing, [],
    `recordOf produces fields the fixture does not carry, so a rule reading them is untested: ${missing}`);
});

test("the conforming log's hand built records carry the same fields", async () => {
  // The second construction site. The token request and the discovery fetch in conformingLog are
  // literals, not calls to request(), and isAuthServer was dropped there after being added to
  // request(). Same check, every record.
  const ORIGIN = "https://shop.example";
  const cfg = { origin: ORIGIN, discovery: discoveryFor(ORIGIN),
                apiOperations: templatesOfOpenapi(openapiFor(ORIGIN), ORIGIN),
                authServerEndpoints: authServerEndpointsFor(ORIGIN) };
  const real = recordOf({ method: "GET", url: "/poppy/orders", headers: { host: "shop.example" } }, cfg, { at: 1 });
  const keys = await f.agentKeys();
  const RULE_INPUTS = ["method", "path", "url", "headers", "isResource", "mustNotCarry", "isAuthServer",
                       "sessionHeaderCount", "sessionHeaderDuplicated", "conversationRoute", "at"];
  for (const [i, r] of (await f.conformingLog(keys)).entries())
    for (const k of RULE_INPUTS)
      assert.ok(k in r, `conforming log record ${i} (${r.method} ${r.path}) lacks ${k}, which a rule reads`);
  assert.ok(RULE_INPUTS.every(k => k in real), "the rule input list must itself match recordOf");
});
