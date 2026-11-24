// A rule must never fault traffic that is not the agent's.
//
// The recorder is a reverse proxy a builder runs in front of their OWN Company, so the log
// it writes holds whatever reaches that host: the storefront's own scripts, a password reset
// link, the shop's mobile app signing in, a verified crawler. None of it is a Personal Agent
// and no sentence of 1.0 binds it. Three rules read the whole log rather than the agent's
// requests, and on an ordinary shop they fault the shop: a reset link carrying a JWS, the
// store's own password grant, and a Web Bot Auth crawler that signs `@authority` without
// ever sending a Session header.
//
// The property is written over EVERY rule, not the three that were found, because the same
// mistake is available to every rule that starts `for (const r of log)`. The hosted rig has
// the same exposure by a different route: its report is a time slice of the records, so
// anything that reaches the public hostname during a lease is charged to the holder.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS } from "../checks.mjs";
import { recordOf } from "../record.mjs";
import { discoveryFor, templatesOfOpenapi, openapiFor, authServerEndpointsFor } from "../discovery.mjs";

const ORIGIN = "https://shop.example";
const CFG = {
  origin: ORIGIN,
  discovery: discoveryFor(ORIGIN),
  apiOperations: templatesOfOpenapi(openapiFor(ORIGIN), ORIGIN),
  authServerEndpoints: authServerEndpointsFor(ORIGIN),
};

// A JWS the shop itself minted for a password reset. It decodes, because every JWS does.
const RESET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjQyfQ.Zm9vYmFy";

function storeTraffic() {
  const at = 1795000000;
  const reqs = [
    // The shop's own password reset page. No agent, no Session, not a destination.
    [{ method: "GET", url: `/account/reset?token=${RESET}`, headers: { host: "shop.example" } }, null],
    // The shop's own mobile app, at the shop's own auth route, which is NOT the Poppy
    // authorization server. RFC 6749 puts grant_type in a form body and nowhere else, so a
    // rule that looks for one anywhere finds this.
    [{ method: "POST", url: "/wp-json/jwt-auth/v1/token",
       headers: { host: "shop.example", "content-type": "application/x-www-form-urlencoded" } },
     "grant_type=password&username=jane&password=hunter2"],
    // A verified crawler. Web Bot Auth signs `@authority` and `signature-agent`; it has never
    // heard of Poppy and sends no Session header.
    [{ method: "GET", url: "/products/mug",
       headers: { host: "shop.example", "signature-input": 'sig1=("@authority");keyid="k"',
                  signature: "sig1=:YWJj:" } }, null],
    // The storefront's own fetch, to a path the shop did not list for agents.
    [{ method: "GET", url: "/cart.json", headers: { host: "shop.example" } }, null],
  ];
  return reqs.map(([req, body], i) => {
    const r = recordOf(req, CFG, { at: at + i, body, bodyComplete: true });
    r.seq = i + 1;
    r.response = { status: 200 };
    return r;
  });
}

// authDisabled is true because that is what this Company serves, and it is the condition
// under which 3.2's prohibition binds at all.
const CTX = { identifier: `${ORIGIN}/poppy`, domain: "shop.example", authDisabled: true,
              extensions: [], protocolVersion: "1.0" };

test("no rule faults a shop's own traffic, because no sentence of 1.0 binds it", () => {
  const log = storeTraffic();
  // The fixture must really be non-agent traffic, or the property proves nothing.
  for (const r of log) {
    assert.equal(r.headers["poppy-session"], undefined, `${r.path} carries a Session header`);
    assert.equal(r.isResource, false, `${r.path} classified as a destination`);
  }
  const faulted = [];
  for (const c of CHECKS) {
    const v = c.run(log, CTX);
    if (v.verdict === "FAIL") faulted.push(`${c.id}: ${JSON.stringify(v.evidence ?? v.why).slice(0, 90)}`);
  }
  assert.deepEqual(faulted, [],
    `rules faulted a shop for its own traffic:\n  ${faulted.join("\n  ")}`);
});
