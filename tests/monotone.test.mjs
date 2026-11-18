// Can this rule be decided on the request in front of you?
//
// The property is monotonicity: a rule FAILS on a one record log and also FAILS inside a log
// of conforming traffic containing that record. It matters for two reasons.
//
// A Company that rejects what it judges decides on one request, because that is all it has
// when it must answer. If a rule fails alone and passes in company, the status code and the
// report would disagree about the same request, which is the class of defect this project
// has already removed twice by deriving two things from one source.
//
// And it is a hole in the report on its own. version.constant failed a request that carried
// no Poppy-Version when that request was alone, and PASSED it when another Session in the
// same run had carried the header, so an agent that never sent the header on one of its
// Sessions was told it conformed. 3.4 is per request: "On every request with the Session
// header (5.2), the Personal Agent sends the protocol version it implements".
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS, grade } from "../checks.mjs";
import { ENFORCED, ENFORCE_EXCLUDED } from "../enforce.mjs";
import { BREACH, conforming, keys } from "./breaches.mjs";
import * as f from "./fixture.mjs";

// The lists live in enforce.mjs, with the product code that acts on them, so there is one
// place where a rule is declared decidable on a single request. A second copy here would be
// the duplication this file exists to prevent.
export const PER_REQUEST = ENFORCED;
export const NEEDS_HISTORY = ENFORCE_EXCLUDED;
test("every check is either decidable on one request or says why it is not", () => {
  const ids = CHECKS.map(c => c.id);
  for (const id of PER_REQUEST) assert.ok(ids.includes(id), `PER_REQUEST names a check that does not exist: ${id}`);
  for (const id of Object.keys(NEEDS_HISTORY)) assert.ok(ids.includes(id), `NEEDS_HISTORY names a check that does not exist: ${id}`);
  for (const id of ids)
    assert.ok(PER_REQUEST.includes(id) || NEEDS_HISTORY[id],
      `${id} is in neither list, so nothing has decided whether a Company could act on it`);
  for (const [id, why] of Object.entries(NEEDS_HISTORY))
    assert.ok(String(why).length > 40, `the reason given for ${id} does not say anything`);
  assert.deepEqual([...new Set(PER_REQUEST)], PER_REQUEST, "a rule is listed twice");
});

test("a per-request rule fails the same request alone and in company", async () => {
  // The whole property, in one loop. A rule that fails alone and passes inside conforming
  // traffic cannot be acted on, and is reporting the breach only by accident of what else
  // the agent happened to send.
  const notMonotone = [];
  for (const id of PER_REQUEST) {
    const breach = await BREACH[id]();
    const alone = grade(breach, f.ctx).find(x => x.id === id);
    const inCompany = grade([...conforming, ...breach], f.ctx).find(x => x.id === id);
    if (alone.verdict !== "FAIL")
      notMonotone.push(`${id}: its breach does not fail on its own (${alone.verdict}: ${alone.why})`);
    else if (inCompany.verdict !== "FAIL")
      notMonotone.push(`${id}: fails alone and ${inCompany.verdict} among conforming traffic (${inCompany.why})`);
  }
  assert.deepEqual(notMonotone, [], notMonotone.join("\n"));
});

test("a rule needing history is not expected to be monotone, and is not treated as if it were", async () => {
  // The control. Without it the loop above could pass by listing nothing interesting, and the
  // split of version.constant would look like a formality rather than a fix.
  const breach = await BREACH["version.constant"]();
  const alone = grade(breach, f.ctx).find(x => x.id === "version.constant");
  assert.equal(alone.verdict, "FAIL", "the historical version rule cannot even fail on its own breach");
  const noHeader = await f.request(keys, { sid: "sid-lonely", version: null });
  const other = await f.request(keys, { sid: "sid-other", version: "1.0" });
  const mixed = grade([noHeader, other], f.ctx).find(x => x.id === "version.constant");
  assert.notEqual(mixed.verdict, "FAIL",
    "version.constant now fails a missing header, which is version.sent's rule, so the two overlap");
  const sent = grade([noHeader, other], f.ctx).find(x => x.id === "version.sent");
  assert.equal(sent.verdict, "FAIL",
    "nothing fails a request that carried a Session header and no Poppy-Version");
});
