// Is the specification we grade against still the one the authors publish?
//
// This project's premise is that `spec/` is published 1.0, verified page by page against the
// authors' own sha256. Two things can break that premise silently. A published version is
// supposed to be frozen, and if one of its hashes ever moved, every quote in checks.mjs would
// be a quote of text that no longer exists while the suite stayed green. And a newer published
// version makes our verdicts true about an older protocol without saying so.
//
// The fetcher is injected, so the checks themselves are tested rather than the network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { specStatus } from "../tools/spec-status.mjs";

const OURS = { version: "1.0", pages: { spec: { sha256: "aaa" }, guides: { sha256: "bbb" } } };
const live = (entries) => async () => entries;

test("the ordinary case: our version is published, frozen, and current", async () => {
  const s = await specStatus(OURS, live([
    { id: "1.0", published: "2026-11-14", pages: { spec: "aaa", guides: "bbb" } },
  ]));
  assert.equal(s.ok, true, s.problems.join("; "));
  assert.deepEqual(s.problems, []);
  assert.deepEqual(s.draftsInProgress, []);
  assert.deepEqual(s.newerPublished, []);
});

test("a frozen version whose hash moved is the loudest failure there is", async () => {
  // Louder than a new version: it means our quotes are of text the specification no longer
  // has, and nothing in the suite would say so, because the suite checks our quotes against
  // our own copy.
  const s = await specStatus(OURS, live([
    { id: "1.0", published: "2026-11-14", pages: { spec: "CHANGED", guides: "bbb" } },
  ]));
  assert.equal(s.ok, false);
  assert.match(s.problems.join(" "), /spec/);
  assert.match(s.problems.join(" "), /frozen/i);
});

test("a page that disappeared from the published version is also a problem", async () => {
  const s = await specStatus(OURS, live([
    { id: "1.0", published: "2026-11-14", pages: { spec: "aaa" } },
  ]));
  assert.equal(s.ok, false);
  assert.match(s.problems.join(" "), /guides/);
});

test("our version no longer being published at all is a problem, not a silence", async () => {
  const s = await specStatus(OURS, live([{ id: "1.1", published: "2026-12-01", pages: { spec: "x" } }]));
  assert.equal(s.ok, false);
  assert.match(s.problems.join(" "), /1\.0/);
});

test("a newer published version is reported without failing", async () => {
  // Not a failure: our verdicts are still true about 1.0, and they say which version they
  // judge. It is a decision for a person, so it is reported and not acted on.
  const s = await specStatus(OURS, live([
    { id: "1.0", published: "2026-11-14", pages: { spec: "aaa", guides: "bbb" } },
    { id: "1.1", published: "2026-12-01", pages: { spec: "x" } },
  ]));
  assert.equal(s.ok, true, s.problems.join("; "));
  assert.deepEqual(s.newerPublished, ["1.1"]);
});

test("a draft in progress is reported, and is not mistaken for a published version", async () => {
  // A draft has no published date and no hashes: it can change under its own number, which
  // this programme has watched happen three times to one draft in a week. Nothing may be
  // captured from it as though it were frozen.
  const s = await specStatus(OURS, live([
    { id: "1.1", pages: ["spec", "guides"] },
    { id: "1.0", published: "2026-11-14", pages: { spec: "aaa", guides: "bbb" } },
  ]));
  assert.equal(s.ok, true, s.problems.join("; "));
  assert.deepEqual(s.draftsInProgress, ["1.1"]);
  assert.deepEqual(s.newerPublished, [], "a draft was counted as published");
});

test("an unreachable or unparseable index is a problem, never a pass", async () => {
  // The failure mode that matters: a check that answers "nothing has changed" when it could
  // not look.
  for (const broken of [async () => { throw new Error("offline"); }, async () => null, async () => ({})]) {
    const s = await specStatus(OURS, broken);
    assert.equal(s.ok, false, "a check that could not look reported no problem");
  }
});
