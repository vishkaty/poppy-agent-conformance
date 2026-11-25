# Changelog

Rule set history. Counts are derived by tests at each commit; these are the shape of the changes.

## Unreleased, at d1a52f3

- The hosted Company refuses to list a version it does not implement; a forged Session declaring a
  listed but unimplemented version was answered 201 before this.
- `gradePair` applies the version partition per log.
- The text of a body is kept in the log only where a rule reads it; everything else keeps a hash
  over every byte and its length.
- Rule 41, `version.new-session-after-unsupported`, on 3.4 recovery.
- The report counts and names what it deliberately did not judge, in its first sentence.
- A sentence of 1.0 reads only a request speaking 1.0; 0.x traffic is judged by nothing.
- The 3.4 compatibility predicate in full, over every version the Company serves; one `contextOf`
  where three disagreed; `judge` rebuilds context from the document in the log header.
- Uniqueness maps keyed by client_id; two delegation rules cite only the request that decided.
- Three rules scoped to agent traffic; a shop is no longer faulted for its own reset links, its
  own app or verified crawlers.
- `tests/mutations.test.mjs`: a stale or ambiguous mutation anchor fails in milliseconds.

## 2026-11-24, 7f9c3d6 (live)

- Rules 30 to 40 from the coverage map; README counts owned by tests; `adewale/pda` named as
  prior art.

## 2026-11-20 to 2026-11-23

- The recorder: a reverse proxy a builder runs in front of their own Company, judged offline.
- Rules 28 and 29 on conversation request ids.
- A public test identity so delegation verification can be exercised end to end.
- Filed #118 and #119.

## 2026-11-18

- Enforcement from the same `grade()` call the report uses; only monotone rules refuse.
- Delegation verification against the agent `jwks_uri`, with an address allowlist and a pinned
  DNS answer.

## 2026-11-17

- Public, Apache 2.0, with twenty rules and the hash verified 1.0 capture.
