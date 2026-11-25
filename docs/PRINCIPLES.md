# Principles

The central idea, and the invariants the code is held to. Each invariant names the test that
holds it, because a principle without a test is a preference.

## The central idea

A verdict is a pure function of a recorded log, and the Company that explains a refusal is
the Company that issued it. Everything else follows from those two sentences.

## Invariants

1. **Every rule quotes the sentence of published 1.0 it rests on, verbatim, inside the section it
   names.** The capture in `spec/` is verified page by page against the hashes the authors
   publish. A rule whose sentence is not in the capture is refused by `tests/quotes.test.mjs`.
2. **Three verdicts, and PASS never on silence.** PASS, FAIL, or INCONCLUSIVE with a cause:
   `unreached` when the agent never reached what the rule governs, `grader` when this instrument
   could not judge it. A rule may not pass a log in which nothing happened. `tests/checks.test.mjs`.
3. **One implementation decides both the refusal and the verdict.** `enforce()` calls the same
   `grade()` the report calls. Only monotone rules may refuse, and only on a destination.
   `tests/monotone.test.mjs`, `tests/enforce.test.mjs`, the six case invariant in
   `tests/server.test.mjs`.
4. **A verdict is reproducible from the file alone.** `judge` needs no network, no configuration
   and not the process that recorded. The served version set, the Company document and the
   context all travel in the log header. `tests/recorder.test.mjs`, `tests/versions.test.mjs`.
5. **A conforming agent is never told it is broken.** Traffic minted by the authors own signing
   code passes every rule it reaches; twelve cases this project once faulted wrongly are kept as
   controls; the hosted Company refuses to grade until its own conforming traffic passes.
   `tests/reference.test.mjs`, `tests/false-fails.test.mjs`, the canary gate in `rig.mjs`.
6. **No rule faults traffic that is not the agent.** The reset links of a shop, its own app and
   verified crawlers are the breach of nobody. `tests/not-agent-traffic.test.mjs`.
7. **No agent is answerable for a value another agent chose.** A Session belongs to one User at
   one Company through one Personal Agent (5.1), so every uniqueness map carries the client_id.
   `tests/two-agents.test.mjs`.
8. **A sentence of 1.0 reads only a request speaking 1.0.** Traffic on a version this Company
   serves under another text is counted and judged by nothing, and the report says so in its
   first sentence. `tests/versions.test.mjs`.
9. **Every rule has a deliberate breach and every guard a named killer.** `tests/breaches.mjs`
   proves each rule can fail; `tools/killtest.mjs` proves each guard matters, crediting only the
   test named for it; `tests/mutations.test.mjs` proves every mutation still points at code.
10. **The log holds only what a rule reads.** The text of a body is kept where a rule reads it
    and hashed everywhere else. `tests/privacy.test.mjs`.
11. **Nothing identifying a subject is published.** No agent or vendor is named by this
    instrument; a report is private to its link; a recorded log is evidence to its owner alone.

## What is deliberately not here

Judging a Company. Judging 0.3 or 0.4. Attributing a bare request to an agent by address or
timing. A fourth verdict. A rule written for the count.
