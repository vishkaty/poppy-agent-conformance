# Contributing

## Reporting a verdict you believe is wrong

Open an issue with the rule id, the sentence of 1.0 the rule quotes, the request as recorded
(redacted as the report redacts it), and the verdict you expected. A wrong FAIL against a
conforming agent is the most expensive output this instrument can produce and is treated as
the highest priority defect.

## Adding a rule

The suite refuses a rule that skips any step, on purpose.

1. **The sentence.** In `checks.mjs`, an entry with an `id`, a `section` and a `quote` that is
   verbatim in the capture under `spec/` and inside the section named. `tests/quotes.test.mjs`
   checks both. A quote in a comment is checked too.
2. **Three verdicts.** Return PASS, FAIL with evidence and the requests that decided it, or SKIP
   with a reason; SKIP takes a second argument `"grader"` when the gap is ours. Never PASS a log
   in which nothing the rule governs happened.
3. **The breach.** In `tests/breaches.mjs`, one deliberate breach that makes the rule FAIL. If
   the conforming log or the authors signing code cannot reach the rule, say why in
   `CONFORMING_UNREACHED` and `REFERENCE_UNREACHED`.
4. **Enforce or explain.** In `enforce.mjs`, add the id to `ENFORCED` if the rule is monotone and
   decidable on one request, otherwise to `ENFORCE_EXCLUDED` with the reason.
5. **The canary.** In `rig.mjs`, add the id to `CANARY_RULES`, `CANARY_ABSTAINS` or
   `CANARY_EXCLUDED` with the reason the control cannot reach it.
6. **A mutation.** In `tools/killtest.mjs`, at least one mutation that breaks one guard of the
   rule, with `kills` naming the test that must die. Apply it by hand once and watch that test
   fail before trusting it; two tests in this suite passed with their guard removed.
7. **The counts.** The README sentences `tests/quotes.test.mjs` derives will fail until they say
   the new number. Dated history sentences are left as they were.
8. **Predict before deploying.** Write down what the authors validator will report after the
   deploy, then run `run-authors-validator.sh` and compare.

## Working rules

- Node 22.6 or later, for `--experimental-strip-types` on the authors reference code.
- Run `npm run killtest` in a worktree of its own, never the tree being edited: it edits and
  restores source files in place, and a suite run in the same tree meanwhile sees a mutated file.
  It holds `.killtest.lock` while running, and `npm test` refuses to start under that lock. If you
  delegate verification to a tool or an agent, say in so many words that it may not run the kill
  test in a shared tree.
- Multi file scripted edits are applied as one patch, then `git diff --stat` is compared with the
  intended file list. A script that crashed halfway once wrote two files of four.
- Read an exit code from the command itself, written to a file; never through a pipe or a
  chained command.
