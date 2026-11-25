# poppy-agent-conformance

A conformance checker for the agent side of Personal Agent Protocol 1.0. Read `README.md` for
what it does, `docs/PRINCIPLES.md` for what it is held to, `docs/ARCHITECTURE.md` for how it is
built, `CONTRIBUTING.md` before adding a rule.

## Commands

- `npm test` runs every test, about nine seconds. Green is the floor, not the ceiling.
- `npm run killtest` applies every mutation and requires each to be killed by the test named for
  it, about twenty minutes. Run it in a worktree of its own, never the tree you are editing.
- `npm run spec-status` says whether published 1.0 is still byte identical to `spec/`.
- `npm run check` runs the pre push gate and writes every exit code to `.check/`.

## Rules of the house

- A verification result is the content of an exit file, never the status of a compound command.
- A new rule follows the recipe in `CONTRIBUTING.md`; the suite refuses one that skips a step.
- `spec/` is frozen published 1.0 and is never edited by hand.
- This repository names no deployment, no private path and no private note. Fixtures use the
  RFC 2606 example names on purpose.
- No agent or vendor is named by this instrument, in code, in a report or in prose.
- Text in this repository uses no apostrophes and no dashes as punctuation.
