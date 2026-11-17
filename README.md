# poppy-agent-conformance

Checks that a Company can make about a Personal Agent, against published
[Personal Agent Protocol](https://personalagentprotocol.org) 1.0.

The protocol has two sides. The authors ship a Company kit with a validator, a checklist and
a fake Company, so a Company can check itself. This is the other side: it judges what a
Personal Agent puts on the wire, which only the Company it is talking to can see.

## What it does

Twenty checks over a recorded request log. Eighteen need one Company. Two need two
Companies, because the rules they test are pairwise: a User ID must differ per Company
(spec 5.1) and a delegated key must sign for one User ID only (spec 5.2), so no single
Company can observe either.

Every check carries the sentence of 1.0 it enforces, word for word, and the suite refuses a
check whose quote is not in the specification or not in the section the check names.

## What it does not do

It does not check a Company. The authors kit does that, better and at the right cadence.

It does not detect a User ID derived from personal information. Spec 5.1 forbids deriving
one even with a keyed hash, and the guides allow an HMAC of an internal id with the Company
identifier. A Company cannot tell those apart on the wire, so no check here claims to.

It does not verify a delegation against the signing key published at the agent jwks_uri.
That needs the key set, which the recorder fetches; the check is not written yet.

## Three verdicts, and why

PASS, FAIL, INCONCLUSIVE. The third is not a soft failure. It means the agent never reached
the point the rule governs, and a grader that reports PASS on silence tells a builder they
conform when their agent did nothing. An empty log returns INCONCLUSIVE on every check, and
that is asserted by the suite rather than intended.

A FAIL names the rule, quotes it, and shows the request that decided it.

## Running it

```sh
npm install
npm test
```

The suite proves three things about every check. A conforming agent passes it. One
deliberate breach fails it. An empty log abstains. The map of breaches is asserted to cover
every check, so adding a check without a way to fail it breaks the suite instead of quietly
adding a green light.

Grading a log:

```js
import { grade, gradePair } from "./checks.mjs";

const ctx = { identifier: "https://example.com/poppy", domain: "example.com" };
for (const r of grade(log, ctx)) console.log(r.verdict, r.id, r.why);

// the pairwise rules, with a log from each of two Companies
for (const r of gradePair(logA, logB, ctxA, ctxB)) console.log(r.verdict, r.id, r.why);
```

A log entry is what the Company saw:

```js
{ host, method, url, path, headers, body, at, isResource }
```

`at` is Unix seconds, stamped when the request headers arrived. `url` is absolute and built
from the configured public origin of the Company, not from the Host header, as the protocol
guides advise for a deployment behind a proxy. `isResource` says whether the Session header
was required at all, which spec 5.2 settles from the Company own poppy.json. Get those
wrong and the verdicts are wrong, so they are documented rather than assumed.

## The copy of the specification in spec/

Published 1.0, frozen by the authors on 2026-11-14, captured from their repository at one
commit and verified page by page against the sha256 values they publish themselves.
`spec/PROVENANCE.json` records the commit, the per page hashes and that the verification
passed. `tools/capture-verified.mjs` is what did it, and will do it again for any version.

That matters for a reason beyond tidiness. The specification moved six times in six weeks,
and twice in one day under the same version number before publication became a thing. A
check that quotes a sentence has to say which bytes it read, or the quote is a memory rather
than a citation.

## Status

Early. Twenty checks and 44 tests. It has been run against synthetic traffic and against a
Company of our own on two public hostnames. It has not yet been run against a third party
agent, and no verdict about anyone else software has been published from it.

If you build a Personal Agent and want it graded, open an issue. Reports go to the builder,
not to the public.

## Licence

Apache 2.0, the same as the specification it reads. See LICENSE and NOTICE.
