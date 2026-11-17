# poppy-agent-conformance

Checks that a Company can make about a Personal Agent, against published
[Personal Agent Protocol](https://personalagentprotocol.org) 1.0.

The protocol has two sides. The authors ship a Company kit with a validator, a checklist and
a fake Company, so a Company can check itself. This is the other side: it judges what a
Personal Agent puts on the wire, which only the Company it is talking to can see.

## What it does

Twenty two checks over a recorded request log. Twenty need one Company. Two need two
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
npm test      # needs Node 22.6 or later, for the type stripping the oracle uses
```

The suite proves three things about every check. A conforming agent passes it. One
deliberate breach fails it. An empty log abstains. The map of breaches is asserted to cover
every check, so adding a check without a way to fail it breaks the suite instead of quietly
adding a green light.

It also proves the checks against an implementation we did not write. `reference/jose.ts` is
the signing code from the authors published kit, vendored with its hash recorded, and the
suite mints conforming traffic with it and requires every check to pass. If our grader
failed traffic built by the people who wrote the specification, our grader would be wrong
and not the traffic. The same tests compare our `ath` and our RFC 7638 thumbprint against
theirs, value for value, because a grader whose hashing disagrees would fail every
conforming agent on the key comparison.

That control exists because our own fixture is only our reading of the text. Two
implementations written from one reading agree with each other and disagree with the
specification, which is a thing this project has done before.

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

`record.mjs` builds that entry and is held to the same standard as the checks, because it
decides which rules apply at all and a mistake in it makes every verdict wrong in a way no
check can notice.

`at` is Unix seconds, taken when the request headers arrive rather than when the response
ends, or a long poll on an events route would add its own duration as apparent clock skew.
`url` is absolute and built from the configured public origin, never from the Host header,
which is what the protocol guides advise for a deployment behind a proxy and is required
behind a tunnel, where the origin process sees plain HTTP on a loopback port. `isResource`
is derived from the Company own poppy.json, exactly as spec 5.2 defines the destinations,
and never from the host: the same sentence says that "Sharing a hostname with one of these
URLs doesn't make another URL a Session destination", so a host based rule would fail a
conforming agent for obeying it.

Three rules follow from that and each was learned by getting it wrong. Exclusions are
evaluated before destinations, because the documents 5.2 forbids routinely share a path
prefix with a real one: the specification own example puts the OpenAPI document at the
origin root. Destinations are matched by method and template rather than by prefix, because
5.2 counts "the request URLs its listed APIs describe" and a prefix also matches the
document beside them. Every comparison checks the origin, because a destination hosted at
another provider is a layout the guides describe and comparing paths alone matched our own.

A page on organization.domain is recorded separately, because the header is a SHOULD there
and its absence can never be a failure. A document that must not carry the header is
recorded separately too, so sending a Session JWT to one can be reported at all.

The tests for this use a deliberately overlapping fixture. An earlier fixture put the API
under a path that collided with nothing, and all of its tests passed while the classifier
marked poppy.json, the OpenAPI document, the token endpoint, the OAuth metadata and the
browser session page as Session destinations. Tests whose fixture does not collide prove
the fixture geometry and not the rule.

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

Early. Twenty two checks and 72 tests. It has been run against synthetic traffic and against a
Company of our own on two public hostnames. It has not yet been run against a third party
agent, and no verdict about anyone else software has been published from it.

If you build a Personal Agent and want it graded, open an issue. Reports go to the builder,
not to the public.

## Licence

Apache 2.0, the same as the specification it reads. See LICENSE and NOTICE.
