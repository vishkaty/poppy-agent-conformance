# poppy-agent-conformance

Checks that a Company can make about a Personal Agent, against published
[Personal Agent Protocol](https://personalagentprotocol.org) 1.0.

The protocol has two sides. The authors ship a Company kit with a validator, a checklist and
a fake Company, so a Company can check itself. This is the other side: it judges what a
Personal Agent puts on the wire, which only the Company it is talking to can see.

## What it does

Twenty four checks over a recorded request log. Twenty two need one Company. Two need
two Companies, because the rules they test are pairwise: a User ID must differ per Company
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

## The server

`server.mjs` is the Company that records. It serves just enough to be a destination, and
its job is to miss nothing, because a request it does not record is a request no rule
examines and that reads as conformance.

So it stamps the arrival time synchronously, before any await and before a byte of body is
read, which a test proves against a deliberately slow response. It records a request whose
body never arrives, marked incomplete, rather than losing it. It records a request Node
refuses before the handler runs, which needs a clientError listener or those requests are
answered by Node and never seen. It distinguishes a body that was never sent from an empty
one, keeps a sha256 of the full body when it truncates a large one, and answers 421 to an
absolute-form target for another authority instead of treating it as a path of its own.

It refuses a configuration that would make the verdicts a statement about our deployment
rather than about the agent: an origin with a path or a trailing slash, or a listed endpoint
with a query or fragment. And it reports every listed destination on an origin it does not
serve, because the specification's own example spreads conversations and an MCP server
across hosts, and a grader that silently cannot see them would report a partial run as a
complete one.

## The report

`report.mjs` builds what a builder reads. Two outputs from one pure function: an object for
diffing two runs after a fix, and a single self contained HTML file for reading, with no
script, no external resource and no dependency.

Its failure modes are not the checks'. Two matter, and the design is shaped by them.

It must not leak a secret while reporting on one. Signatures, access tokens, cookies,
bodies and unknown header values never appear; a private key member inside a delegation is
named and its length given, never its value. Headers are an allowlist, because the next
header somebody invents could hold anything. What identifies a request after redaction is
its ordinal, host, method, path, time, the Session `jti`, and a body hash, which is enough
for a builder to find it in their own logs. A test fills a run with unique sentinels and
requires that none of them, and no compact JWT at all, appears in either output.

And an abstention must never read as a failure. Three verdicts, three unrelated words, and
two different labels for abstaining: not reached by your agent, which the builder can
change, and not judged by this grader, which they cannot. Failures come first because that
is what a builder arrived to find, abstentions second because they are the other thing they
can act on, passes last and collapsed because nothing follows from one. Every abstention
carries a sentence saying what to do differently to reach that rule, and the rules this
grader cannot offer at all say so as our limit rather than their omission.

Every failure names the rule, quotes the sentence of 1.0 it enforces, links the section, and
names the request that decided it. A test requires that of every check, because a failure a
builder cannot trace to a request is one they have to ask us about.

## A run

`rig.mjs` is how a builder actually uses this. It stands up two Companies, because several
sentences of 1.0 can only be judged across two of them: that a User ID differs per Company
and that a delegated key is not shared between them. Locally they are two loopback ports; in
production they are two hostnames, one tunnel ingress rule each, so each Company keeps its
own configured public origin and the public URL is never derived from a Host header.

```
POST /grader/runs            -> 201 with a token, the two origins, and a report link
   ... drive your agent at both origins ...
POST /grader/runs/<token>/end -> freezes the run
GET  /grader/report/<token>   -> the report, HTML, or .json for the same thing as data
```

A run is an exclusive lease, and that choice is the whole design. The alternative was to
attribute each request to a run by the `iss` of its Session JWT, which is tidier and wrong:
the headline failure this grader exists to catch is a request carrying no Session JWT at
all, and such a request has no `iss` to attribute by. Charging another builder's bare
request to your run would produce a wrong FAIL, and a wrong FAIL is the most expensive
output this instrument can produce. So one agent is graded at a time, a second request gets
409 without naming the holder, and the lease expires on its own after fifteen minutes so a
closed laptop does not hold the grader.

Nothing is retained that does not belong to a live run. A request before your lease, or
after your run is frozen, is examined by no rule, and the report says how many there were
rather than leaving the absence to read as conformance. The same goes for a run that sends
more than the per-run limit: counted, and stated.

The report link is the only credential. It is 128 bits, it is not stored (the run is keyed
by its hash), it is never written to any console stream, and the page does not contain it,
so a screenshot cannot leak it and `Referrer-Policy: no-referrer` stops a specification
link on the page from carrying it to someone else's site. A wrong token answers exactly what
an unknown path answers, byte for byte and header for header, so the existence of a report
cannot be probed.

## The canary gate, and the mistake it is for

The worst thing this project could do is misconfigure its own deployment so that every
request fails, and then print a confident red report with a builder's own request
identifiers beside it. So before any lease is granted, the grader drives itself with
conforming traffic minted by the protocol authors' own signing code, and refuses to grade
anybody unless every rule the canary is built to exercise comes back PASS. Not just FAIL:
the quieter failure in this project's history is a check that stops reaching anything and
returns INCONCLUSIVE for ever, so an unreached rule fails the gate exactly as loudly.

The first version of that gate was self-confirming, which is worth stating because it is the
easiest mistake to make here. It built the `htu` claim from the Company's published
discovery document and compared it against the configured origin, as though those were two
independent facts. They are one variable: the document is derived from the origin. A
loopback canary therefore compares a value with itself and passes while the hostname a
builder is given points at nothing, or at the other listener.

So the gate now sends one leg through the public hostname and requires that it arrive at
this Company with the Host it was sent to. That is the only part of the control which is not
a function of the same configuration it is checking, and it is what catches a tunnel whose
ingress rules are swapped, a hostname that resolves to nothing, and a hostname still
pointing at an older process. It also counts what its own traffic reached: if the canary
sends requests to listed destinations and fewer are classified as destinations, the grader
would examine less of a real agent than it claims to, and it says so instead of passing.

Every rule is either in the canary's expected set or in an exclusion list with a reason, and
a test enforces that, so the next check added cannot be quietly forgotten by both.

## Running it

```sh
npm install
npm start     # two Companies on loopback, prints the origins to point your agent at
npm test      # needs Node 22.6 or later, for the type stripping the oracle uses
npm run killtest
```

`npm start` prints one parseable line and nothing secret:

```
ready http://127.0.0.1:53124 http://127.0.0.1:53125 control http://127.0.0.1:53124
```

For a deployment, pass a config file naming the public origin of each Company and the port
it binds. The origin is the URL a builder reaches, which is what `htu` is compared against;
it is never taken from the Host header, because behind a proxy the process sees plain HTTP on
a loopback port and a Host-derived URL would fail every conforming agent.

```json
{
  "lease_seconds": 900,
  "companies": [
    { "origin": "https://poppy.example",  "port": 8787, "trust_forwarded_for": true },
    { "origin": "https://poppy2.example", "port": 8788, "trust_forwarded_for": true }
  ]
}
```

A Company declares its operations once. The OpenAPI document `poppy.json` advertises and the
classifier that decides where the agent went are both built from that one list, because 5.2
counts "the request URLs its listed APIs describe" and holding that as two facts lets them
drift: a path in the document the classifier does not know is a destination an agent is
invited to call and no rule examines, and the reverse fails an agent for calling exactly what
it was told to. A test walks the served document and requires every operation in it to
classify as a destination, with a control so it is not simply passing everything.

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

And it kill-tests itself. `tools/killtest.mjs` breaks each guard on purpose, one line at a
time, and requires a named test to die:

```sh
node tools/killtest.mjs           # every mutation
node tools/killtest.mjs lease     # only the ones whose id matches
```

A mutation that survives means no test covers that guard. A mutation caught only by a test
other than the one named means that test proves something other than what its name says.
Both are reported and both have happened: the first run of this harness found that the mark
deciding which run a request belongs to could be deleted with nothing failing, and that a
test asserting the run token is never logged had cleared its own captured output after
proving the capture worked, which wiped the very line a logged token would have written. It
also found a defect by hanging rather than by failing, which is a finding in itself: an
exception inside the gate left the request with no response at all.

Each mutation writes the original file to a backup before editing and restores any backup
found at startup, because the first version reverted in a `finally` and a killed process
left a mutation in the working tree.

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

## Judged by their code, not only by our reading

`reference/` holds three files from the authors published kit, each with the sha256 of the
archive it came from and of the file itself, which the suite verifies before using them.

`jose.ts` is their signing code. The suite mints conforming traffic with it and requires
every check to pass, so if our grader failed traffic built by the people who wrote the
specification, our grader would be wrong and not the traffic. The same tests compare our
`ath` and our RFC 7638 thumbprint against theirs, value for value.

`schema.ts` and `poppy.schema.json` are their JSON Schema validator and the schema it
applies to a `poppy.json`. Our own discovery document is judged by those rather than by our
reading of section 3.1, and the test proves the check can fail by feeding it the two defects
that refused an earlier Company of ours whole: an extension declared as an object where 1.0
wants an array of version entries, and a conversation protocol entry with no description.
The errors come back in their words, "/extensions/operations must be an array, not an
object" and "/agent/protocols/0/description is required", which is how we know the check
being run is theirs.

Writing that control is what caught the argument order. Their signature is
`validateSchema(schema, value, refs)`, ours was reversed, and validating the schema against
the document produced no errors and read as a pass.

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

Early. Twenty four checks and 116 tests. It has been run against synthetic traffic and against a
Company of our own on two public hostnames. It has not yet been run against a third party
agent, and no verdict about anyone else software has been published from it.

If you build a Personal Agent and want it graded, open an issue. Reports go to the builder,
not to the public.

## Licence

Apache 2.0, the same as the specification it reads. See LICENSE and NOTICE.
