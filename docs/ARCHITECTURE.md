# Architecture

How the instrument is put together, so the design is legible without reading the rules.

## The pipeline

```
request ──► capture ──► record ──► judgement ──► report
            record.mjs   (one      checks.mjs    report.mjs
            server.mjs    shape)   enforce.mjs
            recorder.mjs
```

A request is turned into ONE record shape by `record.mjs`, whichever path captured it. The rules
in `checks.mjs` read records and nothing else. `enforce.mjs` asks `grade()` about one record and
refuses from its answer. `report.mjs` asks `grade()` about a whole log and renders.

## Modules

| Module | Role | Reads | Produces |
|---|---|---|---|
| `record.mjs` | Classifies a request against the Company document and computes every flag a rule may read | the request, the configuration | a record |
| `server.mjs` | The hosted Company: documents, token endpoint, test identities, enforcement, the section 8 conversation routes | | records with `seq`, `refused`, `issuerKeys`, `rejection`, `response` |
| `recorder.mjs`, `record-cli.mjs` | The self run path: a reverse proxy a builder runs in front of their own Company, a JSONL log, an offline `judge` | | records with `seq`, `unsafeTarget`, `response`; never `rejection` |
| `discovery.mjs` | The Company document, OpenAPI templates, metadata, `contextOf`, `compatible`, `isVersion` | the document | `ctx` |
| `checks.mjs` | 39 single Company rules, 2 pairwise rules, `grade`, `gradePair`, `versionScopeOf` | a log and a `ctx` | verdicts |
| `enforce.mjs` | Which rules refuse, which are reported only and why, the error 1.0 names for each | one record | a refusal or null |
| `report.mjs` | Verdict assembly, counts, the first sentence, redaction, HTML | companies, the capture provenance | JSON and HTML |
| `rig.mjs`, `grade.mjs` | Two hosted Companies, the exclusive lease, the canary gate, the control plane | | |
| `issuer-keys.mjs`, `addresses.mjs`, `fetch-pinned.mjs` | Fetching an agent key set with an address allowlist and a pinned DNS answer | `iss`, the delegation `kid` | `record.issuerKeys` |
| `conversations.mjs` | Section 8 state at the hosted Company | a verified Session | 8.13 answers |
| `tools/killtest.mjs`, `tools/spec-status.mjs`, `tools/capture-verified.mjs` | Mutations, the freshness control, the hash verified capture | | |

## The record

One shape, produced by `record.mjs` and extended by whichever path captured it. The fixture in
`tests/fixture.mjs` derives its flags from the same predicates and may not hand set them; it has
handed rules a free pass five times by dropping a field, which is why `tests/fixture.test.mjs`
asserts it carries every key `recordOf` produces.

Produced by `recordOf`: `host`, `method`, `url`, `path`, `at`, `headers`, `body`, `bodyComplete`,
`remoteAddress`, `isResource`, `isPage`, `mustNotCarry`, `isAuthServer`, `classifiedAs`,
`misdirected`, `sessionHeaderCount`, `sessionHeaderDecodable`, `sessionHeaderDuplicated`,
`conversationRoute`. Added by `readBody`: `bodySha256`, `bodyBytes`, `bodyTruncated`, `bodyKept`.
Added by the hosted path: `seq`, `rawTarget`, `refused`, `issuerKeys`, `rejection`, `response`.
Added by the recorder: `seq`, `rawTarget`, `unsafeTarget`, `response`.

## The partition

Before any rule runs, `grade()` decides per record what may read it. No Session header: every
rule, as 3.4 says those carry no version. Compatible with a served 1.x version: every rule.
Compatible with a served 0.x or 2.x version: nothing, counted in the report. Compatible with
nothing served: the three version rules alone, on the warrant of 3.4 line 298. `gradePair` applies
the same partition per log. The hosted Company refuses to list a version it does not implement,
so at a valid hosted configuration no Session request is ever out of scope.

## Things that must change together

- A field added to the record: `record.mjs`, the fixture, the recorder parity test, this file.
- A rule added: its quote and section, a breach in `tests/breaches.mjs`, a decision in
  `enforce.mjs`, a decision in the canary lists in `rig.mjs`, a mutation with a named test, the
  README counts the tests demand. See `CONTRIBUTING.md`.
- A context field: `contextOf` in `discovery.mjs` is the only place; the fixture derives its
  context from it.
- Request identity for a retry: `retryIdOf` in `checks.mjs`, used by the section 7 rule and the
  3.4 recovery rule; never reimplemented.

## Known seams, not yet closed

`refused` (hosted) and `unsafeTarget` (recorder) are one condition under two names.
`rejection` is set only by the hosted path, so the two refusal rules abstain in a recording and
the report does not yet say so. "Carries a Session header" has several spellings across rules.
The 8.2 id alphabet appears in three places. Two implementations combine the verdicts of two
Companies. These are tracked in the private registry.
