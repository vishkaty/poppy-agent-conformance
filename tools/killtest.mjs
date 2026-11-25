// Break each guard on purpose and require a named test to notice.
//
//   node tools/killtest.mjs            every mutation
//   node tools/killtest.mjs lease      only those whose id contains "lease"
//
// Why this exists. A green suite is evidence of nothing until the tests have been seen to
// fail, and the failure that keeps recurring in this work is a check that cannot fail at all:
// a reversed argument order that always returned zero errors, a field renamed under a check
// that then read undefined for ever, a gate whose range matched no lines. Each mutation below
// is a one line edit that makes a guard wrong in the direction a real defect would, and each
// names the test that must die. A mutation that survives, OR that is caught only by a test
// other than the one named, is reported: the second case means the named test proves
// something other than what it says.
//
// Every edit is applied in place and reverted afterwards. A finally block is not enough: the
// first run of this harness was killed while a test process hung and left a mutation in the
// working tree, so the original content is written to a backup file BEFORE the edit and any
// backup found at startup is restored first. An edit that silently does not apply is itself a
// recorded failure mode of this project, so each one asserts its anchor matched exactly once
// before writing, and the content is read back and compared after reverting.
//
// Each test run has a timeout, because a mutation that makes the grader throw where nothing
// answers the request leaves a test waiting for ever. That is not a harness inconvenience: it
// is a finding, and it is reported as HUNG rather than as a kill.
import { readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Each mutation names the test file that must notice it, so a run stays fast and so a
// mutation cannot be credited to a test in a file that was never executed.
const DEFAULT_FILE = "tests/runs.test.mjs";

export const MUTATIONS = [
  // the canary gate
  { id: "gate/public-route-arrival", file: "rig.mjs", kills: "a hostname routed to the wrong listener",
    find: "if (!arrived)", to: "if (false && !arrived)" },
  { id: "gate/public-route-host", file: "rig.mjs", kills: "arrives with a rewritten Host",
    find: "if (arrived.headers?.host !== leg.host)", to: "if (false)" },
  { id: "gate/reach-count", file: "rig.mjs", kills: "not a destination is counted as a shortfall",
    find: "if (got < c.intended[i])", to: "if (false)" },
  { id: "gate/reach-shortfall", file: "rig.mjs", kills: "narrowed canary cannot pass quietly",
    find: "if (c.shortfall[i])", to: "if (false)" },
  { id: "gate/requires-pass", file: "rig.mjs", kills: "refuses to grade when the grader's own configuration is wrong",
    find: "if (!v || v.verdict !== \"PASS\")", to: "if (false)" },
  { id: "gate/unreached-rule", file: "rig.mjs", kills: "fails the gate as loudly as one that fails",
    find: "if (!v || v.verdict !== \"PASS\")", to: "if (v && v.verdict === \"FAIL\")" },
  { id: "gate/throw-grants", file: "rig.mjs", kills: "canary that throws refuses to grade",
    find: "      const why = String(err?.message ?? err);", to: "      const why = String(err?.message ?? err); return null;" },

  // the lease and attribution
  { id: "lease/not-exclusive", file: "rig.mjs", kills: "a second request while it is held is refused",
    find: "if (granting || liveRun()) {", to: "if (false) {" },
  { id: "lease/never-expires", file: "rig.mjs", kills: "an expired lease is grantable again",
    find: "freeze(active);                       // a builder who closed the tab does not hold the grader",
    to: "return active;" },
  { id: "attribution/ignores-mark", file: "rig.mjs", kills: "attributed by its own mark",
    find: "log: g.records.filter(r => r.seq > run.marks[i]),", to: "log: g.records.slice()," },
  { id: "attribution/keeps-canary", file: "rig.mjs", kills: "graded by nothing",
    find: "if (collector) {", to: "if (false) {" },
  { id: "attribution/no-freeze", file: "rig.mjs", kills: "ending a run freezes it",
    find: "run.ended = now(); run.frozen = true;", to: "run.ended = now();" },
  { id: "limit/unbounded", file: "rig.mjs", kills: "beyond the per-run limit",
    find: "if (run.kept[i] >= maxPerCompany) { run.beyondLimit[i]++; return false; }", to: "" },
  { id: "limit/uncounted", file: "rig.mjs", kills: "beyond the per-run limit",
    find: "{ run.beyondLimit[i]++; return false; }", to: "{ return false; }" },

  // the report and the token
  { id: "privacy/no-referrer-policy", file: "rig.mjs", kills: "headers that keep it private",
    find: "\"cache-control\": \"no-store\", \"referrer-policy\": \"no-referrer\",", to: "\"cache-control\": \"no-store\"," },
  { id: "privacy/no-store", file: "rig.mjs", kills: "headers that keep it private",
    find: "\"cache-control\": \"no-store\",", to: "\"cache-control\": \"public, max-age=60\"," },
  { id: "privacy/token-distinguishable", file: "rig.mjs", kills: "indistinguishable from an unknown path",
    find: "const body = JSON.stringify({ error: \"not_found\" });",
    to: "const body = JSON.stringify({ error: \"not_found\", at: res.req?.url ?? null });" },
  { id: "privacy/token-logged", file: "rig.mjs", kills: "never written to any console stream",
    find: "      runs.set(run.id, run);", to: "      runs.set(run.id, run); console.log(`run ${token}`);" },
  { id: "privacy/token-in-page", file: "rig.mjs", kills: "headers that keep it private",
    find: "      res.end(html);", to: "      res.end(html + `<!-- run ${rep[1]} -->`);" },

  // enforcement: what this Company refuses rather than reports
  { id: "enforce/refuses-documents", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "not a destination is never refused",
    find: "  if (!record || !record.isResource) return null;", to: "  if (!record) return null;" },
  { id: "enforce/wrong-status", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "refused with the error 1.0 names for it",
    find: "const INVALID_SESSION = 400, VERSION_UNSUPPORTED = 400;",
    to: "const INVALID_SESSION = 401, VERSION_UNSUPPORTED = 400;" },
  { id: "enforce/wrong-error-code", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "refused with the error 1.0 names for it",
    find: "    ? { status: VERSION_UNSUPPORTED, error: \"version_unsupported\" }",
    to: "    ? { status: VERSION_UNSUPPORTED, error: \"invalid_session\" }" },
  { id: "enforce/says-session-ended", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "session_ended is never emitted",
    find: "    : { status: INVALID_SESSION, error: \"invalid_session\" };",
    to: "    : { status: INVALID_SESSION, error: \"session_ended\" };" },
  { id: "enforce/precedence-reversed", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "precedence follows the order 5.3 verifies in",
    find: "  for (const id of ENFORCED) {\n    const v = byId.get(id);",
    to: "  for (const id of [...ENFORCED].reverse()) {\n    const v = byId.get(id);" },
  { id: "enforce/no-resource-metadata", file: "enforce.mjs", tests: "tests/enforce.test.mjs",
    kills: "an access token this Company never issued is an OAuth error",
    find: "    + `resource_metadata=\"${String(origin).replace(/\\/+$/, \"\")}/.well-known/oauth-protected-resource\"`;",
    to: "    + ``;" },
  { id: "enforce/no-response-record", file: "server.mjs", tests: "tests/server.test.mjs",
    kills: "status this Company answers and the verdict it records can never disagree",
    find: "    record.response = { status, error: body?.error ?? null };", to: "" },
  { id: "enforce/identifier-issuer-only", file: "discovery.mjs", tests: "tests/discovery.test.mjs",
    kills: "a Company with no issuer still has an identifier",
    find: "  const domain = discovery?.organization?.domain;\n  if (typeof domain === \"string\" && domain) return `https://${domain.toLowerCase()}`.replace(/\\/+$/, \"\");",
    to: "" },
  { id: "gate/accepts-refused-leg", file: "rig.mjs", tests: "tests/runs.test.mjs",
    kills: "refuses to grade when its own conforming traffic is answered with an error",
    find: "  for (const leg of legs ?? []) if (!(leg.status >= 200 && leg.status < 300)) return leg;", to: "" },

  // what an adversarial review of the live deployment found, each reproduced before fixing
  { id: "live/fetch-without-lease", file: "server.mjs", tests: "tests/runs.test.mjs",
    kills: "nothing is fetched while no run is open",
    find: "const verifying = !!issuerKeys && (config.verifyWhen?.() ?? true);", to: "const verifying = !!issuerKeys;" },
  { id: "live/canary-issuer-remembered", file: "rig.mjs", tests: "tests/runs.test.mjs",
    kills: "one request cannot deny every later lease",
    find: "    for (const g of graders) g.issuerKeys?.forget?.(g.canaryClientId);", to: "" },
  { id: "live/no-refetch-on-unknown-kid", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "refetched once when the kid in front of us is not in it",
    find: "      if (hit && at < hit.expiresAt && !stale)", to: "      if (hit && at < hit.expiresAt)" },
  { id: "live/refetches-every-unknown-kid", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "refetched once when the kid in front of us is not in it",
    find: "        && at - hit.at >= refetchSeconds;", to: "        && true;" },
  { id: "live/mixed-address-blames-builder", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "resolves to a public address AND a blocked one is not blamed on the builder",
    find: "      return blocked.length === addresses.length", to: "      return true" },
  { id: "live/unimplemented-note-unconditional", file: "report.mjs", tests: "tests/report.test.mjs",
    kills: "does not tell a builder a rule is unimplemented",
    find: "        ...(all.some(({ r }) => r.issuerKeys?.outcome === \"ok\")", to: "        ...(false" },
  { id: "pin/not-pinned", file: "fetch-pinned.mjs", tests: "tests/fetch-pinned.test.mjs",
    kills: "goes to the pinned address",
    find: "        if (options?.all) return callback(null, [{ address, family }]);\n        return callback(null, address, family);",
    to: "        return require(\"node:dns\").lookup(hostname, options, callback);" },
  { id: "pin/no-size-cap", file: "fetch-pinned.mjs", tests: "tests/fetch-pinned.test.mjs",
    kills: "aborted as it arrives",
    find: "        if (bytes > maxBytes) {", to: "        if (false) {" },
  { id: "pin/no-timeout", file: "fetch-pinned.mjs", tests: "tests/fetch-pinned.test.mjs",
    kills: "never answers is given up on",
    find: "      finish(reject, Object.assign(new Error(`no answer within ${timeoutMs}ms`), { timedOut: true }));",
    to: "      finish(reject, new Error(\"gave up\"));" },
  { id: "pin/cert-unverified", file: "fetch-pinned.mjs", tests: "tests/fetch-pinned.test.mjs",
    kills: "certificate that does not match the name is refused",
    find: "      rejectUnauthorized: true,", to: "      rejectUnauthorized: false," },

  { id: "live/state-on-unverified-claims", file: "server.mjs", tests: "tests/conversations.test.mjs",
    kills: "does not keep conversation state for claims it could not verify",
    find: "        if (issuerKeys && record.issuerKeys?.outcome !== \"ok\") {", to: "        if (false) {" },

  // the resolver: what it fetches, what it refuses, and whose fault each outcome is
  { id: "fetch/addresses-unchecked", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "an address a stranger could aim us at is refused",
    find: ".filter(x => !x.c.allowed);", to: ".filter(x => false);" },
  { id: "fetch/first-address-only", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "one bad address among several refuses the whole fetch",
    find: "const blocked = addresses.map(a => ({ a, c: classifyAddress(a) })).filter",
    to: "const blocked = addresses.slice(0, 1).map(a => ({ a, c: classifyAddress(a) })).filter" },
  { id: "fetch/not-pinned", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "both documents fetched once, keys returned",
    find: "connectTo: addresses[0],", to: "" },
  { id: "fetch/follows-redirect", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "a redirect at the client metadata is the agent's defect",
    find: "    if (res.redirected || (res.status >= 300 && res.status < 400))", to: "    if (false)" },
  { id: "fetch/status-all-agent", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "what the agent's own server said decides whose fault it is",
    find: "      return { whose: \"server\", detail: `${target.url} answered ${res.status}, which this grader cannot interpret as a verdict about your agent` };",
    to: "      return { whose: \"agent\", detail: `${target.url} answered ${res.status}` };" },
  { id: "fetch/transport-blames-builder", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "a transport failure is our fault and never the builder's",
    find: "      return { whose: \"grader\", detail: `${target.url}: ${err?.cause?.code ?? err?.message ?? err}` };",
    to: "      return { whose: \"agent\", detail: `${target.url}: ${err?.cause?.code ?? err?.message ?? err}` };" },
  { id: "fetch/client-id-unchecked", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "a document that is not this client's",
    find: "    if (meta.body?.client_id !== iss)", to: "    if (false)" },
  { id: "fetch/no-size-limit", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "larger than this grader reads",
    find: "    if (text.length > maxBytes)", to: "    if (false)" },
  { id: "fetch/retries-always", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "is not retried on every request",
    find: "      if (failed && at - failed.at < refetchSeconds)", to: "      if (false)" },
  { id: "fetch/no-budget", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "fetch budget for one run is bounded",
    find: "      if (!spent.has(iss) && spent.size >= budget)", to: "      if (false)" },
  { id: "fetch/no-cache", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "does not fetch again, and says it was cached",
    find: "      if (hit && at < hit.expiresAt && !stale)", to: "      if (false)" },
  { id: "fetch/resolves-refused-url", file: "issuer-keys.mjs", tests: "tests/issuer-keys.test.mjs",
    kills: "decided without any lookup",
    find: "    if (!target.allowed) {", to: "    if (false) {" },

  // the SSRF boundary. Every one of these is a way to reach something internal.
  { id: "ssrf/v6-hidden-v4", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "IPv4 forms hidden inside IPv6 are decoded",
    find: "  if (!s.includes(\":\")) return null;", to: "  return null;" },
  { id: "ssrf/loopback", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "every address a stranger could aim us at is refused",
    find: "  [\"loopback\", ([a]) => a === 127],", to: "  [\"loopback\", ([a]) => false]," },
  { id: "ssrf/private", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "every address a stranger could aim us at is refused",
    find: "a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)",
    to: "a === 10" },
  { id: "ssrf/link-local", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "every address a stranger could aim us at is refused",
    find: "  [\"link-local\", ([a, b]) => a === 169 && b === 254],", to: "  [\"link-local\", ([a, b]) => false]," },
  { id: "ssrf/fails-open", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "anything unrecognisable fails closed",
    find: "  if (typeof raw !== \"string\" || !raw) return { allowed: false, kind: \"unparseable\" };",
    to: "  if (typeof raw !== \"string\" || !raw) return { allowed: true, kind: \"public\" };" },
  { id: "ssrf/v6-unparseable-allowed", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "anything unrecognisable fails closed",
    find: "  if (!/^[0-9a-f:]+$/i.test(s) || !s.includes(\":\")) return { allowed: false, kind: \"unparseable\" };",
    to: "  if (false) return { allowed: false, kind: \"unparseable\" };" },
  { id: "ssrf/v6-loopback", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "every address a stranger could aim us at is refused",
    find: "  if (/^(0*:)*0*1$/.test(s)) return { allowed: false, kind: \"loopback\" };", to: "" },
  { id: "ssrf/scheme", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "refused for its scheme, its credentials and its port",
    find: "  if (u.protocol !== \"https:\")", to: "  if (false)" },
  { id: "ssrf/credentials", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "refused for its scheme, its credentials and its port",
    find: "  if (u.username || u.password)", to: "  if (false)" },
  { id: "ssrf/port", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "refused for its scheme, its credentials and its port",
    find: "  if (u.port && u.port !== \"443\")", to: "  if (false)" },
  { id: "ssrf/literal-unchecked", file: "addresses.mjs", tests: "tests/addresses.test.mjs",
    kills: "refused for its scheme, its credentials and its port",
    find: "    if (!literal.allowed)", to: "    if (false)" },

  { id: "retention/disk-not-swept", file: "rig.mjs", tests: "tests/runs.test.mjs",
    kills: "older than the retention window is gone, from disk too",
    find: "          if ((saved.storedAt ?? 0) <= cutoff) rmSync(join(reportsDir, name), { force: true });", to: "" },
  { id: "restart/no-disk-read", file: "rig.mjs", tests: "tests/runs.test.mjs",
    kills: "survives a restart",
    find: "      const run = runs.get(sha(rep[1])) ?? fromDisk(sha(rep[1]));",
    to: "      const run = runs.get(sha(rep[1]));" },

  // the two disclosures that cannot be gated: our own clock, and our own refusal
  { id: "report/hides-stop", file: "report.mjs", tests: "tests/report.test.mjs",
    kills: "the report says so instead of blaming the agent",
    find: "  const stopped = stoppedBy", to: "  const stopped = false && stoppedBy" },
  { id: "report/blames-our-limit", file: "report.mjs", tests: "tests/report.test.mjs",
    kills: "the report says so instead of blaming the agent",
    find: "    if (base?.reachable === false) return base;", to: "" },
  { id: "checks/hides-our-clock", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "an iat failure shows both clocks",
    find: "(your iat ${iat}, our clock ${r.at})", to: "" },
  { id: "checks/claims-constant-offset", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "an iat failure shows both clocks",
    find: "      const constant = offsets.length > 1 && spread <= SKEW_SECONDS;",
    to: "      const constant = offsets.length > 1;" },

  // section 8: the conversation state machine
  { id: "conv/ignores-ownership", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "belonging to someone else, get the same 404",
    find: "    if (!c || c.owner !== owner) return fail(\"conversation_not_found\");",
    to: "    if (!c) return fail(\"conversation_not_found\");" },
  { id: "conv/distinguishable-404", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "belonging to someone else, get the same 404",
    find: "    if (!c || c.owner !== owner) return fail(\"conversation_not_found\");",
    to: "    if (!c) return fail(\"conversation_not_found\");\n    if (c.owner !== owner) return fail(\"conversation_not_found\", `owned by another agent`);" },
  { id: "conv/no-request-id-check", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "no request id, or a message with no content, is invalid_request",
    find: "      if (!validId(body.id))", to: "      if (false)" },
  { id: "conv/id-alphabet-unchecked", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "an id outside the alphabet 8.2 defines is invalid_request",
    find: "const ID_OK = /^[A-Za-z0-9_-]{1,256}$/;", to: "const ID_OK = /^[\\s\\S]*$/;" },
  { id: "conv/wait-unchecked", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a wait that is not a whole number of seconds",
    find: "      if (wait !== null && !/^\\d+$/.test(wait))", to: "      if (false)" },
  { id: "conv/direct-parent-unchecked", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "refused in the four ways 8.10 names",
    find: "        if (!parent || parent.owner !== owner) return fail(\"conversation_not_found\");", to: "" },
  { id: "conv/direct-allows-two", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "refused in the four ways 8.10 names",
    find: "        if (open) return fail(\"direct_conversation_open\", undefined, { conversation_id: open.id });", to: "" },
  { id: "conv/retry-not-idempotent", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a request id makes a retry safe",
    find: "        if (seen.path === path && seen.bodyHash === hash(JSON.stringify(body))) return seen.response;",
    to: "" },
  { id: "conv/no-conflict", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a reused id with a different body is a conflict",
    find: "        return fail(\"request_id_conflict\", \"this request id was accepted with a different path or body (8.3)\");",
    to: "        return seen.response;" },
  { id: "conv/accepts-after-close", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a closed conversation takes no more messages",
    find: "    if (c.closed && route !== \"close\")\n      return remember(fail(\"conversation_closed\"));", to: "" },
  { id: "conv/close-adds-event-twice", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "closing is idempotent", find: "      if (!c.closed) {", to: "      if (true) {" },
  { id: "conv/no-cursor-check", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a read from a cursor returns only later events",
    find: "        if (at === -1) return fail(\"invalid_cursor\");", to: "" },
  { id: "conv/cursor-ignored", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a read from a cursor returns only later events",
    find: "        from = at + 1;", to: "        from = 0;" },
  { id: "conv/no-content-check", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a message with no content, is invalid_request",
    find: "    && [\"text\", \"data\", \"context\", \"extensions\"].some(k => m[k] !== undefined);", to: "    ;" },
  { id: "conv/handoff-says-nothing", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a handoff request is answered",
    find: "      say(c, \"No person is available at this grader", to: "      void (\"No person is available at this grader" },
  { id: "conv/wrong-create-status", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a conversation starts with 201 and an id",
    find: "      return remember({ status: 201, body: { conversation_id: cid } });",
    to: "      return remember({ status: 200, body: { conversation_id: cid } });" },
  { id: "conv/role-not-set", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "a conversation starts with 201 and an id",
    find: "    return add(c, { type: \"message\", message: { id: requestId, role: \"user\", ...rest } });",
    to: "    return add(c, { type: \"message\", message: { id: requestId, ...rest } });" },
  { id: "conv/message-id-invented", file: "conversations.mjs", tests: "tests/conversations.test.mjs",
    kills: "keeps the request's own id",
    find: "    return add(c, { type: \"message\", message: { id: requestId, role: \"user\", ...rest } });",
    to: "    return add(c, { type: \"message\", message: { id: id(\"msg\"), role: \"user\", ...rest } });" },
  { id: "conv/route-confusion", file: "record.mjs", tests: "tests/conversations.test.mjs",
    kills: "closing is idempotent",
    find: '  ["close", "POST", "/{id}/close"],', to: '  ["messages", "POST", "/{id}/close"],' },

  // the recorder's own guards, which the run model now leans on
  { id: "record/control-recorded", file: "server.mjs", kills: "control-plane requests never are",
    find: "    if (config.control && config.control(req, res, rawTarget)) return;",
    to: "    if (config.control && config.control(req, res, rawTarget)) { push(recordOf(req, config, { at })); return; }" },
  { id: "record/no-seq", file: "server.mjs", kills: "during a lease are recorded",
    find: "record.seq = ++seq;", to: "record.seq = 0;" },
  { id: "record/prefix-collision-allowed", file: "server.mjs", kills: "under the control-plane prefix is refused",
    find: "if (prefix && x.origin === parsed.origin && x.pathname.startsWith(prefix))", to: "if (false)" },
  // The refusal a builder reads when a delegation could not be verified. Found by the first run
  // against a agent nobody here wrote, which held a lease and was told to go and get one.
  // 8.3's request ids, added after a conversation POST with none passed every rule here.
  { id: "checks/no-request-id-check", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "a conversation POST with no request id fails",
    find: "      if (noId.length)", to: "      if (false)" },
  { id: "checks/retry-counted-as-reuse", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "still a retry when its body is serialised differently",
    find: "        if (seen && seen !== shape) clashing.push(r);", to: "        if (seen) clashing.push(r);" },
  // The classification fix had a named test and no mutation, which a review caught: a fix nothing
  // can break is a fix nothing proves. A POST to a path a listed OpenAPI describes only for GET
  // used to be reported as a web page, where the Session header is only a SHOULD.
  { id: "checks/post-to-get-path-is-a-page", file: "record.mjs", tests: "tests/record.test.mjs",
    kills: "is not a web page",
    find: "  for (const op of cfg.apiOperations ?? [])\n    if (matchesTemplate(path, op.template))",
    to: "  for (const op of [])\n    if (matchesTemplate(path, op.template))" },
  // Three smaller ones: 8.5's wait, 5.2's sid alphabet, 5.6's tokens in a URL.
  { id: "checks/wait-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "wait that is not a whole number of seconds is faulted",
    find: "      const bad = waits.filter(({ wait }) => !/^\\d+$/.test(wait));",
    to: "      const bad = [];" },
  { id: "checks/wait-allows-fractions", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "wait that is not a whole number of seconds is faulted",
    find: "      const bad = waits.filter(({ wait }) => !/^\\d+$/.test(wait));",
    to: "      const bad = waits.filter(({ wait }) => !/^-?[\\d.]+$/.test(wait));" },
  { id: "checks/sid-alphabet-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "sid outside the alphabet 8.2 defines is faulted",
    find: "      const allowed = /^[A-Za-z0-9_-]{1,256}$/;\n      const bad = sids.filter(v => !allowed.test(v));",
    to: "      const allowed = /^[A-Za-z0-9_-]{1,256}$/;\n      const bad = [];" },
  { id: "checks/url-token-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "Session JWT or a token in a URL is faulted",
    find: "          if (jwt?.header?.alg) { bad.push({ r, what: `${key} carries a JWT` }); continue; }",
    to: "          if (false) { continue; }" },
  { id: "checks/url-token-matches-versions", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "Session JWT or a token in a URL is faulted",
    find: "          if (jwt?.header?.alg) { bad.push({ r, what: `${key} carries a JWT` }); continue; }",
    to: "          if (/^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$/.test(value)) { bad.push({ r, what: `${key} carries a JWT` }); continue; }" },
  // 3.4's Poppy-Extensions.
  { id: "checks/extensions-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "extension the Company does not list is faulted",
    find: "          if (!listed.has(m.name)) bad.push({ r, what: `${JSON.stringify(m.name)} is not an extension this Company lists` });",
    to: "          if (false) bad.push({ r, what: `never` });" },
  { id: "checks/extensions-version-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "extension the Company does not list is faulted",
    find: "          else if (m.version === null) bad.push({ r, what: `${JSON.stringify(m.name)} carries no v parameter, so it does not say which version it uses` });",
    to: "" },
  { id: "checks/extensions-guesses-the-document", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "abstains on what it cannot read",
    find: "      if (!Array.isArray(ctx?.extensions))", to: "      if (false)" },
  { id: "checks/extensions-faults-unreadable", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "abstains on what it cannot read",
    find: "        if (!parsed.length || parsed.some(x => x === null)) { unreadable.push(r); continue; }",
    to: "        if (!parsed.length || parsed.some(x => x === null)) { bad.push({ r, what: \"unreadable\" }); continue; }" },
  // 5.3's operator signature: what it must cover.
  { id: "checks/signature-cover-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "operator signature that does not cover the Session header is faulted",
    find: "        if (!covered.includes(\"poppy-session\")) missing.push(\"poppy-session\");", to: "" },
  { id: "checks/signature-ignores-authorization", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "operator signature that does not cover the Session header is faulted",
    find: "        if (r.headers?.authorization !== undefined && !covered.includes(\"authorization\"))\n          missing.push(\"authorization\");", to: "" },
  { id: "checks/signature-faults-unparseable", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "judges only requests that carry one",
    find: "        if (!covered) { unreadable.push(r); continue; }", to: "        if (!covered) { bad.push({ r, missing: [\"poppy-session\"] }); continue; }" },
  // 8.4's context fields.
  { id: "checks/context-formats-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "context fields are judged by format",
    find: "      const bad = [];\n      for (const { r, message } of shared) {", to: "      const bad = [];\n      for (const { r, message } of []) {" },
  { id: "checks/context-locale-any-string", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "context fields are judged by format",
    find: "        try { Intl.getCanonicalLocales(v); return true; } catch { return false; }",
    to: "        return true;" },
  { id: "checks/context-available-any-type", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "context fields are judged by format",
    find: "        if (c.user_available !== undefined && typeof c.user_available !== \"boolean\")",
    to: "        if (false)" },
  { id: "checks/context-zone-any-string", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "context fields are judged by format",
    find: "        try { new Intl.DateTimeFormat(\"en\", { timeZone: v }); return true; } catch { return false; }",
    to: "        return true;" },
  // 5.2, one delegated key per User within one Company: the half the pairwise rule cannot see.
  { id: "checks/key-per-user-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "signing for two Users at one Company is faulted",
    find: "      const shared = [...usersByKey].filter(([, users]) => users.size > 1);",
    to: "      const shared = [];" },
  { id: "checks/key-per-user-faults-one-user", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "signing for two Users at one Company is faulted",
    find: "      const shared = [...usersByKey].filter(([, users]) => users.size > 1);",
    to: "      const shared = [...usersByKey];" },
  { id: "checks/key-per-user-invents-a-user", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "abstains rather than guessing from what it cannot read",
    find: "        if (!key || typeof user !== \"string\" || user === \"\") continue;",
    to: "        if (!key) continue;" },
  // 3.2, a sign-in at a Company that offers none.
  { id: "checks/signin-grant-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "sign-in grant at a Company that offers no sign-in is faulted",
    find: "      const signIn = grants.filter(({ grant }) => grant !== \"refresh_token\");",
    to: "      const signIn = [];" },
  { id: "checks/signin-faults-a-refresh", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "sign-in grant at a Company that offers no sign-in is faulted",
    find: "      const signIn = grants.filter(({ grant }) => grant !== \"refresh_token\");",
    to: "      const signIn = grants;" },
  { id: "checks/signin-guesses-the-company", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "says nothing unless it knows the Company offers no sign-in",
    find: "      if (ctx?.authDisabled !== true)", to: "      if (false)" },
  { id: "checks/signin-reads-any-body", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "a token request is form encoded, so a JSON body carrying a grant_type is not one",
    find: "        if (r.method !== \"POST\" || !isForm(r)) continue;", to: "        if (r.method !== \"POST\") continue;" },
  // Section 7, the retry rule.
  { id: "checks/retry-not-checked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "resends a request it was told to stop sending is faulted",
    find: "        if (later.length) resent.push(...later);", to: "" },
  { id: "checks/retry-counts-any-later-request", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "resends a request it was told to stop sending is faulted",
    find: "                                      && retryIdOf(x) === key\n                                      && x.rejection?.rule === r.rejection.rule);",
    to: ");" },
  // The false positive this rule shipped with: identity by method, URL and body made every
  // bodyless GET to one path a retry of every other.
  { id: "checks/retry-identity-ignores-the-id", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "are not a retry of each other",
    find: "  try { parsed = JSON.parse(r.body ?? \"\"); } catch { return null; }",
    to: "  try { parsed = JSON.parse(r.body ?? \"\"); } catch { return `${r.method} ${r.path}`; }" },
  { id: "checks/retry-counts-our-own-refusal", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "abstains unless this Company actually refused something under a rule",
    find: "      const refused = log.filter(r => r.rejection?.error === \"invalid_session\" && r.rejection?.rule);",
    to: "      const refused = log.filter(r => r.response?.error === \"invalid_session\");" },
  // 8.4 and 8.8, the message itself: the top of the coverage map.
  { id: "checks/message-content-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "a message with no content is faulted",
    find: "      const FIELDS = [\"text\", \"data\", \"context\", \"extensions\"];",
    to: "      const FIELDS = [\"text\", \"data\", \"context\", \"extensions\", \"author\"];" },
  { id: "checks/message-author-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "whether a person or an AI is speaking is faulted",
    find: "      const ALLOWED = [\"agent\", \"human\"];",
    to: "      const ALLOWED = [\"agent\", \"human\", \"robot\", undefined];" },
  { id: "checks/message-rules-read-cut-bodies", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "accuses an agent over a request this grader could not read",
    find: "    if (r.bodyComplete === false || r.bodyTruncated) { unreadable.push(r); continue; }\n    let parsed = null;\n    try { parsed = JSON.parse(r.body ?? \"\"); } catch { parsed = null; }\n    const m = parsed?.message;",
    to: "    let parsed = null;\n    try { parsed = JSON.parse(r.body ?? \"\"); } catch { parsed = null; }\n    const m = parsed?.message;" },
  { id: "checks/message-rules-judge-unsafe", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "accuses an agent over a request this grader could not read",
    find: "  const posts = log.filter(r => r.method === \"POST\" && r.conversationRoute\n                                && !r.unsafeTarget && !r.refused);",
    to: "  const posts = log.filter(r => r.method === \"POST\" && r.conversationRoute);" },
  // 8.2's alphabet, which closed a disagreement between this Company's own answer and its verdicts.
  { id: "checks/id-format-unchecked", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "outside the alphabet 8.2 allows is caught",
    // The anchor carries the line below it, because the same pattern now appears in the rule about
    // a `sid` and an ambiguous anchor is refused by this harness rather than applied to the wrong
    // rule. That refusal is the feature: it caught exactly this.
    find: "      const allowed = /^[A-Za-z0-9_-]{1,256}$/;\n      const bad = ids.filter",
    to: "      const allowed = /^.*$/s;\n      const bad = ids.filter" },
  { id: "checks/id-format-wrong-bound", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "outside the alphabet 8.2 allows is caught",
    find: "      const allowed = /^[A-Za-z0-9_-]{1,256}$/;\n      const bad = ids.filter",
    to: "      const allowed = /^[A-Za-z0-9_-]{1,255}$/;\n      const bad = ids.filter" },
  { id: "checks/id-format-faults-missing", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "one mistake in a request id is one FAIL, not two",
    find: "        if (typeof parsed?.id === \"string\" && parsed.id !== \"\") ids.push({ r, id: parsed.id });",
    to: "        if (parsed) ids.push({ r, id: parsed.id });" },
  // A rule nobody wrote, dormant because this deployment serves no `web` block by default.
  { id: "checks/browser-page-must-not-carry", file: "record.mjs", tests: "tests/record.test.mjs",
    kills: "not a document 5.2 forbids a Session on",
    find: "  for (const e of cfg.authServerEndpoints ?? []) out.push(e);",
    to: "  for (const e of cfg.authServerEndpoints ?? []) out.push(e);\n  if (d.web?.browser_session_endpoint) out.push(d.web.browser_session_endpoint);" },
  // Each of these made the 8.3 rule accuse a conforming agent, and none of them was caught by a
  // test until an adversarial review built the inputs.
  { id: "checks/request-id-any-post", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "judges conversation routes and nothing else",
    find: "      const posts = log.filter(r => r.method === \"POST\" && r.conversationRoute\n                                    && !r.unsafeTarget && !r.refused);",
    to: "      const posts = log.filter(r => r.method === \"POST\");" },
  { id: "checks/request-id-judges-unsafe", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "refused to classify is not judged",
    find: "                                    && !r.unsafeTarget && !r.refused);", to: ");" },
  { id: "checks/request-id-reads-cut-body", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "whose body this grader could not read",
    find: "        if (r.bodyComplete === false || r.bodyTruncated) { unreadable.push(r); continue; }",
    to: "        if (false) { unreadable.push(r); continue; }" },
  { id: "checks/request-id-global-uniqueness", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "unique for the User, not across Users",
    find: "        const key = `${issOf.get(r) ?? \"\"}\\u0000${user}\\u0000${id}`;",
    to: "        const key = `${issOf.get(r) ?? \"\"}\\u0000${id}`;" },
  { id: "checks/request-id-raw-bytes", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "still a retry when its body is serialised differently",
    find: "        const shape = `${r.path}\\u0000${canonicalJson(parsed)}`;",
    to: "        const shape = `${r.path}\\u0000${r.body}`;" },
  { id: "checks/request-id-guesses-user", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "cannot tell whose request it is",
    find: "        if (user === null || user === undefined) continue;", to: "" },
  // A pass that an agent with no Session JWT at all could earn, found by a run that fetched a
  // document, sent no Session JWT anywhere, and passed.
  { id: "checks/documents-free-pass", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "never sent a Session at all",
    find: "      if (!log.some(r => (r.sessionHeaderCount ?? 0) > 0))", to: "      if (false)" },
  { id: "checks/documents-decodable-only", file: "checks.mjs", tests: "tests/checks.test.mjs",
    kills: "an undecodable Session header sent to a document is still the breach",
    find: "      if (!log.some(r => (r.sessionHeaderCount ?? 0) > 0))",
    to: "      if (!sessionRequests(log).length)" },
  // Guards an adversarial review found unprotected, each now with a named test.
  { id: "recorder/drops-parser-rejections", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "Node refuses before the handler runs is still in the recorded log",
    find: "  server.on(\"clientError\", (err, socket) => {", to: "  server.on(\"neverFires\", (err, socket) => {" },
  { id: "recorder/cannot-stop-streaming", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "stops while a stream is still open",
    find: "        server.closeAllConnections?.();", to: "" },
  { id: "recorder/emits-on-finish", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "abandoned is still written to the log",
    find: "    res.on(\"close\", () => emit(record));", to: "    res.on(\"finish\", () => emit(record));" },
  { id: "recorder/forwards-hop-by-hop", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "do not reach the Company",
    find: "    if (HOP_BY_HOP.has(String(rawHeaders[i]).toLowerCase())) continue;", to: "" },
  // The report, after a review read a recorded one end to end.
  { id: "report/recorded-run-left-open", file: "recorder.mjs", tests: "tests/report.test.mjs",
    kills: "says it is finished",
    find: "  const report = buildReport({ ...run, frozen: true, ended: run.ended ?? Math.floor(Date.now() / 1000) });",
    to: "  const report = buildReport({ ...run });" },
  { id: "report/claims-a-rule-did-not", file: "report.mjs", tests: "tests/report.test.mjs",
    kills: "not also reported as an error no rule claims",
    find: "    !r.rejection && !claimedByARule.has(r)", to: "    !r.rejection" },
  { id: "report/hosted-advice-when-recorded", file: "report.mjs", tests: "tests/report.test.mjs",
    kills: "gives advice that fits",
    find: "    const named = (b) => (recorded && b?.how)", to: "    const named = (b) => (false && b?.how)" },
  // the recorder a builder runs in front of their own Company. Each of these is a way a proxy
  // can quietly change the request it is judging, which would make every verdict a statement
  // about the recorder rather than about the agent.
  { id: "recorder/joined-headers", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "duplicate Poppy-Session headers survive",
    find: "headers: forwardableHeaders(req.rawHeaders) }", to: "headers: req.headers }" },
  { id: "recorder/url-from-host", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "the record is built from the origin",
    find: "const record = recordOf(req, cfg, { at });",
    to: "const record = recordOf(req, { ...cfg, origin: `http://${req.headers.host}` }, { at });" },
  { id: "recorder/at-on-response", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "when the request arrived",
    find: "        record.response = { status: answer.statusCode, error: null };",
    to: "        record.at = Math.floor(Date.now() / 1000);\n        record.response = { status: answer.statusCode, error: null };" },
  { id: "recorder/claims-refusal", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "never as this grader's",
    find: "              if (typeof parsed?.error === \"string\") record.response.error = parsed.error;",
    to: "              if (typeof parsed?.error === \"string\") { record.response.error = parsed.error; record.rejection = { rule: \"invented\" }; }" },
  { id: "recorder/no-unsafe-flag", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "an unsafe target is forwarded",
    find: "if (isUnsafeTarget(record.rawTarget)) {", to: "if (false) {" },
  { id: "recorder/no-body", file: "recorder.mjs", tests: "tests/recorder.test.mjs",
    kills: "the two capture paths agree",
    find: "    if (hasBody) readBody(req, record, maxBody, () => {});",
    to: "    if (false) readBody(req, record, maxBody, () => {});" },
  { id: "refusal/always-says-lease", file: "server.mjs", tests: "tests/conversations.test.mjs", kills: "does not tell the builder to lease one",
    find: "  if (!verifying)\n    return \"lease", to: "  if (true)\n    return \"lease" },
  { id: "refusal/no-reason", file: "server.mjs", tests: "tests/conversations.test.mjs", kills: "says why verification failed",
    find: "return k.detail || ", to: "return \"\" || " },
  { id: "refusal/verifying-always-false", file: "server.mjs", tests: "tests/conversations.test.mjs", kills: "does not tell the builder to lease one",
    find: "const verifying = !!issuerKeys && (config.verifyWhen?.() ?? true);", to: "const verifying = false;" },

  // Scoping the rules that read the whole log. In front of a real shop that log holds the shop:
  // its own reset links, its own app signing customers in, verified crawlers. Each mutation here
  // hands one of those back to a rule, and the shop gets accused of being a failing agent.
  { id: "scope/signin-reads-whole-log", file: "checks.mjs", tests: "tests/not-agent-traffic.test.mjs",
    kills: "no rule faults a shop's own traffic, because no sentence of 1.0 binds it",
    find: "        if (!r.isAuthServer) continue;", to: "" },
  { id: "scope/operator-signature-without-session", file: "checks.mjs", tests: "tests/not-agent-traffic.test.mjs",
    kills: "no rule faults a shop's own traffic, because no sentence of 1.0 binds it",
    find: '                                  && typeof r.headers?.["poppy-session"] === "string");', to: ');' },
  { id: "scope/url-rule-reads-whole-log", file: "checks.mjs", tests: "tests/not-agent-traffic.test.mjs",
    kills: "no rule faults a shop's own traffic, because no sentence of 1.0 binds it",
    find: "        if (!mine(r)) continue;", to: "" },
  { id: "scope/url-rule-claims-pages", file: "checks.mjs", tests: "tests/not-agent-traffic.test.mjs",
    kills: "no rule faults a shop's own traffic, because no sentence of 1.0 binds it",
    find: "      const mine = (r) => r.isResource || r.mustNotCarry",
    to: "      const mine = (r) => r.isResource || r.isPage || r.mustNotCarry" },

  // Keying by the agent. A Session belongs to one User at one Company through one Personal
  // Agent (5.1), so every map on a value the agent picks for itself carries its client_id.
  // Drop it and two agents that both number from one collide; the worst of these told one
  // agent that another agent's signature was a replay of its own.
  { id: "agents/sub-stable-pools-agents", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "no rule faults one agent for a value another agent chose",
    find: "        const e = bySid.get(k) ?? bySid.set(k, { sid, values: new Set(), requests: [] }).get(k);",
    to: "        const e = bySid.get(sid) ?? bySid.set(sid, { sid, values: new Set(), requests: [] }).get(sid);" },
  { id: "agents/version-constant-pools-agents", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "no rule faults one agent for a value another agent chose",
    find: "        const e = bySid.get(k) ?? bySid.set(k, { sid, versions: new Map() }).get(k);",
    to: "        const e = bySid.get(sid) ?? bySid.set(sid, { sid, versions: new Map() }).get(sid);" },
  { id: "agents/jti-pools-agents", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "no rule faults one agent for a value another agent chose",
    find: "        const e = byJti.get(k) ?? byJti.set(k, { jti: j, shapes: new Set(), requests: [] }).get(k);",
    to: "        const e = byJti.get(j) ?? byJti.set(j, { jti: j, shapes: new Set(), requests: [] }).get(j);" },
  { id: "agents/request-id-pools-agents", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "no rule faults one agent for a value another agent chose",
    find: '${issOf.get(r) ?? ""}', to: '' },
  { id: "agents/private-key-cites-every-request", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "a FAIL names only the requests that decided it, not every agent in the log",
    find: "[...new Set(bad)], hits)", to: "[...new Set(bad)], pairs.map(x => x.r))" },
  { id: "agents/alg-cites-every-request", file: "checks.mjs", tests: "tests/two-agents.test.mjs",
    kills: "a FAIL names only the requests that decided it, not every agent in the log",
    find: "[...new Set(bad.map(({ d }) => String(d.header?.alg)))].slice(0, 3), bad.map(({ r }) => r))",
    to: "[...new Set(bad.map(({ d }) => String(d.header?.alg)))].slice(0, 3), pairs.map(({ r }) => r))" },

  // Versions. 3.4 lets a Company serve several at once, and the rule read only the one it
  // prefers, with a major only comparison. Each of these restores one half of that.
  { id: "versions/minor-ignored-before-1.0", file: "discovery.mjs", tests: "tests/versions.test.mjs",
    kills: "3.4 compatibility is the same major, and before 1.0 the same minor",
    find: "  return Number(x[1]) === 0 ? Number(x[2]) === Number(y[2]) : true;", to: "  return true;" },
  { id: "versions/served-set-is-preferred-only", file: "discovery.mjs", tests: "tests/versions.test.mjs",
    kills: "the served set is the preferred version plus every version listed beside it",
    find: "    if (isVersion(v) && !served.includes(v)) served.push(v);", to: "" },
  { id: "versions/unknown-assumed-1.0", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "with no served version known, the rule abstains as OUR limit rather than assuming 1.0",
    find: '        return SKIP("this grader was not told which protocol versions this Company serves, so it cannot say whether a declared version is compatible with one", "grader");',
    to: '        served.push("1.0");' },
  { id: "versions/judge-reads-stored-ctx", file: "recorder.mjs", tests: "tests/versions.test.mjs",
    kills: "a log recorded before the served set existed judges exactly like one recorded after",
    find: "const ctx = run.header?.discovery ? contextOf(run.header.discovery) : run.header?.ctx;",
    to: "const ctx = run.header?.ctx;" },

  // The scoping partition. A sentence of 1.0 may only read a request speaking 1.0; each of
  // these hands 1.0 rules a request they cannot ground a verdict on.
  { id: "versions/scope-ignored", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "a breach under a version this Company serves beside 1.0 is judged by NO rule of 1.0",
    find: '    const seen = c.appliesTo === "every version" ? everyVersion : inScope;',
    to: "    const seen = records;" },
  { id: "versions/incompatible-judged-in-full", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "a version nothing serves is judged by the version rule alone",
    find: '  const inScope = records.filter(r => ["judged", "no-session"].includes(scope.get(r)));',
    to: '  const inScope = records.filter(r => scope.get(r) !== "out-of-scope");' },
  { id: "versions/undeclared-charged-at-pre-0.4-host", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "a Session request with no version is out of scope where a pre-0.4 version is served",
    find: '  if (!isVersion(v)) return served.some(predatesTheHeader) ? "out-of-scope" : "judged";',
    to: '  if (!isVersion(v)) return "judged";' },
  { id: "versions/other-major-judged-as-1.0", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "a breach under a version this Company serves beside 1.0 is judged by NO rule of 1.0",
    find: '  return majorOf(match) === 1 ? "judged" : "out-of-scope";',
    to: '  return "judged";' },

  // A partition that drops records silently is worse than one that judges them wrongly, because
  // the reader cannot see it happen. These two hide it.
  { id: "versions/not-judged-uncounted", file: "report.mjs", tests: "tests/versions.test.mjs",
    kills: "the report counts what it did not judge, and names the versions this Company serves",
    find: "    notJudgedForVersion: outOfScope.length,", to: "    notJudgedForVersion: 0," },
  { id: "versions/not-judged-unsaid", file: "report.mjs", tests: "tests/versions.test.mjs",
    kills: "the report counts what it did not judge, and names the versions this Company serves",
    find: "      + (summary.notJudgedForVersion", to: "      + (false && summary.notJudgedForVersion" },

  // 3.4's recovery after version_unsupported: a new Session and one resend. The first mutation
  // stops the rule faulting anything, the second makes it fault the recovery 3.4 prescribes.
  { id: "versions/recovery-never-faults", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "resending in the SAME Session after version_unsupported is faulted",
    find: "        if (!key || !who) continue;", to: "        continue;" },
  { id: "versions/recovery-ignores-session", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "resending in a NEW Session after version_unsupported is exactly what 3.4 prescribes",
    find: "                                 && retryIdOf(x) === key && seenBy(x) === who));",
    to: "                                 && retryIdOf(x) === key));" },

  // What the log on disk is allowed to hold. The report was always redacted; the file was not.
  { id: "privacy/api-body-kept", file: "record.mjs", tests: "tests/privacy.test.mjs",
    kills: "a shopper body on an ordinary API call is not written to the log",
    find: "  return !!record?.conversationRoute || record?.isAuthServer === true;", to: "  return true;" },
  { id: "privacy/conversation-body-dropped", file: "record.mjs", tests: "tests/privacy.test.mjs",
    kills: "a conversation body IS kept, because four rules read it",
    find: "  return !!record?.conversationRoute || record?.isAuthServer === true;", to: "  return false;" },
  { id: "privacy/body-drop-not-declared", file: "record.mjs", tests: "tests/privacy.test.mjs",
    kills: "a shopper body on an ordinary API call is not written to the log",
    find: "    record.bodyKept = bodyIsKept(record);", to: "    record.bodyKept = undefined;" },
  { id: "privacy/jti-compares-text-again", file: "checks.mjs", tests: "tests/privacy.test.mjs",
    kills: "session.jti-unique still tells two bodies apart when neither body was kept",
    find: '        const bodyKey = r.bodySha256 ?? createHash("sha256").update(r.body ?? "").digest("hex");',
    to: '        const bodyKey = r.body ?? "";' },

  // The two regressions the version partition introduced, found by audit before the push.
  { id: "versions/hosted-claims-unimplemented-version", file: "server.mjs", tests: "tests/versions.test.mjs",
    kills: "the hosted Company refuses to list a version it does not implement",
    find: "    if (!compatible(v, d.protocol_version))", to: "    if (false)" },
  { id: "versions/pair-unpartitioned", file: "checks.mjs", tests: "tests/versions.test.mjs",
    kills: "gradePair honours the partition, so 0.x traffic is not compared across Companies",
    find: "  const a = inScope(logA, ctxA), b = inScope(logB, ctxB);", to: "  const a = logA ?? [], b = logB ?? [];" },

  // Attribution by claimed client_id. Each of these makes one agent answerable for another.
  { id: "attribution/pooled", file: "recorder.mjs", tests: "tests/attribution.test.mjs",
    kills: "an agent's report is a function of its own records alone",
    find: "    const own = companies.map(c => ({ ...c, log: c.log.filter(r => issOf(r) === iss) }));",
    to: "    const own = companies.map(c => ({ ...c }));" },
  { id: "attribution/bare-request-charged", file: "recorder.mjs", tests: "tests/attribution.test.mjs",
    kills: "a request with no decodable Session header belongs to no group and is counted",
    find: '    return typeof iss === "string" && iss ? iss : null;',
    to: '    return typeof iss === "string" && iss ? iss : "nobody";' },
  { id: "attribution/default-groups", file: "recorder.mjs", tests: "tests/attribution.test.mjs",
    kills: "single-agent mode is byte for byte what judge returned before",
    find: '  if (attribution !== "by-issuer") return { run, report: buildRecordedReport(run) };',
    to: '  if (false) return { run, report: buildRecordedReport(run) };' },
];

// Imported for its MUTATIONS list by a test that owns the count in the README. Everything
// below this line runs only when this file is the program.
const RUNNING = process.argv[1] && process.argv[1].endsWith("killtest.mjs");

const picked = process.argv[2]
  ? MUTATIONS.filter(m => m.id.includes(process.argv[2]))
  : MUTATIONS;
if (RUNNING && picked.length === 0) { console.error(`no mutation matches ${process.argv[2]}`); process.exit(2); }

const BACKUP = join(ROOT, ".killtest-backup.json");
if (!RUNNING) { /* imported: stop here, run nothing, touch no file */ } else {

// A mutation left behind by a crashed run would make every later number a statement about
// that edit instead of about the code, so this runs before anything else.
if (existsSync(BACKUP)) {
  const saved = JSON.parse(readFileSync(BACKUP, "utf8"));
  writeFileSync(join(ROOT, saved.file), saved.content);
  rmSync(BACKUP);
  console.log(`restored ${saved.file} from a previous run that did not finish\n`);
}

const TIMEOUT_MS = 90_000;
function runSuite(file = DEFAULT_FILE) {
  try {
    const out = execFileSync(process.execPath,
      ["--experimental-strip-types", "--test", ...String(file).split(" ")],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: TIMEOUT_MS });
    return { failed: false, out };
  } catch (err) {
    if (err.killed || err.signal) return { failed: true, hung: true, out: `${err.stdout ?? ""}` };
    return { failed: true, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

for (const file of new Set(picked.map(m => m.tests ?? DEFAULT_FILE))) {
  const base = runSuite(file);
  if (base.failed) {
    console.error(`${file} does not pass before any mutation, so nothing below would mean anything`);
    console.error(base.out.split("\n").filter(l => l.startsWith("not ok")).join("\n"));
    process.exit(2);
  }
  console.log(`control: ${file} passes unmutated`);
}
console.log("");

let survived = 0, miscredited = 0;
for (const m of picked) {
  const path = join(ROOT, m.file);
  const before = readFileSync(path, "utf8");
  const n = before.split(m.find).length - 1;
  if (n !== 1) {
    console.log(`SKIPPED  ${m.id}: its anchor matched ${n} times in ${m.file}, so the mutation is stale`);
    miscredited++;
    continue;
  }
  try {
    writeFileSync(BACKUP, JSON.stringify({ file: m.file, content: before }));
    writeFileSync(path, before.replace(m.find, m.to));
    const r = runSuite(m.tests ?? DEFAULT_FILE);
    const dead = r.out.split("\n").filter(l => l.startsWith("not ok")).map(l => l.slice(5));
    const named = dead.some(l => l.includes(m.kills));
    if (r.hung) {
      console.log(`HUNG     ${m.id}: the suite did not finish in ${TIMEOUT_MS / 1000}s, so this guard fails by hanging rather than by answering`);
      survived++;
    } else if (m.expect === "survives" && !r.failed) {
      console.log(`EXPECTED ${m.id}: survives, and is recorded as a known gap`);
    } else if (!r.failed) {
      console.log(`SURVIVED ${m.id}: nothing failed, so no test covers this guard`);
      survived++;
    } else if (!named) {
      console.log(`MISCREDITED ${m.id}: caught, but not by "${m.kills}" -- by ${dead.map(d => `"${d.trim()}"`).join(", ")}`);
      miscredited++;
    } else {
      console.log(`killed   ${m.id}  by ${dead.length} test${dead.length === 1 ? "" : "s"}`);
    }
  } finally {
    writeFileSync(path, before);
    // Read back rather than trust the write: this project has a recorded case of a scripted
    // edit that did not apply while its script printed success.
    if (readFileSync(path, "utf8") !== before) {
      console.error(`\n${m.file} was NOT restored. Its original content is in ${BACKUP}.`);
      process.exit(3);
    }
    rmSync(BACKUP, { force: true });
  }
}

console.log(`\n${picked.length} mutations, ${survived} survived or hung, ${miscredited} miscredited or stale.`);
process.exit(survived + miscredited > 0 ? 1 : 0);
}
