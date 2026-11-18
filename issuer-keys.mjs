// The keys a delegation claims to have been signed by, fetched from the agent's own documents.
//
// 5.3 step 1: "Fetches the client metadata from `iss` without following redirects, as the CIMD
// draft (§5) requires, and the public keys from its `jwks_uri` (4.1), following the address
// checks in section 3."
//
// This is the only part of this grader that connects to a host somebody else named, so it is
// written to be refused easily and to be tested without a network. Three rules shape it:
//
//  1. WHOSE FAULT IS IT. The line is bytes. If a response arrived, the outcome is about the
//     agent, because a status code and a body are its own server speaking. If no response
//     arrived (DNS, connection, TLS, timeout, our own size or port policy), the outcome is
//     ours, and the check must abstain with cause "grader" rather than fail the builder. Among
//     responses, only 404 and 410 are the agent's defect: a 401, 403, 429 or 5xx is something
//     a builder can change, and a bot rule in front of a metadata host must never close a door.
//  2. IT MUST NOT BECOME A FLOOD. A failed fetch is remembered and not retried on every
//     request, which the guides ask for in those words, and a lease has a budget of distinct
//     issuers, because whoever holds it can name a new one on every request.
//  3. THE CONNECTION GOES TO THE ADDRESS THAT WAS CHECKED. Resolving and then connecting by
//     hostname lets DNS answer differently the second time, so the checked address is pinned
//     and the hostname is kept only for TLS and Host.
import { classifyAddress, checkTargetUrl } from "./addresses.mjs";

const MAX_BYTES = 100_000;        // the size the guides suggest
const REFETCH_SECONDS = 30;       // the interval the guides suggest
const CACHE_MIN = 60, CACHE_MAX = 24 * 3600;   // the bounds the guides give
const BUDGET = 32;                // distinct issuers one lease may make us fetch
const MAX_KEYS = 50;

const result = (outcome, detail, extra = {}) => ({ outcome, detail, keys: [], kids: [], ...extra });

export function createIssuerKeys({ fetch: doFetch = globalThis.fetch, lookup, now = () => Math.floor(Date.now() / 1000),
                                   maxBytes = MAX_BYTES, refetchSeconds = REFETCH_SECONDS,
                                   budget = BUDGET } = {}) {
  const cache = new Map();        // iss -> { at, expiresAt, outcome, detail, keys, kids, jwksUri }
  const attempts = new Map();     // iss -> { at, outcome, detail }
  const spent = new Set();        // distinct issuers fetched under the current budget

  // One GET, with every refusal that does not need the network decided first.
  async function get(url) {
    const target = checkTargetUrl(url);
    if (!target.allowed) {
      // A scheme, credentials or an internal address is the agent's defect: section 3 and 4.1
      // make those its responsibility. A port we decline is OURS, because 4.1 permits any
      // https URL and only this grader's policy objects.
      const whose = target.kind === "port" ? "grader" : "agent";
      return { whose, detail: target.why };
    }
    let addresses;
    try { addresses = await lookup(target.host); } catch (err) { return { whose: "grader", detail: `could not resolve ${target.host}: ${err.message}` }; }
    if (!addresses || addresses.length === 0)
      // Not the builder's fault: we cannot tell our own resolver from their missing zone, and
      // the sentence names the host so a builder with no such zone recognises it.
      return { whose: "grader", detail: `could not resolve ${target.host}` };
    for (const a of addresses) {
      const c = classifyAddress(a);
      if (!c.allowed)
        return { whose: "agent", detail: `${target.host} resolves to ${a}, a ${c.kind} address, and section 3 forbids connecting to one for a URL the other party gave us` };
    }

    let res;
    try {
      res = await doFetch(target.url, { redirect: "manual", connectTo: addresses[0],
                                        headers: { accept: "application/json" } });
    } catch (err) {
      return { whose: "grader", detail: `${target.url}: ${err?.cause?.code ?? err?.message ?? err}` };
    }
    if (res.redirected || (res.status >= 300 && res.status < 400))
      return { whose: "agent", detail: `${target.url} answered ${res.status}, a redirect, and 5.3 step 1 fetches the client metadata without following redirects` };
    if (res.status === 404 || res.status === 410)
      return { whose: "agent", detail: `${target.url} answered ${res.status}, so the document is not there` };
    if (res.status < 200 || res.status >= 300)
      return { whose: "server", detail: `${target.url} answered ${res.status}, which this grader cannot interpret as a verdict about your agent` };

    const text = await res.text();
    if (text.length > maxBytes)
      return { whose: "grader", detail: `${target.url} returned ${text.length} bytes, larger than the ${maxBytes} this grader reads` };
    let body;
    try { body = JSON.parse(text); } catch { return { whose: "agent", detail: `${target.url} did not return JSON` }; }
    const header = res.headers?.get?.("cache-control") ?? "";
    return { whose: null, body, maxAge: Number(/max-age=(\d+)/.exec(header)?.[1] ?? NaN) };
  }

  async function fetchFor(iss) {
    const meta = await get(iss);
    if (meta.whose) return result(meta.whose, meta.detail);
    // 4.1: "`client_id` MUST equal the URL the document was fetched from."
    if (meta.body?.client_id !== iss)
      return result("agent", `the document at ${iss} names client_id ${JSON.stringify(meta.body?.client_id)}, and 4.1 requires it to equal the URL it was fetched from`);
    const jwksUri = meta.body?.jwks_uri;
    if (typeof jwksUri !== "string" || !jwksUri)
      return result("agent", `the document at ${iss} has no jwks_uri, which 4.1 requires`);
    const jwksTarget = checkTargetUrl(jwksUri);
    if (!jwksTarget.allowed && jwksTarget.kind === "scheme")
      return result("agent", `jwks_uri is ${jwksUri}, and 4.1 requires an HTTPS URL`);

    const set = await get(jwksUri);
    if (set.whose) return result(set.whose, set.detail, { jwksUri });
    const keys = Array.isArray(set.body?.keys) ? set.body.keys.slice(0, MAX_KEYS) : null;
    if (!keys) return result("agent", `${jwksUri} did not return a key set with a keys array`, { jwksUri });

    const maxAge = Number.isFinite(set.maxAge) ? Math.min(Math.max(set.maxAge, CACHE_MIN), CACHE_MAX) : CACHE_MIN;
    return { outcome: "ok", detail: `${keys.length} key(s) from ${jwksUri}`, jwksUri, keys,
             kids: keys.map(k => k?.kid).filter(Boolean), maxAge };
  }

  return {
    // Everything a check needs to decide, attached to the record by the caller.
    async forIssuer(iss) {
      const at = now();
      const hit = cache.get(iss);
      if (hit && at < hit.expiresAt)
        return { ...hit.value, source: "cache", fetchedAt: hit.at, ageSeconds: at - hit.at };

      const failed = attempts.get(iss);
      if (failed && at - failed.at < refetchSeconds)
        return { ...result(failed.outcome, `${failed.detail} (tried at ${failed.at}, and this grader refetches at most once every ${refetchSeconds}s so that a stream of bad delegations cannot flood your server)`),
                 source: "cache", fetchedAt: failed.at, ageSeconds: at - failed.at };

      if (!spent.has(iss) && spent.size >= budget)
        return { ...result("grader", `this run has already made this grader fetch ${spent.size} different issuers, which is its budget`), source: "budget" };

      const value = await fetchFor(iss);
      spent.add(iss);
      if (value.outcome === "ok") {
        cache.set(iss, { at, expiresAt: at + (value.maxAge ?? CACHE_MIN), value });
        attempts.delete(iss);
      } else {
        attempts.set(iss, { at, outcome: value.outcome, detail: value.detail });
      }
      return { ...value, source: "fetch", fetchedAt: at, ageSeconds: 0 };
    },
    // A new lease starts with a fresh budget, and forgets nothing it verified.
    newRun() { spent.clear(); },
    get cached() { return cache.size; },
  };
}
