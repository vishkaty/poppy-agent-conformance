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
import { pinnedGet } from "./fetch-pinned.mjs";

const MAX_BYTES = 100_000;        // the size the guides suggest
const TIMEOUT_MS = 5_000;        // "a timeout of a few seconds", likewise
const REFETCH_SECONDS = 30;       // the interval the guides suggest
const CACHE_MIN = 60, CACHE_MAX = 24 * 3600;   // the bounds the guides give
const BUDGET = 32;                // distinct issuers one lease may make us fetch
const MAX_KEYS = 50;

const result = (outcome, detail, extra = {}) => ({ outcome, detail, keys: [], kids: [], ...extra });

// The default transport is the PINNED one, not global fetch.
//
// It used to be global fetch with a `connectTo` option, which Node does not have and ignores
// in silence, so the address this file had just checked was not the address it connected to.
// The only test asserted that a fake fetch had recorded the option, so the suite was green
// over a defence that did not exist. A test injects a transport; nothing else should.
export function createIssuerKeys({ fetch: doFetch = pinnedGet, lookup, now = () => Math.floor(Date.now() / 1000),
                                   maxBytes = MAX_BYTES, refetchSeconds = REFETCH_SECONDS,
                                   budget = BUDGET, timeoutMs = TIMEOUT_MS } = {}) {
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
    // Section 3 forbids CONNECTING to a loopback, private or link-local address for a URL the
    // other party gave us. It does not say the other party is at fault, and this rule is
    // enforced, so blaming them means refusing a conforming agent with 400. A host that
    // answers with a public address AND a blocked one is split-horizon DNS, a VPN or a mesh
    // network, which is not the builder's doing: that abstains as our limit. A host where
    // EVERY address is blocked is one no conforming Company could use either, so that stays
    // the agent's defect.
    const blocked = addresses.map(a => ({ a, c: classifyAddress(a) })).filter(x => !x.c.allowed);
    if (blocked.length) {
      const { a, c } = blocked[0];
      const detail = `${target.host} resolves to ${a}, a ${c.kind} address, and section 3 forbids connecting to one for a URL the other party gave us`;
      return blocked.length === addresses.length
        ? { whose: "agent", detail }
        : { whose: "grader", detail: `${detail}; it also answers with a public address, so this grader will not choose between them` };
    }

    let res;
    try {
      // `address` is the one the loop above approved, and the transport connects to THAT,
      // keeping the hostname for the Host header and for the certificate check.
      res = await doFetch(target.url, { address: addresses[0], timeoutMs, maxBytes,
                                        redirect: "manual", connectTo: addresses[0],
                                        headers: { accept: "application/json" } });
    } catch (err) {
      if (err?.overCap)
        return { whose: "grader", detail: `${target.url} returned more than ${maxBytes} bytes, larger than this grader reads` };
      return { whose: "grader", detail: `${target.url}: ${err?.cause?.code ?? err?.message ?? err}` };
    }
    if (res.redirected || (res.status >= 300 && res.status < 400))
      return { whose: "agent", detail: `${target.url} answered ${res.status}, a redirect, and 5.3 step 1 fetches the client metadata without following redirects` };
    if (res.status === 404 || res.status === 410)
      return { whose: "agent", detail: `${target.url} answered ${res.status}, so the document is not there` };
    if (res.status < 200 || res.status >= 300)
      return { whose: "server", detail: `${target.url} answered ${res.status}, which this grader cannot interpret as a verdict about your agent` };

    const text = await res.text();
    // The transport aborts an oversize body as it arrives; this still catches an injected
    // transport that does not, so neither place is the only one that counts.
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
    // `wantKid` is the kid the delegation in front of us names. A cached key set that does not
    // contain it is refetched once, within the interval, which is what every ordinary JWKS
    // consumer does and what the guides ask for: "Publish a new key in `jwks_uri` before
    // signing with it." Without this, a builder who rotated a key was refused 400 against a
    // cache that could be up to a day old, and ending the run did not clear it.
    async forIssuer(iss, { wantKid } = {}) {
      const at = now();
      const hit = cache.get(iss);
      const stale = hit && wantKid && !(hit.value.kids ?? []).includes(wantKid)
        && !(hit.value.keys ?? []).some(k => !k?.kid)      // a set with an unlabelled key may still hold it
        && at - hit.at >= refetchSeconds;
      if (hit && at < hit.expiresAt && !stale)
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
    // Everything remembered about one issuer, dropped. The gate uses it on its own issuer,
    // whose key changes every run and whose identity is only mounted while it drives.
    forget(iss) { cache.delete(iss); attempts.delete(iss); spent.delete(iss); },
    get cached() { return cache.size; },
  };
}
