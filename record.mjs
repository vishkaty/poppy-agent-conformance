// What the Company saw, recorded so the checks can judge it.
//
// This module decides which rules apply to a request, so a mistake here makes every verdict
// wrong in a way no check can notice. Three things follow from that, and each was learned by
// getting it wrong first:
//
//  1. Exclusions are evaluated BEFORE destinations. 5.2 says "Discovery and description
//     documents and OAuth endpoints don't carry this header", and those documents routinely
//     share a path prefix with a real destination: the specification's own example puts the
//     OpenAPI document at the origin root. An earlier version checked destinations first and
//     classified poppy.json, the OpenAPI document, the token endpoint, the OAuth metadata
//     and the browser session page as destinations, which would fail a conforming agent for
//     obeying the sentence above.
//  2. Destinations are matched by METHOD and TEMPLATE, not by prefix. 5.2 counts "the
//     request URLs its listed APIs describe", and a prefix cannot express that: it also
//     matches the description document beside them, and /poppy/api-docs under /poppy/api.
//  3. Every comparison checks the ORIGIN. A destination configured at another provider,
//     which the guides describe as a normal layout, otherwise matches our own path.
//
// The tests use a deliberately overlapping fixture for this reason. A fixture whose URLs do
// not collide proves the fixture's geometry and not the rule.

const u = s => { try { return new URL(s); } catch { return null; } };
const norm = p => (p.replace(/\/+$/, "") || "/");
export const pathOf = s => { const x = u(s); return x ? norm(x.pathname) : null; };
const originOf = s => { const x = u(s); return x ? x.origin : null; };

// `{id}` matches exactly one segment, so {endpoint}/{id}/messages cannot match
// {endpoint}/a/b/messages.
function matchesTemplate(path, template) {
  const a = norm(path).split("/"), b = norm(template).split("/");
  if (a.length !== b.length) return false;
  return b.every((seg, i) => (seg.startsWith("{") && seg.endsWith("}") ? a[i].length > 0 : seg === a[i]));
}

// The public URL the agent used, built from the CONFIGURED origin.
//
// Never from the Host header. The guides: "Behind proxies and load balancers, compare htu
// with the public URL the personal agent used. Build it from your configured public origin,
// not from the Host header your server receives." Behind a tunnel the origin process sees
// plain HTTP on a loopback port, so a Host-derived URL would never match a conforming htu.
//
// An absolute-form target is accepted rather than concatenated: RFC 9112 says "A server MUST
// accept the absolute-form in requests". Concatenating one produced a url like
// https://shop.example/https://shop.example/v1/orders, which classified as a website page
// and then failed htm-htu against an agent that had done nothing wrong.
export function publicUrl(origin, requestTarget) {
  const t = String(requestTarget ?? "/");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) {
    const abs = u(t);
    if (abs && abs.origin === originOf(origin)) return abs.toString();
    return t;                       // another authority: recordOf flags it as misdirected
  }
  return `${String(origin).replace(/\/+$/, "")}${t.startsWith("/") ? "" : "/"}${t}`;
}

// A repeated or undecodable Poppy-Session header.
//
// Node joins repeated headers with ", " into one undecodable string, and only set-cookie
// arrives as an array. The raw value is KEPT: deleting it made session.header-sent report
// "carried no Session header", which is untrue when two were sent and reproduced the
// self-contradiction the detection exists to stop.
export function sessionHeaderOf(headers) {
  const raw = headers?.["poppy-session"];
  if (raw === undefined) return { value: undefined, count: 0, decodable: false };
  const value = Array.isArray(raw) ? raw.join(", ") : String(raw);
  const parts = value.split(/,\s*/).filter(Boolean);
  const count = parts.length;
  const decodable = count === 1 && parts[0].split(".").length === 3;
  return { value, count, decodable };
}

// Documents and endpoints that MUST NOT carry the header (5.2, 3.4). Built from the
// Company's own document, so it is exact rather than guessed.
function documents(cfg) {
  const d = cfg.discovery ?? {};
  const out = ["/.well-known/poppy.json", "/.well-known/oauth-authorization-server",
               "/.well-known/oauth-protected-resource"];
  for (const a of d.apis ?? []) if (a?.type === "openapi" && a.url) out.push(a.url);
  for (const v of Object.values(d.supported_versions ?? {})) if (v) out.push(v);
  // A ucp entry's endpoint is a profile document, and its requests follow UCP's bindings
  // rather than 8.2, so the profile is not an 8.2 route base.
  for (const p of d.agent?.protocols ?? []) if (p?.type && p.type !== "poppy" && p.endpoint) out.push(p.endpoint);
  for (const e of cfg.authServerEndpoints ?? []) out.push(e);
  if (d.web?.browser_session_endpoint) out.push(d.web.browser_session_endpoint);
  return out;
}

export function classify(url, method, cfg) {
  const x = u(url);
  const origin = originOf(cfg.origin);
  if (!x || x.origin !== origin)
    return { isResource: false, isPage: false, mustNotCarry: false, why: "another host" };
  const path = norm(x.pathname);
  const m = String(method ?? "GET").toUpperCase();
  const samePath = (ref) => originOf(ref) === origin
    ? (ref.startsWith("/") ? norm(ref) === path : pathOf(ref) === path)
    : (ref.startsWith("/") ? norm(ref) === path : false);

  // 1. exclusions first, including the well-known prefix for a path-scoped resource metadata
  for (const ref of documents(cfg)) {
    const p = ref.startsWith("/") ? norm(ref) : (originOf(ref) === origin ? pathOf(ref) : null);
    if (p && (p === path || path.startsWith("/.well-known/oauth-protected-resource/")
                         || path.startsWith("/.well-known/oauth-authorization-server/")))
      return { isResource: false, isPage: false, mustNotCarry: true,
               why: "a discovery or description document, or an OAuth endpoint (5.2)" };
  }

  const d = cfg.discovery ?? {};
  const at = (ref, template, wantMethod) => {
    if (originOf(ref) !== origin) return false;
    if (wantMethod && m !== wantMethod) return false;
    return matchesTemplate(path, pathOf(ref) + template);
  };

  // 2. the six routes of 8.2, under a `poppy` entry only
  for (const p of d.agent?.protocols ?? []) {
    if (p?.type !== "poppy" || !p.endpoint) continue;
    for (const [wm, t] of [["POST", ""], ["POST", "/{id}/messages"], ["GET", "/{id}/events"],
                           ["POST", "/{id}/handoff"], ["POST", "/{id}/handoff/cancel"], ["POST", "/{id}/close"]])
      if (at(p.endpoint, t, wm))
        return { isResource: true, isPage: false, mustNotCarry: false, why: `a conversation route of 8.2 (${wm} {endpoint}${t})` };
  }

  // 3. an mcp url IS the endpoint, and nothing beneath it
  for (const a of d.apis ?? [])
    if (a?.type === "mcp" && a.url && originOf(a.url) === origin && pathOf(a.url) === path)
      return { isResource: true, isPage: false, mustNotCarry: false, why: "an MCP server listed in apis (section 7)" };

  // 4. operations a listed OpenAPI describes, compiled to method plus template at startup
  for (const op of cfg.apiOperations ?? [])
    if (String(op.method).toUpperCase() === m && matchesTemplate(path, op.template))
      return { isResource: true, isPage: false, mustNotCarry: false, why: `an operation a listed OpenAPI describes (${op.method} ${op.template})` };

  // 5. the single-request protocol endpoints
  if (d.web?.browser_session_endpoint && at(d.web.browser_session_endpoint, "/authorize", "POST"))
    return { isResource: true, isPage: false, mustNotCarry: false, why: "browser authorization (section 6)" };
  if (d.tasks?.endpoint && at(d.tasks.endpoint, "", "GET"))
    return { isResource: true, isPage: false, mustNotCarry: false, why: "the tasks endpoint (section 9)" };
  if (cfg.feedbackEndpoint && at(cfg.feedbackEndpoint, "", "POST"))
    return { isResource: true, isPage: false, mustNotCarry: false, why: "the feedback endpoint (section 9)" };
  for (const e of cfg.extensionEndpoints ?? [])
    if (samePath(e)) return { isResource: true, isPage: false, mustNotCarry: false, why: "an extension endpoint (3.3)" };

  // 6. a page of the Company's own website, where 5.2 makes the header a SHOULD. Its absence
  //    can never be a failure, which is why it is recorded separately.
  const domain = String(d.organization?.domain ?? "").toLowerCase();
  if (domain && x.host.toLowerCase() === domain)
    return { isResource: false, isPage: true, mustNotCarry: false, why: "a website page, where 5.2 makes the header a SHOULD" };
  return { isResource: false, isPage: false, mustNotCarry: false, why: "not a Session destination" };
}

// Where the request came from.
//
// Used only to let a builder SEE that traffic in their run came from somewhere other than
// their own agent: a scanner probing a freshly published hostname, or a previous builder's
// agent still long polling. It never decides a verdict, and the report shows a salted prefix
// rather than the address.
//
// A forwarded header is honoured only when the deployment says something in front overwrites
// it. Trusting one by default would let an agent split its own traffic into three sources by
// sending a header, and behind no proxy at all the socket address is the truth.
export function sourceOf(req, cfg) {
  const h = req.headers ?? {};
  const first = v => String(v ?? "").split(",")[0].trim() || null;
  if (cfg?.trustForwardedFor) {
    // Cloudflare overwrites cf-connecting-ip on every request, which is why it is first.
    const fwd = first(h["cf-connecting-ip"]) ?? first(h["x-forwarded-for"])
      ?? (String(h["forwarded"] ?? "").match(/for="?\[?([^\];,"]+)/)?.[1] ?? null);
    if (fwd) return fwd;
  }
  return req.socket?.remoteAddress ?? null;
}

// The methods that would make this path a destination.
//
// 8.2 creates a conversation with POST, so a GET there is a method mismatch and not a missing
// endpoint. Answering 404 told an agent its endpoint was wrong when it was not, and made the
// Company look as though it advertised something it does not serve.
export function allowedMethodsFor(url, cfg) {
  const all = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  return all.filter(m => classify(url, m, cfg).isResource);
}

// One record. `at` is Unix SECONDS and the caller SHOULD pass the time the request headers
// arrived: stamping it when the response ends would add a long poll's own duration as
// apparent clock skew and fail a conforming agent on the iat window.
//
// `body` is null when none was sent and "" when an empty one was, because 8.2 requires every
// POST to carry a JSON body and a later check needs to tell those apart.
export function recordOf(req, cfg, { at, body = null, bodyComplete = true } = {}) {
  const target = req.url ?? "/";
  const url = publicUrl(cfg.origin, target);
  const misdirected = /^[a-z][a-z0-9+.-]*:\/\//i.test(String(target))
    && originOf(url) !== originOf(cfg.origin);
  const method = String(req.method ?? "GET").toUpperCase();
  const c = misdirected
    ? { isResource: false, isPage: false, mustNotCarry: false,
        why: "misdirected: an absolute-form target for another authority (RFC 9112)" }
    : classify(url, method, cfg);
  const session = sessionHeaderOf(req.headers);
  return {
    host: originOf(url) ? new URL(url).host : null,
    method, url, path: originOf(url) ? norm(new URL(url).pathname) : null,
    at: at ?? Math.floor(Date.now() / 1000),
    headers: { ...req.headers }, body, bodyComplete,
    remoteAddress: sourceOf(req, cfg),
    isResource: c.isResource, isPage: c.isPage, mustNotCarry: c.mustNotCarry,
    classifiedAs: c.why, misdirected,
    sessionHeaderCount: session.count,
    sessionHeaderDecodable: session.decodable,
    sessionHeaderDuplicated: session.count > 1,
  };
}
