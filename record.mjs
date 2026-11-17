// What the Company saw, recorded so the checks can judge it.
//
// This module decides which rules apply to a request, so a mistake here makes every verdict
// wrong in a way no check can notice. It is separated from the server and kept pure for
// that reason: the classification is testable against a fixture poppy.json with no network,
// and `tests/record.test.mjs` asserts every case 5.2 names.

// The public URL the agent used, built from the CONFIGURED origin.
//
// Never from the Host header. The protocol guides are explicit: "Behind proxies and load
// balancers, compare htu with the public URL the personal agent used. Build it from your
// configured public origin, not from the Host header your server receives." Behind a tunnel
// the origin process sees plain HTTP on a loopback port, so a Host-derived URL would never
// match a conforming `htu` and every agent would fail for our deployment choice.
export function publicUrl(origin, requestTarget) {
  return `${String(origin).replace(/\/+$/, "")}${requestTarget.startsWith("/") ? "" : "/"}${requestTarget}`;
}

// A repeated Poppy-Session header. Node joins repeated unknown headers with ", ", giving one
// undecodable string. Left undetected that reads as "no Session header was sent" on every
// claim check while session.header-sent passes, which is a self-contradicting report. 5.2
// defines one header holding one JWT signed for one request, so two is a defect worth
// naming rather than a parse failure worth hiding.
export function sessionHeaderOf(headers) {
  const raw = headers?.["poppy-session"];
  if (raw === undefined) return { value: undefined, duplicated: false };
  const parts = String(raw).split(/,\s*/).filter(Boolean);
  if (parts.length > 1) return { value: undefined, duplicated: true, count: parts.length };
  return { value: String(raw), duplicated: false };
}

const originOf = u => { try { return new URL(u).origin; } catch { return null; } };
const pathOf = u => { try { return new URL(u).pathname.replace(/\/+$/, "") || "/"; } catch { return null; } };

// Does this URL carry the Session header, per 5.2?
//
// "The destinations come from the Company's `poppy.json`: the request URLs its listed APIs
// describe (section 7), and protocol endpoints listed there or derived as the protocol or
// extension defines... Sharing a hostname with one of these URLs doesn't make another URL a
// Session destination... Discovery and description documents and OAuth endpoints don't
// carry this header."
//
// So this is derived from the document, exactly, and never from the host. A host-based
// heuristic marks poppy.json and the OpenAPI document as resources and fails a conforming
// agent for obeying the sentence above.
export function classify(url, cfg) {
  const d = cfg?.discovery ?? {};
  const path = pathOf(url), origin = originOf(url);
  if (!path || origin !== originOf(cfg.origin)) return { isResource: false, isPage: false, why: "another host" };

  // exact endpoints, and the routes derived beneath them
  const under = (base) => {
    const b = pathOf(base);
    return b && (path === b || path.startsWith(b + "/"));
  };
  const exact = (base) => pathOf(base) === path;

  for (const p of d.agent?.protocols ?? [])
    if (p?.endpoint && under(p.endpoint)) return { isResource: true, isPage: false, why: "a conversation route under agent.protocols[].endpoint (8.2)" };

  for (const a of d.apis ?? []) {
    // An `mcp` url IS the server endpoint. An `openapi` url is the DESCRIPTION document,
    // which 5.2 excludes; the request URLs it describes are covered by apiPrefixes.
    if (a?.type === "mcp" && a.url && under(a.url)) return { isResource: true, isPage: false, why: "an MCP server listed in apis (section 7)" };
  }
  for (const prefix of cfg.apiPrefixes ?? [])
    if (path.startsWith(pathOf(prefix) === "/" ? "/" : pathOf(prefix)))
      return { isResource: true, isPage: false, why: "a request URL a listed OpenAPI describes (section 7)" };

  if (d.web?.browser_session_endpoint && exact(d.web.browser_session_endpoint + "/authorize"))
    return { isResource: true, isPage: false, why: "browser authorization (section 6)" };
  if (d.tasks?.endpoint && under(d.tasks.endpoint))
    return { isResource: true, isPage: false, why: "the tasks endpoint (section 9)" };
  if (cfg.feedbackEndpoint && under(cfg.feedbackEndpoint))
    return { isResource: true, isPage: false, why: "the feedback endpoint the tasks response listed (section 9)" };
  for (const e of cfg.extensionEndpoints ?? [])
    if (under(e)) return { isResource: true, isPage: false, why: "an extension endpoint (3.3)" };

  // Not a destination. A page on organization.domain is a SHOULD, so it is recorded
  // separately and its missing header can never be a FAIL.
  const host = (() => { try { return new URL(url).host.toLowerCase(); } catch { return null; } })();
  const domain = String(d.organization?.domain ?? "").toLowerCase();
  if (domain && host === domain) return { isResource: false, isPage: true, why: "a website page, where 5.2 makes the header a SHOULD" };
  return { isResource: false, isPage: false, why: "not a Session destination" };
}

// One record. `at` is Unix SECONDS and is taken now, which the caller must do when the
// request headers arrive rather than when the response ends: a long poll on
// `{endpoint}/{id}/events?wait=N` would otherwise add N seconds of apparent clock skew and
// fail session.iat-window on a conforming agent.
export function recordOf(req, cfg, body = "") {
  const url = publicUrl(cfg.origin, req.url ?? "/");
  const { isResource, isPage, why } = classify(url, cfg);
  const session = sessionHeaderOf(req.headers);
  const headers = { ...req.headers };
  if (session.duplicated) delete headers["poppy-session"];
  else if (session.value !== undefined) headers["poppy-session"] = session.value;
  return {
    host: (() => { try { return new URL(url).host; } catch { return null; } })(),
    method: String(req.method ?? "GET").toUpperCase(),
    url, path: pathOf(url), at: Math.floor(Date.now() / 1000),
    headers, body,
    isResource, isPage, classifiedAs: why,
    sessionHeaderDuplicated: session.duplicated,
  };
}
