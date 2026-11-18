// The grader's own poppy.json.
//
// An agent cannot be graded without a document to drive against, and a document that is not
// valid is refused whole: their validator reports "poppy.json fields have the forms section
// 3.1 describes" and every check that depends on the document is skipped. That has already
// happened twice to an earlier Company of ours, once for declaring an extension as an
// object where 1.0 wants an array of version entries, and once for omitting a description
// on a conversation protocol entry. Both were found by their validator and missed by our
// own tests, because nothing of ours read their schema. Now something does:
// tests/discovery.test.mjs judges this with their schema validator and their schema.
export function discoveryFor(origin, { name = "Grader Shop", withExtensions = true } = {}) {
  const u = new URL(origin);
  // 3.1: "`domain` MUST be the host that serves the document, after any redirects, with its
  // port when that isn't 443." URL.host is exactly that: it carries a non-default port and
  // omits 443.
  const domain = u.host;
  void domain;
  const issuer = `${origin}/poppy`;
  return {
    protocol_version: "1.0",
    organization: { name, domain },
    auth: { issuer },
    agent: {
      protocols: [{
        type: "poppy",
        endpoint: `${origin}/poppy/conversations`,
        // 3.1 requires a description on every entry: "Each entry has a `type`, an
        // `endpoint`, and a `description`."
        description: "Questions about this grader and what it records about your agent.",
      }],
    },
    apis: [{
      type: "openapi",
      url: `${origin}/poppy/openapi.json`,
      description: "A small read-only API, so an agent has a signed-out request to make.",
    }],
    web: { browser_session_endpoint: `${origin}/poppy/browser-session` },
    tasks: { endpoint: `${origin}/poppy/tasks` },
    ...(withExtensions
      // 3.1: extensions are "keyed by name, with an entry for each version", so the value is
      // an array even for one version.
      ? { extensions: { operations: [{ version: "3", endpoint: `${origin}/poppy/operations` }] } }
      : {}),
  };
}

// The OpenAPI document the discovery advertises, built from the Company's declared operations.
//
// 5.2 counts "the request URLs its listed APIs describe", so the document an agent reads and
// the classifier that judges where the agent went are ONE fact. Held as two they drift: a
// path in the document the classifier does not recognise is a destination an agent is
// invited to call and no rule examines, and the reverse fails an agent for calling exactly
// what it was told to. So both are derived from the same list, and a test walks the served
// document and requires every operation in it to classify as a destination.
//
// Minimal on purpose. An agent needs the method, the path and enough of a response shape to
// know the call succeeded; this grader is not pretending to be a shop.
export function openapiFor(origin, operations = DEFAULT_OPERATIONS) {
  const paths = {};
  for (const op of operations) {
    const method = String(op.method).toLowerCase();
    paths[op.path] ??= {};
    paths[op.path][method] = {
      summary: op.summary ?? `${op.method} ${op.path}`,
      operationId: op.operationId ?? `${method}${op.path.replace(/[^a-zA-Z0-9]+/g, "_")}`,
      ...(op.path.includes("{")
        ? { parameters: [...op.path.matchAll(/\{([^}]+)\}/g)].map(m => ({
              name: m[1], in: "path", required: true, schema: { type: "string" } })) }
        : {}),
      responses: { "200": { description: "ok",
        content: { "application/json": { schema: { type: "object" } } } } },
    };
  }
  return {
    openapi: "3.1.0",
    info: { title: "Grader Shop API", version: "1.0.0",
            description: "A small read-only API, so an agent has a signed-out request to make." },
    servers: [{ url: origin }],
    paths,
  };
}

export const DEFAULT_OPERATIONS = [
  { method: "GET", path: "/poppy/orders", summary: "List the orders of this session" },
  { method: "GET", path: "/poppy/orders/{id}", summary: "One order" },
];

// The method and template pairs the classifier compares a request against, from the same
// list the document is built from.
export const operationsToTemplates = (operations = DEFAULT_OPERATIONS) =>
  operations.map(op => ({ method: String(op.method).toUpperCase(), template: op.path }));

// The domain's protected resource metadata, RFC 9728, at /.well-known/oauth-protected-resource.
//
// 3.2: "its `resource` MUST be exactly `https://{organization.domain}`, and its
// `authorization_servers`, when nonempty, names the issuer". An earlier Company of ours
// served the MCP server's metadata at this path instead, with a resource of
// `.../poppy/mcp`, and the authors' validator caught it.
export function resourceMetadataFor(origin) {
  const u = new URL(origin);
  return {
    // The scheme comes from the origin. Production is https, which the authors' validator
    // enforces; a loopback rig on http must still be self-consistent or its own documents
    // disagree and the agent refuses it for our reason rather than its own.
    resource: `${u.protocol}//${u.host}`,
    authorization_servers: [`${origin}/poppy`],
  };
}

// The issuer's OAuth Authorization Server Metadata, RFC 8414, at the URL RFC 8414 section
// 3.1 defines: /.well-known/oauth-authorization-server with the issuer's path appended.
//
// 3.2 requires `protected_resources` to list `https://{domain}` "for every domain whose
// issuer it is, with no path or trailing slash". The guides call it "the required field an
// existing issuer is most likely to be missing", so getting it right here is the point.
//
// grant_types_supported deliberately offers no sign-in: 3.2 ties the offered sign-in types
// to this list, and advertising a grant this grader does not implement would make the
// grader nonconformant and send a builder's agent down a path that cannot complete. 3.2
// allows it: "A Company without one can offer signed-out Sessions, including APIs,
// conversations, feedback, and browser join, without running an authorization server",
// and we keep the issuer so that `aud` is an issuer, which is the case builders will meet.
export function authServerMetadataFor(origin) {
  const issuer = `${origin}/poppy`;
  return {
    issuer,
    protected_resources: [`${new URL(origin).protocol}//${new URL(origin).host}`],
    token_endpoint: `${issuer}/token`,
    revocation_endpoint: `${issuer}/revoke`,
    grant_types_supported: ["refresh_token"],
    token_endpoint_auth_methods_supported: ["private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: ["ES256", "PS384"],
  };
}

// The path RFC 8414 section 3.1 defines for an issuer with a path: the well-known segment
// goes between the host and the issuer's path, which is why it is not simply appended.
export function authServerMetadataPath(origin) {
  const p = new URL(`${origin}/poppy`).pathname.replace(/\/+$/, "");
  return `/.well-known/oauth-authorization-server${p}`;
}
