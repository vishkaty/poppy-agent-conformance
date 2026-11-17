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
