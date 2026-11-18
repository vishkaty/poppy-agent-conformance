// Start the grader.
//
//   npm start                      two Companies on loopback, ephemeral ports
//   npm start path/to/config.json  a deployment
//
// Needs Node 22.6 or later with type stripping, because the canary that gates every run is
// driven by the protocol authors' own TypeScript. Started without it, the gate refuses to
// grade rather than grading with a control that did not run.
//
// A deployment config, one entry per Company. Two are required: several sentences of 1.0 can
// only be judged across two Companies, and a grader that silently had one would report those
// rules as not reached for ever.
//
//   {
//     "lease_seconds": 900,
//     "reports_dir": "/var/lib/poppy-grader/reports",
//     "companies": [
//       { "origin": "https://poppy.example", "port": 8787, "trust_forwarded_for": true,
//         "verify_delegations": false },
//       { "origin": "https://poppy2.example", "port": 8788, "trust_forwarded_for": true }
//     ]
//   }
//
// `origin` is the public URL a builder reaches, which is what htu is compared against, never
// the Host header the process receives. Omit it and the origin becomes the loopback address
// actually bound, which is the local mode. `trust_forwarded_for` says something in front
// overwrites the client address headers: set it behind a proxy and not otherwise, or an agent
// can forge the source its own requests appear to come from.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRig } from "./rig.mjs";

const DEFAULT = { companies: [{ port: 0 }, { port: 0 }] };

function graderCommit() {
  // Which code produced a verdict. Printed in every report, so a builder can come back with
  // one and be told exactly what judged it.
  if (process.env.POPPY_GRADER_COMMIT) return process.env.POPPY_GRADER_COMMIT;
  try {
    const sha = execFileSync("git", ["rev-parse", "--short=12", "HEAD"],
                             { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain"],
                               { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return dirty ? `${sha}+local-changes` : sha;
  } catch { return "unknown"; }
}

const file = process.argv[2];
let config;
try {
  config = file ? JSON.parse(readFileSync(file, "utf8")) : DEFAULT;
} catch (err) {
  console.error(`could not read ${file}: ${err.message}`);
  process.exit(2);
}

const declared = config.companies ?? [];
if (declared.length !== 2) {
  console.error(`a run needs exactly two Companies and this config declares ${declared.length}. `
    + `Several rules of 1.0 can only be judged across two, and a grader with one would report them as not reached for ever.`);
  process.exit(2);
}

const rig = createRig({
  leaseSeconds: config.lease_seconds,
  retentionSeconds: config.retention_seconds,
  maxRequestsPerCompany: config.max_requests_per_company,
  // Where frozen reports are kept so a restart does not kill a builder's link. Omitted, they
  // live only in memory and a restart answers every link the way a typo does.
  reportsDir: config.reports_dir,
  graderCommit: graderCommit(),
  companies: declared.map(c => ({
    // A placeholder until the port is known. setOrigins below replaces it, and the
    // documents are re-derived from the real one rather than kept as a stale snapshot.
    origin: c.origin ?? "http://127.0.0.1",
    operations: c.operations,
    trustForwardedFor: c.trust_forwarded_for === true,
    // Verify a delegation against the key the agent published at its jwks_uri (5.2 step 1).
    // OFF unless asked for, because it makes this process fetch a URL a stranger chose. Read
    // the section in the README before turning it on: the fetch reveals this origin's egress
    // address to whichever host the lease holder names in `iss`.
    verifyDelegations: c.verify_delegations === true,
    // Where the authors' own Company validator keeps its test agent identity. Setting this
    // serves exactly agent.json and jwks.json from that directory, under /test-agent, so
    // their validator can run past discovery against this deployment. The signing key in the
    // same directory is never served, which a test asserts by name.
    testAgentIdentity: c.test_agent_identity,
    testAgentPrefix: c.test_agent_prefix,
    name: c.name,
  })),
});

let ports;
try {
  ports = await rig.listen(declared.map(c => c.port ?? 0));
  rig.setOrigins(declared.map((c, i) => c.origin ?? `http://127.0.0.1:${ports[i]}`));
} catch (err) {
  console.error(`refusing to start: ${err.message}`);
  await rig.close();
  process.exit(2);
}

const [a, b] = rig.origins;
// The one line a script can parse, and the only thing printed that a builder needs. No run
// token is ever printed: a token in a log is a report anybody holding the log can read.
console.log(`ready ${a} ${b} control ${a}`);
for (const w of rig.graders.flatMap(g => g.warnings)) console.log(`warning: ${w}`);
console.log(`bound 127.0.0.1:${ports[0]} and 127.0.0.1:${ports[1]}`);
console.log(`POST ${a}/grader/runs to lease a run. GET ${a}/grader/health for what this process is.`);

let closing = false;
for (const sig of ["SIGTERM", "SIGINT"]) process.on(sig, async () => {
  if (closing) return;
  closing = true;
  await rig.close();
  process.exit(0);
});
