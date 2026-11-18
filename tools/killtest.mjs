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
const FILE = "tests/runs.test.mjs";

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

  // the recorder's own guards, which the run model now leans on
  { id: "record/control-recorded", file: "server.mjs", kills: "control-plane requests never are",
    find: "    if (config.control && config.control(req, res, rawTarget)) return;",
    to: "    if (config.control && config.control(req, res, rawTarget)) { push(recordOf(req, config, { at })); return; }" },
  { id: "record/no-seq", file: "server.mjs", kills: "during a lease are recorded",
    find: "record.seq = ++seq;", to: "record.seq = 0;" },
  { id: "record/prefix-collision-allowed", file: "server.mjs", kills: "under the control-plane prefix is refused",
    find: "if (prefix && x.origin === parsed.origin && x.pathname.startsWith(prefix))", to: "if (false)" },
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
function runSuite() {
  try {
    const out = execFileSync(process.execPath,
      ["--experimental-strip-types", "--test", FILE],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: TIMEOUT_MS });
    return { failed: false, out };
  } catch (err) {
    if (err.killed || err.signal) return { failed: true, hung: true, out: `${err.stdout ?? ""}` };
    return { failed: true, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

const base = runSuite();
if (base.failed) {
  console.error("the suite does not pass before any mutation, so nothing below would mean anything");
  console.error(base.out.split("\n").filter(l => l.startsWith("not ok")).join("\n"));
  process.exit(2);
}
console.log(`control: ${FILE} passes unmutated\n`);

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
    const r = runSuite();
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
