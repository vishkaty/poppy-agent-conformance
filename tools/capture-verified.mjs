// Capture a specification version from the authors' repository and VERIFY it against the
// hashes they publish themselves.
//
//   node tools/capture-verified.mjs 0.4     a published version: every page hash checked
//   node tools/capture-verified.mjs 1.0     a draft: no hashes exist, so pinned by commit
//
// Why this replaces scraping the served markdown. Until 2026-11-04 every version was a
// draft that moved under its own number, so a capture was only ever "what the site served
// when we asked", and two captures hours apart disagreed. Published versions now carry a
// sha256 per page in content/versions/versions.json, and the authors' own build refuses to
// let a published source change ("belongs to a published version, which is frozen"). So a
// published capture can be proved authentic rather than asserted, and a draft capture can
// at least be pinned to the commit it came from.
//
// Everything is fetched at ONE commit sha. Fetching page by page from `main` can straddle a
// push and produce a capture that never existed, which is the same class of error as the
// two same-day 0.3 captures that started this.
import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const REPO = "personal-agent-protocol/personal-agent-protocol";
const version = process.argv[2];
if (!version) { console.error("usage: capture-verified.mjs <version>   e.g. 0.4 or 1.0"); process.exit(2); }

const sha256 = s => createHash("sha256").update(s).digest("hex");
const bytes = s => Buffer.byteLength(s, "utf8");

async function raw(sha, path) {
  const r = await fetch(`https://raw.githubusercontent.com/${REPO}/${sha}/${path}`);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.text();
}

// one commit for the whole capture
const head = await fetch(`https://api.github.com/repos/${REPO}/commits/main`,
                         { headers: { accept: "application/vnd.github+json" } });
if (!head.ok) { console.error(`cannot read HEAD: HTTP ${head.status}`); process.exit(3); }
const sha = (await head.json()).sha;

const manifest = JSON.parse(await raw(sha, "content/versions/versions.json"));
const entry = manifest.find(v => v.id === version);
if (!entry) { console.error(`version ${version} is not in versions.json`); process.exit(3); }

const published = entry.published ?? null;
// A published version lists its pages as an object of page -> sha256; a draft lists an array.
const pages = Array.isArray(entry.pages) ? entry.pages : Object.keys(entry.pages);
const expected = Array.isArray(entry.pages) ? null : entry.pages;

const stamp = new Date().toISOString().slice(0, 10);
// Captures land in snapshots/, and the copy the tests read lives in spec/. Keeping them
// separate is deliberate: spec/ is the version this release was written against and must
// not move under a reader, while snapshots/ is where you put a newer one to see what
// changed before adopting it.
const dir = join("snapshots", `pap-source-${version}-${stamp}`);
mkdirSync(dir, { recursive: true });

console.log(`\n  ${REPO} at ${sha.slice(0, 12)}`);
console.log(`  version ${version}, ${published ? `published ${published}` : "IN PROGRESS, no hashes exist"}`);
console.log(`  ${pages.length} pages -> ${dir}\n`);

let verified = 0, failed = [];
const record = {};
for (const page of pages) {
  const src = await raw(sha, `content/versions/${version}/${page}.mdx`);
  const got = sha256(src);
  const want = expected?.[page] ?? null;
  const name = page.replace(/\//g, "-") + ".mdx";
  writeFileSync(join(dir, name), src);
  const rendered = await fetch(`https://personalagentprotocol.org/docs/${version}/${page}.md`);
  if (rendered.ok) writeFileSync(join(dir, page.replace(/\//g, "-") + ".md"), await rendered.text());
  record[page] = { file: name, bytes: bytes(src), sha256: got, expected: want };
  if (want == null) console.log(`  -       ${page.padEnd(28)} ${String(bytes(src)).padStart(7)}  ${got.slice(0, 16)}  (draft, nothing to verify against)`);
  else if (want === got) { verified++; console.log(`  OK      ${page.padEnd(28)} ${String(bytes(src)).padStart(7)}  ${got.slice(0, 16)}`); }
  else { failed.push(page); console.log(`  FAILED  ${page.padEnd(28)} got ${got.slice(0, 16)} want ${want.slice(0, 16)}`); }
}

writeFileSync(join(dir, "PROVENANCE.json"), JSON.stringify({
  repo: REPO, commit: sha, version, published,
  captured: new Date().toISOString(),
  verified_against_authors_hashes: expected != null,
  pages: record,
}, null, 2) + "\n");

console.log();
if (expected == null) {
  console.log(`  draft captured and pinned to commit ${sha.slice(0, 12)}; no hashes published for it\n`);
} else if (failed.length) {
  console.error(`  ${failed.length} page(s) do NOT match the published hash: ${failed.join(", ")}`);
  console.error(`  either the capture is wrong or a frozen version changed, and both matter\n`);
  process.exit(1);
} else {
  console.log(`  all ${verified} pages verified against the authors' own sha256\n`);
}
