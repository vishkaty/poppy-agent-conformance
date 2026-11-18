// Is the specification we grade against still the one the authors publish?
//
//   node tools/spec-status.mjs          checks spec/PROVENANCE.json against the live index
//
// Exit 0 when our copy is still a published version with the hashes we recorded, 1 when it is
// not, and the output always names any newer published version and any draft in progress.
//
// Two premises can break silently, which is why this exists rather than a note in a README.
// A published version is frozen, so if one of its page hashes ever moved, every quote in
// checks.mjs would be a quote of text the specification no longer has, and the suite would
// stay green because it checks our quotes against our own copy. And a newer published version
// makes every verdict true about an older protocol without anything saying so.
//
// A draft is NOT a newer version for this purpose. It has no published date and no hashes, it
// can change under its own number, and this programme has watched one draft do that three
// times in a week. Nothing may be captured from a draft as though it were frozen.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const INDEX = "https://raw.githubusercontent.com/personal-agent-protocol/personal-agent-protocol/main/content/versions/versions.json";

export async function fetchIndex() {
  const res = await fetch(INDEX);
  if (!res.ok) throw new Error(`${INDEX} answered ${res.status}`);
  return res.json();
}

// `ours` is the shape of spec/PROVENANCE.json: { version, pages: { name: { sha256 } } }.
// `getIndex` is injected so the checks are tested rather than the network.
export async function specStatus(ours, getIndex = fetchIndex) {
  const problems = [];
  let entries;
  try {
    entries = await getIndex();
  } catch (err) {
    // A check that answers "nothing has changed" when it could not look is the whole class
    // of defect this project exists to avoid.
    return { ok: false, problems: [`could not read the published version index: ${err.message}`],
             newerPublished: [], draftsInProgress: [], version: ours?.version ?? null };
  }
  if (!Array.isArray(entries) || entries.length === 0)
    return { ok: false, problems: ["the published version index was not a non-empty list"],
             newerPublished: [], draftsInProgress: [], version: ours?.version ?? null };

  // A published entry carries a date AND a hash per page; a draft carries neither.
  const published = entries.filter(e => e?.published && e.pages && !Array.isArray(e.pages));
  const drafts = entries.filter(e => !e?.published);

  const mine = published.find(e => String(e.id) === String(ours?.version));
  if (!mine) {
    problems.push(`${ours?.version} is no longer a published version: the index publishes ${published.map(e => e.id).join(", ") || "nothing"}`);
  } else {
    for (const [name, rec] of Object.entries(ours.pages ?? {})) {
      const want = typeof rec === "string" ? rec : rec?.sha256;
      const got = mine.pages[name];
      if (got === undefined) problems.push(`page ${name} is no longer in published ${mine.id}, which is supposed to be frozen`);
      else if (got !== want) problems.push(`page ${name} of published ${mine.id} has changed, and a published version is supposed to be frozen: we recorded ${String(want).slice(0, 12)} and the index now says ${String(got).slice(0, 12)}`);
    }
  }

  const order = v => String(v).split(".").map(n => Number(n) || 0);
  const newer = published
    .filter(e => mine && order(e.id).join() !== order(mine.id).join()
                 && order(e.id).some((n, i) => n > (order(mine.id)[i] ?? 0))
                 && order(e.id)[0] >= order(mine.id)[0])
    .map(e => String(e.id));

  return { ok: problems.length === 0, problems, version: ours?.version ?? null,
           newerPublished: newer, draftsInProgress: drafts.map(e => String(e.id)) };
}

// Run directly.
if (process.argv[1] && process.argv[1].endsWith("spec-status.mjs")) {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const ours = JSON.parse(readFileSync(join(HERE, "../spec/PROVENANCE.json"), "utf8"));
  const s = await specStatus(ours);
  console.log(`our copy: published ${s.version}`);
  for (const p of s.problems) console.log(`PROBLEM: ${p}`);
  if (s.newerPublished.length) console.log(`a newer published version exists: ${s.newerPublished.join(", ")}. Verdicts here are still true about ${s.version} and say so; adopting it is a decision for a person.`);
  if (s.draftsInProgress.length) console.log(`drafts in progress, which can change under their own number: ${s.draftsInProgress.join(", ")}`);
  if (s.ok && !s.newerPublished.length) console.log(`published ${s.version} is unchanged and current.`);
  process.exit(s.ok ? 0 : 1);
}
