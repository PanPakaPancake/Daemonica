// Fails if de.json and en.json do not contain exactly the same keys (SPEC §5.7).
import { readFileSync } from "node:fs";
const load = (l) => JSON.parse(readFileSync(new URL(`../src/locales/${l}.json`, import.meta.url)));
const flat = (o, p = "") => Object.entries(o).flatMap(([k, v]) => (typeof v === "object" ? flat(v, `${p}${k}.`) : [`${p}${k}`]));
const de = new Set(flat(load("de"))), en = new Set(flat(load("en")));
const missingEn = [...de].filter((k) => !en.has(k)), missingDe = [...en].filter((k) => !de.has(k));
if (missingEn.length || missingDe.length) {
  console.error("missing in en:", missingEn, "\nmissing in de:", missingDe);
  process.exit(1);
}
console.log(`i18n ok (${de.size} keys)`);

// Every literal key used in the code must exist (plural keys via _one/_other).
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
const srcDir = new URL("../src/", import.meta.url).pathname;
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : /\.tsx?$/.test(f) ? [join(d, f)] : []));
const used = new Set();
for (const f of walk(srcDir)) {
  for (const m of readFileSync(f, "utf8").matchAll(/\bt\(\s*"([a-zA-Z][\w-]*(?:\.[\w-]+)+)"/g)) used.add(m[1]);
}
const missing = [...used].filter((k) => !de.has(k) && !de.has(`${k}_one`));
if (missing.length) {
  console.error("keys used in code but missing in locales:", missing);
  process.exit(1);
}
console.log(`i18n usage ok (${used.size} literal keys)`);
