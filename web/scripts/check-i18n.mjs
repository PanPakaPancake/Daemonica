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
