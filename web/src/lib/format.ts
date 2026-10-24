// Locale-aware formatting helpers (SPEC §5.7: formats via Intl).

const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

export function bytes(n: number, lang: string): string {
  if (!Number.isFinite(n) || n < 0) return "–";
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${new Intl.NumberFormat(lang, { maximumFractionDigits: v < 10 && i > 0 ? 1 : 0 }).format(v)} ${units[i]}`;
}

export function rate(bps: number, lang: string): string {
  return `${bytes(bps, lang)}/s`;
}

export function pct(v: number, lang: string, digits = 0): string {
  return new Intl.NumberFormat(lang, { style: "percent", maximumFractionDigits: digits }).format(v / 100);
}

export function num(v: number, lang: string, digits = 2): string {
  return new Intl.NumberFormat(lang, { maximumFractionDigits: digits, minimumFractionDigits: digits }).format(v);
}

export function duration(sec: number, lang: string): string {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const parts: string[] = [];
  const f = (value: number, unit: "day" | "hour" | "minute") =>
    new Intl.NumberFormat(lang, { style: "unit", unit, unitDisplay: "short" }).format(value);
  if (d) parts.push(f(d, "day"));
  if (h || d) parts.push(f(h, "hour"));
  parts.push(f(m, "minute"));
  return parts.join(" ");
}

export function dateTime(iso: string | undefined, lang: string): string {
  if (!iso || iso.startsWith("0001-")) return "–";
  return new Date(iso).toLocaleString(lang);
}

export function relative(iso: string | undefined, lang: string): string {
  if (!iso || iso.startsWith("0001-")) return "–";
  const diff = (Date.parse(iso) - Date.now()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  return rtf.format(Math.round(diff / 86400), "day");
}

/** Saves text as a file download (data already on screen; no server round trip). */
export function saveText(name: string, text: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.append(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
