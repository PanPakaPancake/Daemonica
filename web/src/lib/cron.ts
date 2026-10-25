// Schedule builder for cron entries: the same choices as the job wizard,
// translated to and from the five cron fields.
import { timeRE, weekdays } from "./jobs";

export type CronKind = "hourly" | "daily" | "weekly" | "monthly" | "interval" | "reboot" | "custom";
export const cronKinds: CronKind[] = ["hourly", "daily", "weekly", "monthly", "interval", "reboot", "custom"];
// Steps that divide the hour or the day evenly (cron restarts */n each hour or day).
export const minuteSteps = [1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30];
export const hourSteps = [1, 2, 3, 4, 6, 8, 12];

export interface CronDraft {
  kind: CronKind;
  minute: number;
  time: string;
  weekdays: string[];
  day: number;
  every: number;
  unit: "min" | "h";
  expr: string;
}

const defaults: CronDraft = { kind: "daily", minute: 0, time: "03:00", weekdays: ["Mon"], day: 1, every: 15, unit: "min", expr: "0 3 * * *" };
// cron counts Sunday as 0 (or 7), our weekday list starts on Monday.
const dowOf = (w: string) => (weekdays.indexOf(w as (typeof weekdays)[number]) + 1) % 7;
const pad = (n: number) => String(n).padStart(2, "0");

/** The cron expression of a draft. */
export function toCron(d: CronDraft): string {
  const [h, m] = d.time.split(":").map(Number);
  switch (d.kind) {
    case "hourly":
      return `${d.minute} * * * *`;
    case "daily":
      return `${m} ${h} * * *`;
    case "weekly":
      return `${m} ${h} * * ${[...d.weekdays]
        .map(dowOf)
        .sort((a, b) => (a || 7) - (b || 7))
        .join(",")}`;
    case "monthly":
      return `${m} ${h} ${d.day} * *`;
    case "interval":
      if (d.unit === "h") return `${d.minute} ${d.every === 1 ? "*" : `*/${d.every}`} * * *`;
      return d.every === 1 ? "* * * * *" : `*/${d.every} * * * *`;
    case "reboot":
      return "@reboot";
    case "custom":
      return d.expr.trim().replace(/\s+/g, " ");
  }
}

const num = (s: string, max: number) => (/^\d{1,2}$/.test(s) && Number(s) <= max ? Number(s) : undefined);

/** Reads an expression back into the builder; anything else is "custom". */
export function fromCron(expr: string): CronDraft {
  const e = expr.trim().replace(/\s+/g, " ");
  const base = { ...defaults, expr: e };
  const short: Record<string, Partial<CronDraft>> = {
    "@reboot": { kind: "reboot" },
    "@hourly": { kind: "hourly", minute: 0 },
    "@daily": { kind: "daily", time: "00:00" },
    "@midnight": { kind: "daily", time: "00:00" },
    "@weekly": { kind: "weekly", time: "00:00", weekdays: ["Sun"] },
    "@monthly": { kind: "monthly", time: "00:00", day: 1 },
  };
  if (short[e]) return { ...base, ...short[e] };
  const f = e.split(" ");
  if (f.length !== 5) return { ...base, kind: "custom" };
  const [mi, ho, dom, mon, dow] = f as [string, string, string, string, string];
  const m = num(mi, 59);
  const h = num(ho, 23);
  const time = m !== undefined && h !== undefined ? `${pad(h)}:${pad(m)}` : "";
  if (mon === "*") {
    if (m !== undefined && ho === "*" && dom === "*" && dow === "*") return { ...base, kind: "hourly", minute: m };
    if (time && dom === "*" && dow === "*") return { ...base, kind: "daily", time };
    if (time && dom !== "*" && dow === "*" && num(dom, 31)) return { ...base, kind: "monthly", time, day: Number(dom) };
    if (time && dom === "*") {
      const days = dow === "1-5" ? ["1", "2", "3", "4", "5"] : dow.split(",");
      if (days.every((x) => /^[0-7]$/.test(x))) {
        const names = [...new Set(days.map((x) => weekdays[(Number(x) + 6) % 7] as string))];
        return { ...base, kind: "weekly", time, weekdays: weekdays.filter((w) => names.includes(w)) };
      }
    }
    if (ho === "*" && dom === "*" && dow === "*") {
      if (mi === "*") return { ...base, kind: "interval", unit: "min", every: 1 };
      const s = /^\*\/(\d+)$/.exec(mi);
      if (s && minuteSteps.includes(Number(s[1]))) return { ...base, kind: "interval", unit: "min", every: Number(s[1]) };
    }
    const hs = /^\*\/(\d+)$/.exec(ho);
    if (m !== undefined && hs && hourSteps.includes(Number(hs[1])) && dom === "*" && dow === "*")
      return { ...base, kind: "interval", unit: "h", every: Number(hs[1]), minute: m };
  }
  return { ...base, kind: "custom" };
}

/** Field errors of a draft (keys of jobs.err.*). */
export function cronErrors(d: CronDraft): Partial<Record<"minute" | "time" | "weekdays" | "day", string>> {
  const e: Partial<Record<"minute" | "time" | "weekdays" | "day", string>> = {};
  if ((d.kind === "hourly" || (d.kind === "interval" && d.unit === "h")) && !(d.minute >= 0 && d.minute <= 59 && Number.isInteger(d.minute)))
    e.minute = "minute";
  if (["daily", "weekly", "monthly"].includes(d.kind) && !timeRE.test(d.time)) e.time = "time";
  if (d.kind === "weekly" && d.weekdays.length === 0) e.weekdays = "weekdays";
  if (d.kind === "monthly" && !(d.day >= 1 && d.day <= 31)) e.day = "day";
  return e;
}
