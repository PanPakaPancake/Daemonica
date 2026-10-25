// Scheduled tasks (SPEC §7.7 M1.6): types of the jobs.* and cron.* helper
// operations and the plain-language schedule text of the schedule builder.
import type { TFunction } from "i18next";

export type Mode = "exec" | "script" | "shell";
export type Kind = "hourly" | "daily" | "weekly" | "monthly" | "interval" | "calendar";
export const kinds: Kind[] = ["hourly", "daily", "weekly", "monthly", "interval", "calendar"];
export const weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;
export const interpreters = ["", "/bin/sh", "/bin/bash", "/usr/bin/python3", "/usr/bin/perl"];

export interface Schedule {
  kind: Kind;
  minute?: number;
  time?: string;
  weekdays?: string[];
  day?: number;
  every?: number;
  unit?: "min" | "h";
  calendar?: string;
  timezone?: string;
  persistent?: boolean;
  random_delay_sec?: number;
}

export interface EnvVar {
  name: string;
  value: string;
}

export interface Job {
  id: string;
  description?: string;
  mode: Mode;
  program?: string;
  args?: string[];
  script?: string;
  interpreter?: string;
  shell?: string;
  user: string;
  schedule: Schedule;
  timeout_sec?: number;
  env?: EnvVar[];
  workdir?: string;
  hardening: "safe" | "none";
  write_paths?: string[];
  protect_home?: "read-only" | "yes" | "no";
  memory_max_mib?: number;
  cpu_quota?: number;
  tasks_max?: number;
  enabled: boolean;
  created?: string;
  updated?: string;
  created_by?: string;
}

export interface Timer {
  name: string;
  description: string;
  active: string;
  file_state: string;
  unit: string;
  next?: string;
  last?: string;
  schedule?: string[];
  result?: string;
  exit_code?: number;
  service_active?: string;
}

export interface JobView extends Job {
  state: Timer;
  drift?: boolean;
}

export interface Preview {
  normalized?: string;
  next: string[];
  approx?: boolean;
}

export interface Run {
  invocation: string;
  start: string;
  end?: string;
  duration_ms?: number;
  result: string;
  exit_code?: number;
  excerpt?: string[];
}

export interface JobDetail extends JobView {
  service_unit: string;
  timer_unit: string;
  preview: Preview;
  history: Run[];
}

export interface FieldError {
  field: string;
  code: string;
}

export interface JobCheck {
  error?: FieldError;
  job: Job;
  preview: Preview;
  warnings: string[];
  service_unit: string;
  timer_unit: string;
}

export interface CronEntry {
  source: string;
  line: number;
  user?: string;
  schedule: string;
  command: string;
  next?: string[];
  reboot?: boolean;
  editable?: boolean;
  error?: string;
}

export interface CronFile {
  user: string;
  hash: string;
  entries: CronEntry[];
}

export interface Overview {
  managed: JobView[];
  timers: Timer[];
  cron: { installed: boolean; entries: CronEntry[]; users: string[] };
}

export interface CalendarResult {
  preview: Preview;
  error?: FieldError;
}

export const idRE = /^[a-z0-9][a-z0-9-]{0,47}$/;
export const pathRE = /^\/[A-Za-z0-9._/@+-]*$/;
export const timeRE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;
// eslint-disable-next-line no-control-regex
const controlRE = /[\u0000-\u001f\u007f]/;

/** Mirrors the server's checks of free text (no control characters). */
export function noControl(s: string): boolean {
  return !controlRE.test(s);
}

/** A clean absolute path the server accepts in a unit file. */
export function cleanPath(p: string): boolean {
  return pathRE.test(p) && !p.split("/").some((s) => s === ".." || s === ".") && !p.includes("//") && (p === "/" || !p.endsWith("/"));
}

/** Suggests a job id from a description ("Nightly backup" → "nightly-backup"). */
export function slug(s: string): string {
  return s
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/ß/g, "ss")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
    .replace(/-+$/, "");
}

/** Splits an argument line like a shell would for plain words and quotes,
 * but without any expansion: `a "b c" 'd'` → [a, b c, d]. undefined when a
 * quote is not closed. */
export function splitArgs(s: string): string[] | undefined {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && (s[i + 1] === '"' || s[i + 1] === "\\")) cur += s[++i];
      else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (c === " " || c === "\t") {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
    }
  }
  if (quote) return undefined;
  if (has || cur) out.push(cur);
  return out;
}

/** Joins arguments back into one line (quoting where needed). */
export function joinArgs(a: string[]): string {
  return a.map((x) => (x === "" || /[\s"'\\]/.test(x) ? `"${x.replace(/["\\]/g, (m) => `\\${m}`)}"` : x)).join(" ");
}

/** Plain-language description of a schedule. */
export function describe(t: TFunction, s: Schedule, lang: string): string {
  const days = (s.weekdays ?? [])
    .map((d) => {
      const i = weekdays.indexOf(d as (typeof weekdays)[number]);
      // 2024-01-01 was a Monday.
      return new Date(Date.UTC(2024, 0, 1 + i)).toLocaleDateString(lang, { weekday: "long", timeZone: "UTC" });
    })
    .join(", ");
  const tz = s.timezone ? ` (${s.timezone})` : "";
  switch (s.kind) {
    case "hourly":
      return t("jobs.describe.hourly", { minute: String(s.minute ?? 0).padStart(2, "0") });
    case "daily":
      return t("jobs.describe.daily", { time: s.time }) + tz;
    case "weekly":
      return t("jobs.describe.weekly", { days, time: s.time }) + tz;
    case "monthly":
      return t("jobs.describe.monthly", { day: s.day, time: s.time }) + tz;
    case "interval":
      return t(s.unit === "h" ? "jobs.describe.everyH" : "jobs.describe.everyMin", { count: s.every ?? 0 });
    case "calendar":
      return t("jobs.describe.calendar", { expr: s.calendar ?? "" }) + tz;
  }
}

/** Copy of a job for "duplicate": new id, disabled, no timestamps. */
export function duplicate(j: Job, taken: string[]): Job {
  let i = 2;
  const base = j.id.replace(/-\d+$/, "").slice(0, 44);
  while (taken.includes(`${base}-${i}`)) i++;
  return {
    ...j,
    id: `${base}-${i}`,
    enabled: false,
    created: undefined,
    updated: undefined,
    created_by: undefined,
  };
}
