// Types and helpers of the time and host page (M1.7c, DEC-033).

export interface TimeState {
  now: string;
  timezone: string;
  local_rtc: boolean;
  can_ntp: boolean;
  ntp: boolean;
  ntp_synced: boolean;
  rtc?: string;
  ntp_server?: string;
}

export interface HostState {
  hostname: string;
  static: string;
  pretty: string;
  chassis?: string;
  os?: string;
}

export interface Scheduled {
  type: string;
  at: string;
}

export interface Inhibitor {
  what: string;
  who: string;
  why: string;
  mode: string;
  uid: number;
  pid: number;
}

export interface TimeHost {
  time: TimeState | null;
  host: HostState | null;
  hosts_line: string;
  cloud_init_resets: boolean;
  boot_id: string;
  scheduled: Scheduled | null;
  inhibitors: Inhibitor[];
  errors?: string[];
}

export interface HostnamePlan {
  diff: string;
  cloud_init_resets: boolean;
  hosts_changed: boolean;
}

export interface PowerResult {
  action: "reboot" | "poweroff";
  at: string;
  boot_id: string;
}

export type PowerAction = PowerResult["action"];

/** Delays offered for a reboot or power-off, in minutes (0 = now). */
export const delays = [0, 1, 5, 15, 30, 60, 120, 240];

const labelRE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/** Why a static host name is rejected (same rule as the helper), or undefined. */
export function hostnameProblem(s: string): "empty" | "upper" | "dot" | "invalid" | undefined {
  if (s === "") return "empty";
  if (labelRE.test(s)) return undefined;
  if (labelRE.test(s.toLowerCase())) return "upper";
  if (s.includes(".")) return "dot";
  return "invalid";
}

/** The name a power action must be confirmed with (static, else kernel name). */
export function confirmName(h: HostState | null | undefined): string {
  return h ? h.static || h.hostname : "";
}

/** Formats an instant in a time zone (falls back to UTC for unknown zones). */
export function inZone(ms: number, tz: string, lang: string, withZone = true): string {
  // dateStyle/timeStyle cannot be combined with timeZoneName.
  const opts: Intl.DateTimeFormatOptions = {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    ...(withZone ? { timeZoneName: "short" } : {}),
  };
  try {
    return new Intl.DateTimeFormat(lang, { ...opts, timeZone: tz }).format(ms);
  } catch {
    return new Intl.DateTimeFormat(lang, { ...opts, timeZone: "UTC" }).format(ms);
  }
}

const utc = new Set(["UTC", "Etc/UTC", "Etc/Universal", "Etc/Zulu", "Universal", "Zulu"]);

/** Whether two zone names mean the same zone (only the UTC aliases are folded). */
export function sameZone(a: string, b: string): boolean {
  return a === b || (utc.has(a) && utc.has(b));
}

/** The browser's time zone, if the server lists it. */
export function browserZone(list: string[]): string | undefined {
  try {
    const z = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return list.includes(z) ? z : undefined;
  } catch {
    return undefined;
  }
}

/** Groups zone names by region ("Europe/Berlin" → "Europe"); single names go to "". */
export function groupZones(list: string[]): [string, string[]][] {
  const m = new Map<string, string[]>();
  for (const z of list) {
    const i = z.indexOf("/");
    const g = i < 0 ? "" : z.slice(0, i);
    m.set(g, [...(m.get(g) ?? []), z]);
  }
  return [...m.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
}

/** Seconds left until an instant, never negative. */
export function secondsUntil(at: string, now: number): number {
  return Math.max(0, Math.ceil((Date.parse(at) - now) / 1000));
}

/** "1:05:09" or "4:09" for a countdown. */
export function countdown(s: number): string {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
}

/** Phases of the reconnect overlay. */
export type Phase = "waiting" | "offline" | "back" | "timeout";

/** Next phase from one poll: ok with a boot id, or failed. */
export function nextPhase(phase: Phase, before: string, poll: { ok: true; bootId: string } | { ok: false }, elapsedMs: number, limitMs: number): Phase {
  if (phase === "back") return phase;
  if (poll.ok && poll.bootId && poll.bootId !== before) return "back";
  if (elapsedMs > limitMs) return "timeout";
  if (!poll.ok) return "offline";
  return phase === "timeout" ? "timeout" : phase;
}
