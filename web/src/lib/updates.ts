// Types and helpers of the updates page (M1.7a, DEC-031).

export type Kind = "update" | "upgrade" | "selected" | "install" | "remove" | "purge" | "autoremove" | "dry-run" | "repair";

export interface Pkg {
  name: string;
  arch?: string;
  old?: string;
  new?: string;
  origins?: string[];
  security: boolean;
}

export interface Sim {
  install: Pkg[];
  remove: Pkg[];
  kept: string[];
}

export interface Holder {
  pid: number;
  comm: string;
  file: string;
}

export type JobState = "running" | "succeeded" | "failed" | "unknown";

export interface AptJob {
  id: string;
  kind: Kind;
  packages: string[];
  account: string;
  started: string;
  ended?: string;
  state: JobState;
  result?: string;
  exit: number;
  phase?: "lock" | "download" | "install";
  percent: number;
  current?: string;
  issues: string[];
  conffiles: string[];
  restore_auto?: string[];
}

export interface Distro {
  id: string;
  version: string;
  codename: string;
  pretty: string;
}

export interface Overview {
  distro: Distro;
  kernel: string;
  last_update?: string;
  upgrade: Sim;
  security: number;
  sim_error?: string;
  reboot: boolean;
  reboot_pkgs: string[];
  lock?: Holder;
  /** Packages whose installation was interrupted (dpkg state U, F, h, W, t). */
  broken: string[];
  running?: AptJob;
  last?: AptJob;
}

export interface Plan {
  kind: Kind;
  sim: Sim;
  critical: string[];
  protected: boolean;
  error?: string;
}

export interface JobLog {
  job: AptJob;
  log: string;
  next: number;
}

export interface NeedRestart {
  available: boolean;
  kernel: number;
  kernel_current?: string;
  kernel_expected?: string;
  microcode: number;
  services: string[];
  containers: string[];
  sessions: string[];
}

export interface Installed {
  name: string;
  version: string;
  arch: string;
  status: string;
  auto: boolean;
  size_kib: number;
  section?: string;
  summary?: string;
}

export interface Found {
  name: string;
  summary: string;
  installed?: string;
  candidate?: string;
}

export interface SourceEntry {
  file: string;
  line: number;
  format: "one-line" | "deb822";
  enabled: boolean;
  types: string[];
  uris: string[];
  suites: string[];
  components: string[];
  signed_by?: string;
  https: boolean;
  official: boolean;
}

export interface Sources {
  entries: SourceEntry[];
  files: { path: string; entries: number; errors?: string[] }[];
}

export interface UnattendedWanted {
  enabled: boolean;
  auto_reboot: boolean;
  reboot_time: string;
}

export interface Unattended {
  installed: boolean;
  version?: string;
  managed: boolean;
  wanted?: UnattendedWanted;
  update_lists: boolean;
  upgrade: boolean;
  auto_reboot: boolean;
  reboot_time?: string;
  origins: string[];
  patterns: string[];
  security_only: boolean;
  log: string;
  last_run?: string;
  supported: boolean;
}

/** Package name check (same rule as the helper). */
export const pkgNameRE = /^[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9-]{1,20})?$/;

/** Search term check (same rule as the helper). */
export const termRE = /^[A-Za-z0-9][A-Za-z0-9+._-]{1,63}$/;

/** Reboot time check (HH:MM). */
export const hhmmRE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

/** The suite part of an archive name: "Ubuntu:26.04/resolute-security" → "resolute-security". */
export function suiteOf(origin: string): string {
  const i = origin.lastIndexOf("/");
  return i >= 0 ? origin.slice(i + 1) : origin;
}

/** Upgrades (packages already installed) of a simulation. */
export function upgrades(s: Sim | undefined): Pkg[] {
  return (s?.install ?? []).filter((p) => !!p.old);
}

/** Names of the security upgrades. */
export function securityNames(s: Sim | undefined): string[] {
  return upgrades(s)
    .filter((p) => p.security)
    .map((p) => p.name);
}

/** Removals that were not asked for (dependencies apt removes too). */
export function extraRemovals(plan: Plan, asked: string[]): string[] {
  const a = new Set(asked.map((n) => n.replace(/:.*$/, "")));
  return plan.sim.remove.map((p) => p.name).filter((n) => !a.has(n.replace(/:.*$/, "")));
}

/** Sorted, unique removal names as the helper compares them. */
export function removalNames(plan: Plan): string[] {
  return [...new Set(plan.sim.remove.map((p) => p.name))].sort();
}

/** Appends a log chunk and keeps at most max characters (oldest dropped at a line). */
export function appendLog(cur: string, chunk: string, max = 1_000_000): string {
  const s = cur + chunk;
  if (s.length <= max) return s;
  const cut = s.indexOf("\n", s.length - max);
  return cut >= 0 ? s.slice(cut + 1) : s.slice(s.length - max);
}

/** dpkg status abbreviation → translation key part. */
export function statusKey(abbrev: string): "installed" | "held" | "config" | "broken" | "other" {
  if (abbrev.length > 2 && abbrev[2] !== " ") return "broken";
  if (abbrev.startsWith("ii")) return "installed";
  if (abbrev.startsWith("hi")) return "held";
  if (abbrev.startsWith("rc")) return "config";
  return "other";
}
