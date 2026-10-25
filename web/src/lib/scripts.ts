// Script library (DEC-030): types of the scripts.* helper operations and
// small helpers shared by the library tab, the job wizard and the terminal.
import type { FieldError } from "./jobs";

export const LOCAL = "local";

export interface Commit {
  sha: string;
  message?: string;
  author?: string;
  date: string;
}

export interface Source {
  id: string;
  repo: string;
  ref?: string;
  subdir?: string;
  commit: Commit;
  added: string;
  updated: string;
  by?: string;
  has_token: boolean;
}

export interface ScriptFile {
  source: string;
  path: string;
  abs: string;
  size: number;
  exec: boolean;
  sha256: string;
  modified: string;
  shebang?: string;
  used_by?: string[];
}

export interface Library {
  root: string;
  sources: Source[];
  files: ScriptFile[];
}

export interface Content {
  text: boolean;
  content?: string;
  hash: string;
  /** -1 when the file is too large to show. */
  size: number;
}

export interface Change {
  path: string;
  status: "added" | "removed" | "modified" | "mode";
  exec: boolean;
  binary?: boolean;
  diff?: string;
  omitted?: boolean;
  used_by?: string[];
}

export interface Skipped {
  path: string;
  reason: "name" | "symlink" | "size";
}

export interface Candidate {
  commit: Commit;
  files: number;
  size: number;
  changes: Change[];
  skipped: Skipped[];
  current?: boolean;
}

export interface Spec {
  id?: string;
  repo: string;
  ref?: string;
  subdir?: string;
  token?: string;
}

export interface CandidateResult {
  candidate?: Candidate;
  spec?: Spec;
  error?: FieldError;
}

export const nameRE = /^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,127}$/;
export const sourceIdRE = /^[a-z0-9][a-z0-9-]{0,39}$/;

/** Accepts "owner/name" or a GitHub URL, like the server. */
export function normalizeRepo(s: string): string | undefined {
  const r = s
    .trim()
    .replace(/^https:\/\//, "")
    .replace(/^github\.com\//, "")
    .replace(/\/$/, "")
    .replace(/\.git$/, "");
  return /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(r) ? r : undefined;
}

export const shortSha = (sha: string) => sha.slice(0, 7);

/** The interpreter a job needs for a non-executable file, from its shebang
 * or file name ("" when it can run directly or nothing fits). */
export function interpreterFor(f: Pick<ScriptFile, "exec" | "shebang" | "path">): string {
  if (f.exec) return "";
  const s = f.shebang ?? "";
  if (/python/.test(s) || f.path.endsWith(".py")) return "/usr/bin/python3";
  if (/perl/.test(s) || f.path.endsWith(".pl")) return "/usr/bin/perl";
  if (/bash/.test(s) || f.path.endsWith(".bash")) return "/bin/bash";
  if (/\bsh\b/.test(s) || f.path.endsWith(".sh")) return "/bin/sh";
  return "";
}

/** Command line typed into a terminal to run a library file (not sent). */
export function terminalCommand(f: Pick<ScriptFile, "exec" | "shebang" | "path" | "abs">): string {
  const i = interpreterFor(f);
  return `${i ? i + " " : ""}${f.abs} `;
}
