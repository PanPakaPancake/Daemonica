// File manager API (SPEC §7.4). Every request carries `as_root` while the
// session's root mode is active; the helper decides everything else.
import { api, ApiError } from "./api";

export interface FsEntry {
  name: string;
  raw?: string;
  display?: string;
  type: "file" | "dir" | "symlink" | "fifo" | "socket" | "char" | "block" | "other";
  size: number;
  mode: number;
  uid: number;
  gid: number;
  user?: string;
  group?: string;
  mtime: string;
  target?: string;
  target_type?: string;
  blocked?: boolean;
}

export interface FsListing {
  path: string;
  entries: FsEntry[];
  total: number;
  truncated?: boolean;
  writable: boolean;
  virtual?: boolean;
}

export interface FsStat extends FsEntry {
  path: string;
  atime: string;
  ctime: string;
  btime?: string;
  nlink: number;
  inode: number;
  readable: boolean;
  writable: boolean;
  sensitive?: boolean;
  virtual?: boolean;
}

export interface FsInfo {
  home: string;
  root: { active: boolean; until?: string };
  upload_limit_mib: number;
  edit_limit: number;
}

export interface FileContent {
  path: string;
  dir: string;
  name: string;
  size: number;
  mtime: string;
  mode: number;
  user?: string;
  group?: string;
  hash?: string;
  binary?: boolean;
  too_large?: boolean;
  writable: boolean;
  content?: string;
}

export interface Target {
  dir: string;
  name?: string;
  raw?: string;
}

export function targetOf(dir: string, e: FsEntry): Target {
  return e.raw ? { dir, raw: e.raw } : { dir, name: e.name };
}

export function joinPath(dir: string, name: string): string {
  return dir === "/" ? `/${name}` : `${dir}/${name}`;
}

export function parentOf(p: string): string {
  if (p === "/") return "/";
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

export function shownName(e: FsEntry): string {
  return e.display ?? e.name;
}

export function isDir(e: FsEntry): boolean {
  return e.type === "dir" || (e.type === "symlink" && e.target_type === "dir");
}

/** rwxr-x--- with s/S/t/T, like ls. */
export function modeString(m: number): string {
  const b = "rwxrwxrwx".split("").map((c, i) => (m & (1 << (8 - i)) ? c : "-"));
  const sp = (bit: number, i: number, set: string, unset: string) => {
    if (m & bit) b[i] = b[i] === "x" ? set : unset;
  };
  sp(0o4000, 2, "s", "S");
  sp(0o2000, 5, "s", "S");
  sp(0o1000, 8, "t", "T");
  return b.join("");
}

export function octal(m: number): string {
  return (m & 0o7777).toString(8).padStart(4, "0");
}

export interface Flags {
  as_root?: boolean;
  confirm_sensitive?: boolean;
}

export function fsCall<T>(op: string, body: Record<string, unknown>, flags: Flags): Promise<T> {
  return api<T>("POST", `/files/${op}`, { ...body, ...clean(flags) });
}

function clean(f: Flags): Flags {
  const o: Flags = {};
  if (f.as_root) o.as_root = true;
  if (f.confirm_sensitive) o.confirm_sensitive = true;
  return o;
}

/** JSON with every non-ASCII character escaped, safe for an HTTP header value. */
function headerJSON(v: unknown): string {
  return JSON.stringify(v).replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

async function problem(res: Response): Promise<ApiError> {
  let code = "internal_error";
  let cid: string | undefined;
  if ((res.headers.get("Content-Type") ?? "").includes("json")) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; correlation_id?: string };
    code = p.code ?? code;
    cid = p.correlation_id;
  }
  return new ApiError(res.status, code, cid);
}

export async function readFile(t: Target, flags: Flags): Promise<FileContent> {
  return api<FileContent>("POST", "/files/content/read", { ...t, ...clean(flags) });
}

/** Check of a known configuration file (sshd -t, visudo -c, nginx -t, …). */
export interface Validation {
  tool: string;
  ok: boolean;
  skipped?: boolean;
  output?: string;
  /** No "save anyway" (sudoers). */
  blocking?: boolean;
  /** The save was undone because the check failed. */
  rolled_back?: boolean;
}

export interface WriteResult {
  path: string;
  hash: string;
  size: number;
  mtime: string;
  atomic: boolean;
  /** false when the check blocked or undid the save. */
  saved: boolean;
  validation?: Validation;
  /** Id of the stored previous version (files below /etc). */
  version?: string;
}

export async function writeFile(t: Target, content: string, expectedHash: string | undefined, flags: Flags, force = false): Promise<WriteResult> {
  const res = await fetch("/api/v1/files/content", {
    method: "PUT",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "X-Daemonica-CSRF": "1",
      "Content-Type": "application/octet-stream",
      "X-Daemonica-Params": headerJSON({ ...t, expected_hash: expectedHash ?? "", ...(force ? { force: true } : {}), ...clean(flags) }),
    },
    body: new TextEncoder().encode(content),
  });
  if (!res.ok) throw await problem(res);
  return (await res.json()) as WriteResult;
}

export interface FileVersion {
  id: string;
  time: string;
  size: number;
  hash: string;
  account?: string;
}

export interface FileVersions {
  path: string;
  versioned: boolean;
  versions: FileVersion[];
}

export function listVersions(t: Target, flags: Flags): Promise<FileVersions> {
  return fsCall<FileVersions>("versions", { ...t }, flags);
}

export function readVersion(t: Target, id: string, flags: Flags): Promise<{ path: string; version: FileVersion; content?: string }> {
  return api("POST", "/files/versions/read", { ...t, id, ...clean(flags) });
}

export interface UploadResult {
  path: string;
  size: number;
  sha256: string;
}

/** Uploads one file with progress; abort via the signal. */
export function uploadFile(
  file: File,
  dir: string,
  opts: { overwrite?: boolean; mode?: number } & Flags,
  onProgress: (loaded: number) => void,
  signal: AbortSignal,
): Promise<UploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", "/api/v1/files/upload");
    xhr.setRequestHeader("X-Daemonica-CSRF", "1");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    const params: Record<string, unknown> = { dir, name: file.name, size: file.size, ...clean(opts) };
    if (opts.overwrite) params.overwrite = true;
    if (opts.mode) params.mode = opts.mode;
    xhr.setRequestHeader("X-Daemonica-Params", headerJSON(params));
    xhr.responseType = "json";
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => {
      const body = xhr.response as { code?: string; correlation_id?: string } | null;
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response as UploadResult);
      else reject(new ApiError(xhr.status, body?.code ?? "internal_error", body?.correlation_id));
    };
    xhr.onerror = () => reject(new ApiError(0, "unavailable"));
    xhr.onabort = () => reject(new ApiError(0, "aborted"));
    signal.addEventListener("abort", () => xhr.abort(), { once: true });
    xhr.send(file);
  });
}

/** Requests a one-time token (60 s) and lets the browser download the file. */
export async function downloadFile(t: Target, flags: Flags): Promise<void> {
  const { token } = await fsCall<{ token: string }>("download_token", { ...t }, flags);
  const a = document.createElement("a");
  a.href = `/api/v1/files/download/${encodeURIComponent(token)}`;
  a.rel = "noopener";
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
