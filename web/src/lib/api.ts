// Minimal API client. Every state-changing request carries the CSRF header;
// the browser adds Origin (SPEC §3.5). Errors carry the stable `code` from
// the server's RFC 9457 problem document, which the UI translates.

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly correlationId?: string,
  ) {
    super(code);
  }
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";

let onUnauthorized: (() => void) | undefined;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

export async function api<T = unknown>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-Daemonia-CSRF"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api/v1${path}`, {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("Content-Type") ?? "";
  if (!res.ok) {
    let code = "internal_error";
    let cid: string | undefined;
    if (ct.includes("json")) {
      const p = (await res.json().catch(() => ({}))) as { code?: string; correlation_id?: string };
      code = p.code ?? code;
      cid = p.correlation_id;
    }
    if (res.status === 401 && code === "unauthorized" && onUnauthorized) onUnauthorized();
    throw new ApiError(res.status, code, cid);
  }
  return (ct.includes("json") ? await res.json() : undefined) as T;
}

export interface Account {
  id: string;
  name: string;
  role: "admin" | "operator" | "readonly";
  linux_user: string;
  passkeys: number;
}

export interface WhoAmI {
  account_id: string;
  role: Account["role"];
  linux_user: string;
  step_up: boolean;
}

export interface Passkey {
  id: string;
  name: string;
  backup_eligible: boolean;
  backup_state: boolean;
  created_at: string;
  last_used_at?: string;
}

export interface SetupState {
  setup_done: boolean;
  language: "de" | "en";
  domain?: string;
  port?: number;
  has_certificate?: boolean;
  tls_source?: string;
}

export interface CeremonyStart {
  ceremony_id: string;
  options: unknown;
}

export interface LinuxUser {
  name: string;
  uid: number;
  home: string;
}
