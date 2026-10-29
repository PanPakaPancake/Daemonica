// Dashboard certificate (SPEC §3.6, DEC-034): types and pure helpers shared by
// the setup wizard and the settings page.

export type CertMethod = "http-01" | "tls-alpn-01" | "dns-01";
export type CertMode = CertMethod | "own";
export type CA = "production" | "staging";
export type IssueState = "running" | "dns_wait" | "dns_check" | "done" | "failed" | "canceled";

export interface CertInfo {
  domain: string;
  names?: string[];
  issuer?: string;
  not_after: string;
  days_left: number;
  source: string;
}

export interface Issuance {
  method: CertMethod;
  ca: CA;
  state: IssueState;
  renewal?: boolean;
  record?: { name: string; value: string };
  check?: string;
  checks?: number;
  error?: string;
  started: string;
  finished?: string;
  cert?: CertInfo;
}

export interface CertView {
  domain: string;
  cert?: CertInfo;
  source?: string;
  method?: string;
  auto_renew: boolean;
  renew_days: number;
  issuance?: Issuance;
}

export const methods: CertMode[] = ["http-01", "tls-alpn-01", "dns-01", "own"];

export function running(i: Issuance | undefined): boolean {
  return !!i && (i.state === "running" || i.state === "dns_wait" || i.state === "dns_check");
}

/** Health of the installed certificate for badges: ok, warn (< renew days), bad (expired). */
export function certTone(c: CertInfo | undefined, renewDays: number): "ok" | "warn" | "bad" {
  if (!c || c.days_left < 0) return "bad";
  return c.days_left < renewDays ? "warn" : "ok";
}

/** Staging certificates are issued by "(STAGING) …" intermediates; browsers do not trust them. */
export function isStaging(c: CertInfo | undefined): boolean {
  return !!c && (c.source === "acme-staging" || /staging/i.test(c.issuer ?? ""));
}

/** Zone-relative name for DNS panels that want the host part only ("_acme-challenge.dash" in zone "example.org"). */
export function relativeName(fqdn: string, zone: string): string {
  const f = fqdn.replace(/\.$/, "").toLowerCase();
  const z = zone.replace(/\.$/, "").toLowerCase();
  if (z && f.endsWith("." + z)) return f.slice(0, -z.length - 1);
  return f;
}

/** The registrable zone guess for the hint (last two labels; good enough for a display hint). */
export function zoneGuess(domain: string): string {
  const parts = domain.replace(/\.$/, "").split(".");
  return parts.slice(-2).join(".");
}
