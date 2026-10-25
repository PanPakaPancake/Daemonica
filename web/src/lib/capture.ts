// Packet capture types and the client-side filter preview (SPEC §7.6 M1.5d).
// The server builds the real BPF expression; the preview mirrors
// capture.Spec.Filter so the wizard can show it before the start.

export interface Builder {
  proto?: "" | "tcp" | "udp" | "icmp" | "arp";
  host?: string;
  ports?: number[];
  dir?: "" | "src" | "dst";
}

export interface Spec {
  template?: string;
  iface: string;
  builder: Builder;
  expr?: string;
  duration_sec?: number;
  packets?: number;
  size_bytes?: number;
  full_packets?: boolean;
  promisc?: boolean;
  include_dashboard?: boolean;
  accept_warning: boolean;
  accept_full_warning?: boolean;
}

export interface Meta {
  id: string;
  template?: string;
  iface: string;
  filter: string;
  snaplen: number;
  promisc: boolean;
  duration_sec: number;
  packets: number;
  size_bytes: number;
  started: string;
  ended?: string;
  state: "running" | "done" | "failed";
  reason?: string;
  error?: string;
  captured: number;
  bytes: number;
  account?: string;
}

export interface Stats {
  packets: number;
  bytes: number;
  protos: Record<string, number>;
  talkers: { host: string; packets: number; bytes: number }[];
  seconds: number;
  pps: number;
  bps: number;
}

export interface Status {
  available: boolean;
  installable: boolean;
  ifaces: string[];
  dashboard_port: number;
  current?: { meta: Meta; stats: Stats };
  captures: Meta[];
  retention_hours: number;
  total_bytes: number;
  total_limit: number;
}

export interface Line {
  seq: number;
  time: string;
  src: string;
  dst: string;
  proto: string;
  len: number;
  info: string;
}

export interface Lines {
  entries: Line[];
  cursor: string;
  truncated: boolean;
  skipped: number;
  running: boolean;
}

export const templates = ["host", "port", "dns", "dhcp", "headers", "custom"] as const;
export type Template = (typeof templates)[number];

/** Builder preset of a purpose template. */
export function templateBuilder(t: Template): Builder {
  switch (t) {
    case "port":
      return { proto: "tcp", dir: "dst", ports: [] };
    case "dns":
      return { proto: "udp", ports: [53] };
    case "dhcp":
      return { proto: "udp", ports: [67, 68] };
    default:
      return { proto: "" };
  }
}

/** Parses "53, 67 68" into ports; undefined when invalid. */
export function parsePorts(s: string): number[] | undefined {
  const parts = s.split(/[\s,]+/).filter(Boolean);
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,5}$/.test(p)) return undefined;
    const n = Number(p);
    if (n < 1 || n > 65535) return undefined;
    out.push(n);
  }
  return out.length > 10 ? undefined : out;
}

/** Same allowlist as the server (capture.exprRE). */
export function exprAllowed(s: string): boolean {
  const e = s.trim().split(/\s+/).join(" ");
  return e === "" || (/^[A-Za-z0-9 .:/()[\]!&|=<>+*-]{1,512}$/.test(e) && !e.startsWith("-"));
}

/** Mirror of capture.Spec.Filter. */
export function filterPreview(s: Pick<Spec, "builder" | "expr" | "include_dashboard">, dashboardPort: number): string {
  const parts: string[] = [];
  const expr = (s.expr ?? "").trim().split(/\s+/).join(" ");
  if (expr) {
    parts.push(`(${expr})`);
  } else {
    const b = s.builder;
    const dir = b.dir ? `${b.dir} ` : "";
    if (b.proto === "icmp") parts.push("(icmp or icmp6)");
    else if (b.proto) parts.push(b.proto);
    const host = b.host?.trim();
    if (host) parts.push(`${dir}${host.includes("/") ? "net" : "host"} ${host}`);
    if (b.ports?.length) parts.push(`(${b.ports.map((p) => `${dir}port ${p}`).join(" or ")})`);
  }
  if (!s.include_dashboard && dashboardPort > 0) parts.push(`not (tcp port ${dashboardPort})`);
  return parts.join(" and ");
}
