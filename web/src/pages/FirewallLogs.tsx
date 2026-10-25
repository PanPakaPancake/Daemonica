import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, type Column, type Filters } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, type MenuItem } from "../components/Modal";
import { Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { followEndText, useFollow } from "../lib/follow";
import { saveText } from "../lib/format";

export interface LogEntry {
  time: string;
  action: "allow" | "block" | "audit" | "log";
  limit?: boolean;
  prefix: string;
  direction: "in" | "out" | "forward";
  in?: string;
  out?: string;
  src: string;
  dst: string;
  proto: string;
  spt?: number;
  dpt?: number;
  flags?: string[];
  len?: number;
  ttl?: number;
  v6?: boolean;
}
interface LogResult {
  entries: LogEntry[];
  cursor?: string;
  truncated: boolean;
  scanned: number;
}

const ranges = { "15m": 15, "1h": 60, "24h": 1440, "7d": 10080 } as const;
type Range = keyof typeof ranges;
const actionTone: Record<string, string> = { allow: "text-ok", block: "text-bad", audit: "text-info", log: "text-muted" };
const MAX_LIVE = 5000;
// Column filter → server filter field.
const serverKeys: Record<string, string> = {
  action: "action",
  direction: "direction",
  iface: "iface",
  src: "src",
  spt: "spt",
  dst: "dst",
  dpt: "dpt",
  proto: "proto",
};

/** CSV cell with formula-injection protection. */
function csvCell(v: unknown): string {
  let s = v === undefined || v === null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n;]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

export function FirewallLogs({
  logging,
  isAdmin,
  onLogging,
  onBlock,
}: {
  logging?: string;
  isAdmin: boolean;
  onLogging: (level: string) => void;
  onBlock: (src: string) => void;
}) {
  const { t, i18n } = useTranslation();
  const [range, setRange] = useState<Range>("1h");
  const [lines, setLines] = useState(500);
  const [text, setText] = useState("");
  const [filters, setFilters] = useState<Filters>({});
  const [server, setServer] = useState<{ text: string; filters: Filters }>({ text: "", filters: {} });
  const [live, setLive] = useState(false);
  const [extra, setExtra] = useState<LogEntry[]>([]);
  const [skipped, setSkipped] = useState(0);
  const [stats, setStats] = useState(false);
  const [err, setErr] = useState<string>();

  // Text inputs reach the server after a short pause.
  useEffect(() => {
    const id = window.setTimeout(() => setServer({ text, filters }), 350);
    return () => window.clearTimeout(id);
  }, [text, filters]);

  const filter = useMemo(() => {
    const f: Record<string, string> = {};
    for (const [k, v] of Object.entries(server.filters)) if (v.trim() && serverKeys[k]) f[serverKeys[k]] = v.trim();
    if (server.text.trim()) f.text = server.text.trim();
    return f;
  }, [server]);

  const q = useQuery({
    queryKey: ["firewall-logs", range, lines, filter],
    queryFn: async () => {
      const r = await api<LogResult>("POST", "/firewall/logs", { since: new Date(Date.now() - ranges[range] * 60_000).toISOString(), lines, filter });
      setExtra([]);
      setSkipped(0);
      return r;
    },
  });
  // useFollow reconnects only when the serialized params change.
  const start = q.data?.cursor;
  const followParams = live && start ? { filter, after: start } : undefined;
  useFollow<LogEntry>(
    "firewall.logs",
    followParams,
    (es, sk) => {
      setExtra((x) => [...x, ...es].slice(-MAX_LIVE));
      if (sk) setSkipped((n) => n + sk);
    },
    (reason) => {
      setErr(followEndText(t, reason));
      setLive(false);
    },
  );
  const rows = useMemo(() => [...(q.data?.entries ?? []), ...extra], [q.data, extra]);
  const fmt = (s: string) => new Date(s).toLocaleString(i18n.language);

  const items = (e: LogEntry): MenuItem[] => [
    { label: t("firewall.logs.filterSrc"), icon: "filter", onSelect: () => setFilters((f) => ({ ...f, src: e.src })) },
    { label: t("firewall.logs.filterDpt"), icon: "filter", disabled: !e.dpt, onSelect: () => setFilters((f) => ({ ...f, dpt: String(e.dpt) })) },
    {
      label: t("firewall.logs.copy"),
      icon: "copy",
      onSelect: () => void navigator.clipboard?.writeText(`${e.time} ${e.prefix} ${e.proto} ${e.src}:${e.spt ?? ""} -> ${e.dst}:${e.dpt ?? ""}`),
    },
    { label: t("firewall.logs.block"), icon: "lock", danger: true, disabled: !isAdmin || e.direction !== "in", onSelect: () => onBlock(e.src) },
  ];

  const cols: Column<LogEntry>[] = [
    { key: "time", label: t("firewall.logs.col.time"), sortValue: (e) => e.time, filter: false, tdClass: "whitespace-nowrap", cell: (e) => fmt(e.time) },
    {
      key: "action",
      label: t("firewall.col.action"),
      sortValue: (e) => e.action,
      filter: { options: ["block", "allow", "audit", "log"].map((x) => ({ value: x, label: t(`firewall.logs.action.${x}`) })) },
      cell: (e) => (
        <span className={`font-semibold ${actionTone[e.action] ?? ""}`} title={e.prefix}>
          {t(`firewall.logs.action.${e.action}`)}
          {e.limit && <span className="ml-1 font-normal text-faint">({t("firewall.action.limit")})</span>}
        </span>
      ),
    },
    {
      key: "direction",
      label: t("firewall.col.direction"),
      sortValue: (e) => e.direction,
      filter: { options: ["in", "out", "forward"].map((x) => ({ value: x, label: t(`firewall.logs.dir.${x}`) })) },
      cell: (e) => t(`firewall.logs.dir.${e.direction}`),
    },
    {
      key: "iface",
      label: t("firewall.col.iface"),
      sortValue: (e) => [e.in, e.out].filter(Boolean).join(" → "),
      filter: "text",
      tdClass: "font-mono text-sm",
      cell: (e) => [e.in, e.out].filter(Boolean).join(" → ") || "—",
    },
    { key: "src", label: t("firewall.col.src"), sortValue: (e) => e.src, filter: "text", tdClass: "font-mono text-sm", cell: (e) => e.src },
    { key: "spt", label: t("firewall.logs.col.spt"), sortValue: (e) => e.spt ?? "", filter: "text", tdClass: "font-mono text-sm", cell: (e) => e.spt ?? "—" },
    { key: "dst", label: t("firewall.col.dst"), sortValue: (e) => e.dst, filter: "text", tdClass: "font-mono text-sm", cell: (e) => e.dst },
    { key: "dpt", label: t("firewall.logs.col.dpt"), sortValue: (e) => e.dpt ?? "", filter: "text", tdClass: "font-mono text-sm", cell: (e) => e.dpt ?? "—" },
    {
      key: "proto",
      label: t("network.col.proto"),
      sortValue: (e) => e.proto,
      filter: { options: ["tcp", "udp", "icmp", "icmpv6"].map((x) => ({ value: x, label: x.toUpperCase() })) },
      cell: (e) => e.proto.toUpperCase() || "—",
    },
    {
      key: "flags",
      label: t("firewall.logs.col.flags"),
      sortValue: (e) => (e.flags ?? []).join(" "),
      filter: false,
      tdClass: "font-mono text-xs",
      cell: (e) => (e.flags ?? []).join(" "),
    },
    {
      key: "len",
      label: t("firewall.logs.col.len"),
      sortValue: (e) => e.len ?? 0,
      filter: false,
      tdClass: "text-right tabular-nums",
      cell: (e) => e.len ?? "",
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (e) => <Menu label={t("firewall.logs.actionsFor", { src: e.src })} items={items(e)} />,
    },
  ];

  const exportAs = (kind: "csv" | "json") => {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (kind === "json") return saveText(`firewall-log-${stamp}.json`, JSON.stringify(rows, null, 2), "application/json");
    const head = ["time", "action", "prefix", "direction", "in", "out", "src", "spt", "dst", "dpt", "proto", "flags", "len", "ttl"];
    const body = rows.map((e) =>
      [e.time, e.action, e.prefix, e.direction, e.in, e.out, e.src, e.spt, e.dst, e.dpt, e.proto, (e.flags ?? []).join(" "), e.len, e.ttl]
        .map(csvCell)
        .join(","),
    );
    saveText(`firewall-log-${stamp}.csv`, [head.join(","), ...body].join("\n") + "\n", "text/csv");
  };

  return (
    <section className="flex flex-col gap-3">
      {logging === "off" && (
        <Notice tone="warn">
          <p>{t("firewall.logs.off")}</p>
          {isAdmin && (
            <button type="button" className="btn btn-primary mt-2" onClick={() => onLogging("low")}>
              {t("firewall.logs.enable")}
            </button>
          )}
        </Notice>
      )}
      {(logging === "high" || logging === "full") && <Notice tone="warn">{t("firewall.logs.highWarn")}</Notice>}
      <p className="text-sm text-muted">{t("firewall.logs.intro")}</p>

      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <label className="shrink-0">
          <span className="sr-only">{t("firewall.logs.range")}</span>
          <select className="input min-h-9 py-1" value={range} onChange={(e) => setRange(e.target.value as Range)}>
            {Object.keys(ranges).map((r) => (
              <option key={r} value={r}>
                {t(`firewall.logs.ranges.${r}`)}
              </option>
            ))}
          </select>
        </label>
        <label className="relative min-w-40 flex-1">
          <span className="sr-only">{t("firewall.logs.search")}</span>
          <Icon name="search" className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input className="input min-h-9 w-full py-1 pl-9" placeholder={t("firewall.logs.search")} value={text} onChange={(e) => setText(e.target.value)} />
        </label>
        <label className="shrink-0">
          <span className="sr-only">{t("firewall.logs.lines")}</span>
          <select className="input min-h-9 py-1" value={lines} onChange={(e) => setLines(Number(e.target.value))} title={t("firewall.logs.lines")}>
            {[500, 2000].map((n) => (
              <option key={n} value={n}>
                {t("firewall.logs.linesN", { n })}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          aria-pressed={live}
          className={`btn min-h-9 shrink-0 ${live ? "btn-primary" : "btn-secondary"}`}
          onClick={() => {
            setErr(undefined);
            setLive(!live);
          }}
        >
          <Icon name="signal" className="h-4 w-4" />
          {t("firewall.logs.live")}
          {live && <span className="h-2 w-2 animate-pulse rounded-full bg-ok" aria-hidden="true" />}
        </button>
        <button
          type="button"
          aria-pressed={stats}
          className={`btn min-h-9 shrink-0 ${stats ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setStats(!stats)}
        >
          <Icon name="overview" className="h-4 w-4" />
          {t("firewall.logs.stats")}
        </button>
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={() => void q.refetch()}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!rows.length}
          onClick={() => exportAs("csv")}
          title={t("firewall.logs.exportCsv")}
        >
          <Icon name="download" className="h-4 w-4" />
          CSV
        </button>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!rows.length}
          onClick={() => exportAs("json")}
          title={t("firewall.logs.exportJson")}
        >
          <Icon name="download" className="h-4 w-4" />
          JSON
        </button>
      </div>

      {(q.isError || err) && <Notice tone="bad">{err ?? errorText(t, q.error)}</Notice>}
      {q.data && (
        <p className="text-sm text-faint">
          {t("firewall.logs.summary", { count: rows.length, scanned: q.data.scanned })}
          {q.data.truncated && ` · ${t("firewall.logs.truncated")}`}
          {skipped > 0 && <span className="text-warn"> · {t("common.skipped", { count: skipped })}</span>}
        </p>
      )}
      {stats && rows.length > 0 && <Stats rows={rows} />}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("firewall.tab.logs")}
          columns={cols}
          rows={rows}
          rowKey={(e) => `${e.time}-${e.src}-${e.spt ?? 0}-${e.dst}-${e.dpt ?? 0}-${e.proto}`}
          loading={q.isLoading}
          defaultSort={{ key: "time", desc: true }}
          filters={filters}
          onFilters={setFilters}
          className="min-w-[900px]"
          rowMenu={(e) => ({ label: t("firewall.logs.actionsFor", { src: e.src }), items: items(e) })}
          empty={t("firewall.logs.empty")}
        />
      </div>
    </section>
  );
}

function top(rows: LogEntry[], key: (e: LogEntry) => string | undefined, n = 5): [string, number][] {
  const m = new Map<string, number>();
  for (const e of rows) {
    const k = key(e);
    if (k) m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function Stats({ rows }: { rows: LogEntry[] }) {
  const { t, i18n } = useTranslation();
  const blocked = rows.filter((e) => e.action === "block");
  const actions = top(rows, (e) => e.action, 4);
  const srcs = top(blocked, (e) => e.src);
  const ports = top(blocked, (e) => (e.dpt ? `${e.dpt}/${e.proto}` : undefined));
  // Histogram over the covered time span in 30 buckets.
  const times = rows.map((e) => Date.parse(e.time)).filter(Number.isFinite);
  const lo = Math.min(...times);
  const hi = Math.max(...times);
  const buckets = Array.from({ length: 30 }, () => ({ block: 0, other: 0 }));
  for (const e of rows) {
    const x = Date.parse(e.time);
    const i = hi > lo ? Math.min(29, Math.floor(((x - lo) / (hi - lo)) * 30)) : 29;
    const b = buckets[i];
    if (b) b[e.action === "block" ? "block" : "other"]++;
  }
  const peak = Math.max(1, ...buckets.map((b) => b.block + b.other));
  const list = (title: string, items: [string, number][]) => (
    <div className="min-w-0">
      <h3 className="mb-1 text-sm font-semibold">{title}</h3>
      {items.length === 0 ? (
        <p className="text-sm text-faint">—</p>
      ) : (
        <ol className="flex flex-col gap-0.5 text-sm">
          {items.map(([k, n]) => (
            <li key={k} className="flex justify-between gap-3">
              <span className="truncate font-mono">{k}</span>
              <span className="tabular-nums text-muted">{n.toLocaleString(i18n.language)}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
  return (
    <Panel>
      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
        {list(
          t("firewall.logs.perAction"),
          actions.map(([k, n]) => [t(`firewall.logs.action.${k}`), n]),
        )}
        {list(t("firewall.logs.topSources"), srcs)}
        {list(t("firewall.logs.topPorts"), ports)}
        <div className="min-w-0">
          <h3 className="mb-1 text-sm font-semibold">{t("firewall.logs.timeline")}</h3>
          <div
            className="flex h-20 items-end gap-px"
            role="img"
            aria-label={t("firewall.logs.timelineLabel", { from: new Date(lo).toLocaleString(i18n.language), to: new Date(hi).toLocaleString(i18n.language) })}
          >
            {buckets.map((b, i) => (
              <div key={i} className="flex flex-1 flex-col justify-end">
                <div className="bg-bad/80" style={{ height: `${(b.block / peak) * 80}px` }} />
                <div className="bg-cyan/60" style={{ height: `${(b.other / peak) * 80}px` }} />
              </div>
            ))}
          </div>
          <p className="mt-1 flex justify-between text-xs text-faint">
            <span>{Number.isFinite(lo) ? new Date(lo).toLocaleTimeString(i18n.language) : ""}</span>
            <span>{Number.isFinite(hi) ? new Date(hi).toLocaleTimeString(i18n.language) : ""}</span>
          </p>
        </div>
      </div>
    </Panel>
  );
}
