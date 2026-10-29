import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { Icon } from "../components/icons";
import { Meter, Notice, Panel, Stat } from "../components/ui";
import { api, type Passkey } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, duration, num, pct, rate, relative } from "../lib/format";
import { DataTable } from "../components/DataTable";

export interface ProcessInfo {
  pid: number;
  ppid: number;
  uid: number;
  user: string;
  state: string;
  name: string;
  command: string;
  cpu: number;
  rss: number;
  start: string;
  threads: number;
}

interface MountInfo {
  device: string;
  mountpoint: string;
  fstype: string;
  total: number;
  used: number;
  available: number;
  used_pct: number;
  inodes_total: number;
  inodes_used: number;
  inodes_pct: number;
  read_only: boolean;
}

interface Overview {
  hostname: string;
  os: string;
  kernel: string;
  uptime_sec: number;
  cpus: number;
  cpu_pct: number;
  load: [number, number, number];
  memory: { total: number; available: number; used: number; cached: number; swap_total: number; swap_used: number };
  mounts: MountInfo[] | null;
  interfaces: { name: string; state: string; mac: string; rx_bps: number; tx_bps: number; errors: number }[] | null;
  processes: number;
  top: ProcessInfo[] | null;
  reboot_required: boolean;
  reboot_pkgs?: string[];
  failed_units?: number;
  cert_days_left?: number;
  updates?: { total: number; security: number; auto_security?: boolean };
  last_logins?: { user: string; from: string; tty: string; time: string; end?: string }[];
}

export function OverviewPage() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const q = useQuery({
    queryKey: ["overview"],
    queryFn: () => api<Overview>("GET", "/system/overview"),
    refetchInterval: 3000,
  });
  const pk = useQuery({ queryKey: ["passkeys"], queryFn: () => api<Passkey[]>("GET", "/passkeys") });
  // Same query as the firewall page, so a change there updates the checklist.
  const fw = useQuery({ queryKey: ["firewall"], queryFn: () => api<{ active: boolean }>("GET", "/firewall"), staleTime: 60_000 });
  const o = q.data;

  const certOk = o?.cert_days_left !== undefined && o.cert_days_left >= 30;
  const items = [
    { key: "cert", done: certOk },
    { key: "allowlist", done: true },
    { key: "secondPasskey", done: (pk.data?.length ?? 0) >= 2 },
    { key: "firewall", done: fw.data?.active === true },
    { key: "updates", done: o?.updates?.auto_security === true },
  ];
  const doneCount = items.filter((i) => i.done).length;
  const memPct = o && o.memory.total > 0 ? (100 * o.memory.used) / o.memory.total : 0;
  const swapPct = o && o.memory.swap_total > 0 ? (100 * o.memory.swap_used) / o.memory.swap_total : 0;
  const rootFs = o?.mounts?.find((m) => m.mountpoint === "/");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-2xl font-semibold">{t("overview.title")}</h1>
          {o && (
            <p className="mt-1 text-muted">
              <span className="font-mono">{o.hostname}</span> · {o.os} · {t("overview.kernel")} {o.kernel} · {t("overview.uptime")}{" "}
              {duration(o.uptime_sec, lang)}
            </p>
          )}
        </div>
        {q.isFetching && <span className="text-xs text-faint">{t("overview.live")}</span>}
      </div>

      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}

      {o && (
        <>
          {(o.reboot_required || (o.failed_units ?? 0) > 0 || (o.cert_days_left !== undefined && o.cert_days_left < 30)) && (
            <div className="flex flex-col gap-2">
              {o.reboot_required && (
                <Notice tone="warn">
                  {t("overview.rebootRequired")}
                  {o.reboot_pkgs && o.reboot_pkgs.length > 0 && <span className="text-muted"> ({o.reboot_pkgs.slice(0, 5).join(", ")})</span>}
                </Notice>
              )}
              {(o.failed_units ?? 0) > 0 && (
                <Notice tone="bad">
                  {t("overview.failedUnits", { count: o.failed_units })}{" "}
                  <Link to="/services?state=failed" className="text-violet underline">
                    {t("overview.show")}
                  </Link>
                </Notice>
              )}
              {o.cert_days_left !== undefined && o.cert_days_left < 30 && (
                <Notice tone={o.cert_days_left < 7 ? "bad" : "warn"}>{t("overview.certExpiring", { count: o.cert_days_left })}</Notice>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <Stat title={t("overview.cpu")} value={pct(o.cpu_pct, lang)} sub={t("overview.cores", { count: o.cpus })}>
              <Meter value={o.cpu_pct} label={t("overview.cpu")} />
            </Stat>
            <Stat title={t("overview.load")} value={num(o.load[0], lang)} sub={`${num(o.load[1], lang)} · ${num(o.load[2], lang)} (5 / 15 min)`}>
              <Meter value={(100 * o.load[0]) / Math.max(1, o.cpus)} label={t("overview.load")} warn={100} bad={200} />
            </Stat>
            <Stat
              title={t("overview.memory")}
              value={pct(memPct, lang)}
              sub={`${bytes(o.memory.used, lang)} / ${bytes(o.memory.total, lang)}${o.memory.swap_total ? ` · Swap ${pct(swapPct, lang)}` : ""}`}
            >
              <Meter value={memPct} label={t("overview.memory")} />
            </Stat>
            <Stat
              title={t("overview.rootfs")}
              value={rootFs ? pct(rootFs.used_pct, lang) : "–"}
              sub={rootFs ? `${bytes(rootFs.used, lang)} / ${bytes(rootFs.total, lang)}` : undefined}
            >
              {rootFs && <Meter value={rootFs.used_pct} label={t("overview.rootfs")} warn={85} bad={95} />}
            </Stat>
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <Panel>
              <h2 className="mb-3 flex items-center gap-2 font-semibold">
                <Icon name="disk" className="h-4 w-4 text-cyan" />
                {t("overview.mounts")}
              </h2>
              <div className="relative overflow-x-auto">
                <DataTable
                  rows={o.mounts}
                  rowKey={(m) => m.mountpoint}
                  className=""
                  label={t("overview.mounts")}
                  columns={[
                    {
                      key: "mount",
                      label: t("overview.mountpoint"),
                      sortValue: (m) => m.mountpoint,
                      filterValue: (m) => `${m.mountpoint} ${m.fstype}`,
                      filter: "text",
                      cell: (m) => (
                        <>
                          <span className="font-mono">{m.mountpoint}</span>{" "}
                          <span className="text-faint">
                            {m.fstype}
                            {m.read_only ? " · ro" : ""}
                          </span>
                        </>
                      ),
                    },
                    {
                      key: "usage",
                      label: t("overview.usage"),
                      thClass: "w-40",
                      tdClass: "w-40",
                      sortValue: (m) => m.used_pct,
                      cell: (m) => (
                        <>
                          <div className="flex items-center gap-2">
                            <Meter value={m.used_pct} label={`${m.mountpoint} ${t("overview.usage")}`} warn={85} bad={95} />
                            <span className="w-12 text-right tabular-nums">{pct(m.used_pct, lang)}</span>
                          </div>
                        </>
                      ),
                    },
                    {
                      key: "inodes",
                      label: t("overview.inodes"),
                      tdClass: "tabular-nums",
                      sortValue: (m) => (m.inodes_total ? m.inodes_pct : undefined),
                      cell: (m) => <>{m.inodes_total ? pct(m.inodes_pct, lang) : "–"}</>,
                    },
                    {
                      key: "free",
                      label: t("overview.free"),
                      tdClass: "tabular-nums",
                      sortValue: (m) => m.available,
                      cell: (m) => <>{bytes(m.available, lang)}</>,
                    },
                  ]}
                />
              </div>
            </Panel>

            <Panel>
              <h2 className="mb-3 flex items-center gap-2 font-semibold">
                <Icon name="network" className="h-4 w-4 text-cyan" />
                {t("overview.network")}
              </h2>
              <ul className="flex flex-col gap-2 text-sm">
                {(o.interfaces ?? []).map((n) => (
                  <li key={n.name} className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-2 first:border-t-0 first:pt-0">
                    <span className="flex items-center gap-2">
                      <span aria-hidden="true" className={n.state === "up" ? "text-ok" : "text-faint"}>
                        ●
                      </span>
                      <span className="font-mono">{n.name}</span>
                      <span className="text-faint">{n.state}</span>
                    </span>
                    <span className="tabular-nums text-muted">
                      ↓ {rate(n.rx_bps, lang)} · ↑ {rate(n.tx_bps, lang)}
                      {n.errors > 0 && <span className="text-warn"> · {t("overview.errors", { count: n.errors })}</span>}
                    </span>
                  </li>
                ))}
              </ul>
              <div className="mt-4 grid grid-cols-2 gap-2 text-sm">
                <p className="text-muted">
                  {t("overview.processes")}: <span className="text-fg tabular-nums">{o.processes}</span>
                </p>
                <p className="text-muted">
                  <Link className="underline" to="/updates">
                    {t("overview.updates")}
                  </Link>
                  :{" "}
                  <span className="text-fg tabular-nums">
                    {o.updates ? t("overview.updatesValue", { total: o.updates.total, security: o.updates.security }) : "–"}
                  </span>
                </p>
                <p className="text-muted">
                  {t("overview.cert")}:{" "}
                  <span className="text-fg tabular-nums">{o.cert_days_left !== undefined ? t("overview.days", { count: o.cert_days_left }) : "–"}</span>
                </p>
                <p className="text-muted">
                  {t("overview.failed")}: <span className="text-fg tabular-nums">{o.failed_units ?? "–"}</span>
                </p>
              </div>
            </Panel>
          </div>

          <Panel>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="flex items-center gap-2 font-semibold">
                <Icon name="process" className="h-4 w-4 text-cyan" />
                {t("overview.top")}
              </h2>
              <Link to="/processes" className="text-sm text-violet underline">
                {t("overview.allProcesses")}
              </Link>
            </div>
            <div className="relative overflow-x-auto">
              <DataTable
                rows={o.top}
                rowKey={(p) => String(p.pid)}
                className=""
                label={t("overview.top")}
                columns={[
                  {
                    key: "pid",
                    label: "PID",
                    tdClass: "tabular-nums",
                    sortValue: (p) => p.pid,
                    cell: (p) => <>{p.pid}</>,
                  },
                  {
                    key: "user",
                    label: t("processes.user"),
                    sortValue: (p) => p.user,
                    filter: "text",
                    cell: (p) => <>{p.user}</>,
                  },
                  {
                    key: "cpu",
                    label: "CPU",
                    thClass: "text-right",
                    tdClass: "text-right tabular-nums",
                    sortValue: (p) => p.cpu,
                    cell: (p) => <>{pct(p.cpu, lang, 1)}</>,
                  },
                  {
                    key: "rss",
                    label: "RAM",
                    thClass: "text-right",
                    tdClass: "text-right tabular-nums",
                    sortValue: (p) => p.rss,
                    cell: (p) => <>{bytes(p.rss, lang)}</>,
                  },
                  {
                    key: "cmd",
                    label: t("processes.command"),
                    tdClass: "max-w-0 truncate font-mono",
                    tdTitle: (p) => p.command,
                    sortValue: (p) => p.command,
                    filter: "text",
                    cell: (p) => <>{p.command}</>,
                  },
                ]}
              />
            </div>
          </Panel>

          <Panel>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="flex items-center gap-2 font-semibold">
                <Icon name="users" className="h-4 w-4 text-cyan" />
                {t("overview.logins")}
              </h2>
              <Link to="/users" className="text-sm text-violet underline">
                {t("overview.allUsers")}
              </Link>
            </div>
            {(o.last_logins ?? []).length === 0 ? (
              <p className="text-sm text-muted">{t("overview.noLogins")}</p>
            ) : (
              <div className="relative overflow-x-auto">
                <DataTable
                  rows={o.last_logins ?? []}
                  rowKey={(l) => `${l.user}-${l.tty}-${l.time}`}
                  className=""
                  label={t("overview.logins")}
                  columns={[
                    { key: "user", label: t("processes.user"), sortValue: (l) => l.user, cell: (l) => <>{l.user}</> },
                    { key: "from", label: t("overview.loginFrom"), tdClass: "font-mono", sortValue: (l) => l.from, cell: (l) => <>{l.from || "–"}</> },
                    { key: "tty", label: t("overview.loginTty"), tdClass: "font-mono", sortValue: (l) => l.tty, cell: (l) => <>{l.tty}</> },
                    {
                      key: "time",
                      label: t("overview.loginTime"),
                      tdClass: "tabular-nums",
                      sortValue: (l) => l.time,
                      cell: (l) => <span title={dateTime(l.time, lang)}>{relative(l.time, lang)}</span>,
                    },
                    {
                      key: "state",
                      label: t("overview.loginState"),
                      sortValue: (l) => (l.end ? 1 : 0),
                      filterValue: (l) => (l.end ? t("overview.loginEnded") : t("overview.loginOpen")),
                      cell: (l) =>
                        l.end ? <span className="text-muted">{t("overview.loginEnded")}</span> : <span className="text-ok">● {t("overview.loginOpen")}</span>,
                    },
                  ]}
                />
              </div>
            )}
          </Panel>
        </>
      )}

      <Panel edge>
        <h2 className="font-semibold">{t("overview.checklist", { done: doneCount, total: items.length })}</h2>
        <ul className="mt-3 flex flex-col gap-2">
          {items.map((i) => (
            <li key={i.key} className="flex items-center gap-2">
              <span aria-hidden="true" className={i.done ? "text-ok" : "text-faint"}>
                {i.done ? "✓" : "○"}
              </span>
              <span className={i.done ? "" : "text-muted"}>{t(`overview.items.${i.key}`)}</span>
              <span className="sr-only">{i.done ? t("common.yes") : t("common.no")}</span>
            </li>
          ))}
        </ul>
        {(pk.data?.length ?? 0) < 2 && (
          <Link to="/security/passkeys" className="mt-4 inline-block text-violet underline">
            {t("passkeys.add")}
          </Link>
        )}
      </Panel>
    </div>
  );
}
