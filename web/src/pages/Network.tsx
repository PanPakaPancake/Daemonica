import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChangeFlow, type Change } from "../components/ChangeFlow";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";

interface Iface {
  name: string;
  index: number;
  kind: string;
  state: string;
  mac?: string;
  mtu: number;
  speed_mbit?: number;
  addresses: string[];
  parent?: string;
  vlan_id?: number;
  members?: string[];
  master?: string;
  session?: boolean;
}
interface Route {
  family: number;
  to: string;
  via?: string;
  dev?: string;
  metric?: number;
  protocol?: string;
  src?: string;
}
interface NetView {
  hostname: string;
  domain?: string;
  interfaces: Iface[];
  routes: Route[];
  gateways: string[];
  dns: { servers: string[]; search: string[]; resolved: boolean };
  manager: { name: string; renderer?: string; writable: boolean; reason?: string; files: string[] };
  session_iface?: string;
  client_ip: string;
}
interface Port {
  proto: string;
  address: string;
  port: number;
  uid: number;
  user?: string;
  processes: { pid: number; name: string }[];
}
interface StaticRoute {
  to: string;
  via: string;
  metric?: number;
}
interface IfaceConfig {
  name: string;
  dhcp4: boolean;
  dhcp6: boolean;
  addresses: string[];
  gateway4?: string;
  gateway6?: string;
  dns: string[];
  search: string[];
  mtu?: number;
  routes: StaticRoute[];
  source?: string;
  editable: boolean;
  reason?: string;
}
interface PlanView extends Change {
  addresses: string[];
  session: boolean;
}

const stateTone: Record<string, string> = { up: "text-ok", down: "text-bad", dormant: "text-warn", lowerlayerdown: "text-bad" };

export function Network() {
  const { t } = useTranslation();
  const { me } = useSession();
  const [tab, setTab] = useState<"overview" | "ports">("overview");
  const [edit, setEdit] = useState<string>();
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "warn" }>();
  const q = useQuery({ queryKey: ["network"], queryFn: () => api<NetView>("GET", "/network"), refetchInterval: 10_000 });
  const isAdmin = me?.role === "admin";
  const n = q.data;
  const writable = !!n?.manager.writable && isAdmin;

  const ifaceItems = (i: Iface): MenuItem[] => [
    {
      label: t("network.edit"),
      icon: "edit",
      disabled: !writable || i.kind === "loopback",
      onSelect: () => {
        setDone(undefined);
        setEdit(i.name);
      },
    },
    {
      label: t("network.copyAddresses"),
      icon: "copy",
      disabled: i.addresses.length === 0,
      onSelect: () => void navigator.clipboard?.writeText(i.addresses.join("\n")),
    },
  ];

  const ifaceCols: Column<Iface>[] = [
    {
      key: "name",
      label: t("network.col.name"),
      sortValue: (i) => i.name,
      cell: (i) => (
        <span className="flex items-center gap-2 font-mono">
          {i.name}
          {i.session && (
            <span className="rounded-full border border-cyan px-1.5 text-[11px] text-cyan" title={t("network.sessionHint")}>
              {t("network.session")}
            </span>
          )}
        </span>
      ),
    },
    {
      key: "kind",
      label: t("network.col.kind"),
      sortValue: (i) => i.kind,
      filter: {
        options: [...new Set((n?.interfaces ?? []).map((i) => i.kind))].map((k) => ({ value: k, label: t(`network.kind.${k}`, { defaultValue: k }) })),
      },
      cell: (i) => (
        <span>
          {t(`network.kind.${i.kind}`, { defaultValue: i.kind })}
          {i.kind === "vlan" && i.parent && <span className="text-faint"> ({t("network.vlanOf", { id: i.vlan_id, parent: i.parent })})</span>}
          {i.members && i.members.length > 0 && <span className="text-faint"> ({i.members.join(", ")})</span>}
          {i.master && <span className="text-faint"> → {i.master}</span>}
        </span>
      ),
    },
    {
      key: "state",
      label: t("network.col.state"),
      sortValue: (i) => i.state,
      cell: (i) => <span className={stateTone[i.state] ?? "text-muted"}>{i.state || "—"}</span>,
    },
    {
      key: "addresses",
      label: t("network.col.addresses"),
      sortValue: (i) => i.addresses[0] ?? "",
      filterValue: (i) => i.addresses.join(" "),
      tdClass: "font-mono text-sm",
      cell: (i) => (i.addresses.length ? i.addresses.map((a) => <div key={a}>{a}</div>) : <span className="text-faint">—</span>),
    },
    { key: "mac", label: t("network.col.mac"), sortValue: (i) => i.mac ?? "", tdClass: "font-mono text-sm", cell: (i) => i.mac ?? "—" },
    { key: "mtu", label: "MTU", sortValue: (i) => i.mtu, cell: (i) => i.mtu },
    {
      key: "speed",
      label: t("network.col.speed"),
      sortValue: (i) => i.speed_mbit ?? 0,
      cell: (i) => (i.speed_mbit ? (i.speed_mbit >= 1000 ? `${i.speed_mbit / 1000} Gbit/s` : `${i.speed_mbit} Mbit/s`) : "—"),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (i) => <Menu label={t("network.actionsFor", { name: i.name })} items={ifaceItems(i)} />,
    },
  ];

  const routeCols: Column<Route>[] = [
    { key: "family", label: t("network.col.family"), sortValue: (r) => `IPv${r.family}`, cell: (r) => `IPv${r.family}` },
    {
      key: "to",
      label: t("network.col.to"),
      sortValue: (r) => r.to,
      tdClass: "font-mono text-sm",
      cell: (r) => (r.to === "default" ? t("network.default") : r.to),
    },
    { key: "via", label: t("network.col.via"), sortValue: (r) => r.via ?? "", tdClass: "font-mono text-sm", cell: (r) => r.via ?? t("network.onLink") },
    { key: "dev", label: t("network.col.dev"), sortValue: (r) => r.dev ?? "", tdClass: "font-mono text-sm", cell: (r) => r.dev ?? "—" },
    { key: "metric", label: t("network.col.metric"), sortValue: (r) => r.metric ?? 0, cell: (r) => r.metric ?? 0 },
    { key: "protocol", label: t("network.col.protocol"), sortValue: (r) => r.protocol ?? "", cell: (r) => r.protocol ?? "—" },
    { key: "src", label: t("network.col.src"), sortValue: (r) => r.src ?? "", tdClass: "font-mono text-sm", cell: (r) => r.src ?? "—" },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("network.title")}</h1>
        <p className="mt-1 text-muted">{t("network.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done?.msg && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}

      {n && (
        <Panel>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-faint">{t("network.host")}</dt>
            <dd className="font-mono">
              {n.hostname}
              {n.domain && <span className="text-muted">.{n.domain}</span>}
            </dd>
            <dt className="text-faint">{t("network.gateway")}</dt>
            <dd className="font-mono">{n.gateways.length ? n.gateways.join(", ") : "—"}</dd>
            <dt className="text-faint">{t("network.dns")}</dt>
            <dd className="font-mono">
              {n.dns.servers.join(", ") || "—"}
              {n.dns.resolved && <span className="ml-2 font-sans text-faint">({t("network.resolved")})</span>}
            </dd>
            <dt className="text-faint">{t("network.search")}</dt>
            <dd className="font-mono">{n.dns.search.join(", ") || "—"}</dd>
            <dt className="text-faint">{t("network.manager")}</dt>
            <dd>
              {t(`network.managers.${n.manager.name}`, { defaultValue: n.manager.name })}
              {n.manager.renderer && <span className="text-muted"> ({n.manager.renderer})</span>}
              {n.manager.files.length > 0 && <span className="ml-2 font-mono text-xs text-faint">{n.manager.files.join(", ")}</span>}
            </dd>
          </dl>
          {!n.manager.writable && (
            <div className="mt-4">
              <Notice tone="info">{t(`network.readOnly.${n.manager.reason ?? "unsupported"}`, { defaultValue: t("network.readOnly.unsupported") })}</Notice>
            </div>
          )}
        </Panel>
      )}

      <div role="tablist" className="flex gap-1 border-b border-line">
        {(["overview", "ports"] as const).map((x) => (
          <button
            key={x}
            role="tab"
            type="button"
            aria-selected={tab === x}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
            onClick={() => setTab(x)}
          >
            {t(`network.tab.${x}`)}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <>
          <section className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">{t("network.interfaces")}</h2>
            <DataTable
              label={t("network.interfaces")}
              columns={ifaceCols}
              rows={n?.interfaces}
              rowKey={(i) => i.name}
              loading={q.isLoading}
              defaultSort={{ key: "name", desc: false }}
              rowMenu={(i) => ({ label: t("network.actionsFor", { name: i.name }), items: ifaceItems(i) })}
            />
          </section>
          <section className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold">{t("network.routes")}</h2>
            <DataTable
              label={t("network.routes")}
              columns={routeCols}
              rows={n?.routes}
              rowKey={(r) => `${r.family}-${r.to}-${r.via ?? ""}-${r.dev ?? ""}-${r.metric ?? 0}`}
              loading={q.isLoading}
            />
          </section>
        </>
      )}
      {tab === "ports" && <Ports />}

      {edit && n && (
        <EditIface
          name={edit}
          net={n}
          onClose={() => setEdit(undefined)}
          onDone={(msg, tone) => {
            setDone({ msg, tone });
            setEdit(undefined);
          }}
        />
      )}
    </div>
  );
}

function Ports() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["network-ports"], queryFn: () => api<{ ports: Port[] }>("GET", "/network/ports"), refetchInterval: 10_000 });
  const rows = q.data?.ports;
  const cols: Column<Port>[] = useMemo(
    () => [
      {
        key: "proto",
        label: t("network.col.proto"),
        sortValue: (p) => p.proto,
        filter: { options: ["tcp", "tcp6", "udp", "udp6"].map((x) => ({ value: x, label: x })) },
        cell: (p) => p.proto,
      },
      { key: "address", label: t("network.col.bind"), sortValue: (p) => p.address, tdClass: "font-mono text-sm", cell: (p) => bindText(t, p.address) },
      { key: "port", label: t("network.col.port"), sortValue: (p) => p.port, tdClass: "font-mono", cell: (p) => p.port },
      {
        key: "process",
        label: t("network.col.process"),
        sortValue: (p) => p.processes[0]?.name ?? "",
        filterValue: (p) => p.processes.map((x) => `${x.name} ${x.pid}`).join(" "),
        cell: (p) =>
          p.processes.length ? (
            p.processes.map((x) => (
              <div key={x.pid}>
                {x.name} <span className="text-faint">({x.pid})</span>
              </div>
            ))
          ) : (
            <span className="text-faint">{t("network.kernel")}</span>
          ),
      },
      { key: "user", label: t("network.col.user"), sortValue: (p) => p.user ?? String(p.uid), cell: (p) => p.user ?? p.uid },
      {
        key: "exposure",
        label: t("network.col.exposure"),
        sortValue: (p) => exposure(p.address),
        filter: { options: ["local", "all", "specific"].map((x) => ({ value: x, label: t(`network.exposure.${x}`) })) },
        cell: (p) => <span className={exposure(p.address) === "all" ? "text-warn" : "text-muted"}>{t(`network.exposure.${exposure(p.address)}`)}</span>,
      },
    ],
    [t],
  );
  return (
    <section className="flex flex-col gap-2">
      <p className="text-sm text-muted">{t("network.portsIntro")}</p>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      <DataTable
        label={t("network.tab.ports")}
        columns={cols}
        rows={rows}
        rowKey={(p) => `${p.proto}-${p.address}-${p.port}`}
        loading={q.isLoading}
        defaultSort={{ key: "port", desc: false }}
      />
    </section>
  );
}

function exposure(addr: string): "local" | "all" | "specific" {
  if (addr === "0.0.0.0" || addr === "::") return "all";
  if (addr.startsWith("127.") || addr === "::1") return "local";
  return "specific";
}

function bindText(t: (k: string) => string, addr: string) {
  if (addr === "0.0.0.0") return `0.0.0.0 (${t("network.allV4")})`;
  if (addr === "::") return `:: (${t("network.allV6")})`;
  return addr;
}

const lines = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function EditIface({ name, net, onClose, onDone }: { name: string; net: NetView; onClose: () => void; onDone: (msg: string, tone: "ok" | "warn") => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { withStepUp } = useSession();
  const q = useQuery({ queryKey: ["network-config", name], queryFn: () => api<IfaceConfig>("POST", "/network/config", { name }) });
  const [form, setForm] = useState<IfaceConfig>();
  const [addrText, setAddrText] = useState<string>();
  const [dnsText, setDnsText] = useState<string>();
  const [searchText, setSearchText] = useState<string>();
  const [needAck, setNeedAck] = useState(false);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [change, setChange] = useState<PlanView>();
  const cfg = form ?? q.data;
  const iface = net.interfaces.find((i) => i.name === name);
  const set = (p: Partial<IfaceConfig>) => cfg && setForm({ ...cfg, ...p });

  const plan = async () => {
    if (!cfg) return;
    setBusy(true);
    setErr(undefined);
    const body: IfaceConfig = {
      ...cfg,
      addresses: lines(addrText ?? cfg.addresses.join("\n")),
      dns: lines(dnsText ?? cfg.dns.join(" ")),
      search: lines(searchText ?? cfg.search.join(" ")),
      routes: cfg.routes.filter((r) => r.to.trim() || r.via.trim()),
    };
    delete body.source;
    delete body.reason;
    try {
      const c = await withStepUp(() => api<PlanView>("POST", "/network/plan", { config: { ...body, editable: undefined }, confirm_lockout: ack }));
      setChange(c);
      setNeedAck(false);
    } catch (e) {
      if (e instanceof ApiError && e.code === "lockout_protection") setNeedAck(true);
      else setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  // While a change waits for confirmation the dialog stays open.
  const close = () => {
    if (change?.state === "applied") return;
    onClose();
  };

  // The dashboard is reached by IP and that IP is gone: show where it will be.
  const host = window.location.hostname.replace(/^\[|\]$/g, "");
  const byIp = /^[\d.]+$|:/.test(host);
  const newAddrs = (change?.addresses ?? []).filter((a) => a !== "dhcp").map((a) => a.split("/")[0] ?? a);
  const hostGone = change?.session && byIp && !newAddrs.includes(host);

  return (
    <Modal title={t("network.editTitle", { name })} onClose={close} wide>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {cfg && !change && (
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void plan();
          }}
        >
          {!cfg.editable && <Notice tone="info">{t(`network.notEditable.${cfg.reason ?? "advanced"}`, { file: cfg.source })}</Notice>}
          {cfg.editable && cfg.source && <p className="text-sm text-faint">{t("network.writesTo", { file: cfg.source })}</p>}
          {iface?.session && <Notice tone="bad">{t("network.sessionWarn", { name, ip: net.client_ip })}</Notice>}
          <fieldset disabled={!cfg.editable || busy} className="flex flex-col gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="flex flex-col gap-3">
                <h3 className="font-semibold">IPv4</h3>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={cfg.dhcp4} onChange={(e) => set({ dhcp4: e.target.checked })} />
                  <span>{t("network.dhcp4")}</span>
                </label>
                <Field label={t("network.gateway4")}>
                  {(p) => (
                    <input
                      {...p}
                      className="input font-mono"
                      value={cfg.gateway4 ?? ""}
                      onChange={(e) => set({ gateway4: e.target.value })}
                      placeholder="192.0.2.1"
                    />
                  )}
                </Field>
              </div>
              <div className="flex flex-col gap-3">
                <h3 className="font-semibold">IPv6</h3>
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={cfg.dhcp6} onChange={(e) => set({ dhcp6: e.target.checked })} />
                  <span>{t("network.dhcp6")}</span>
                </label>
                <Field label={t("network.gateway6")}>
                  {(p) => (
                    <input
                      {...p}
                      className="input font-mono"
                      value={cfg.gateway6 ?? ""}
                      onChange={(e) => set({ gateway6: e.target.value })}
                      placeholder="2001:db8::1"
                    />
                  )}
                </Field>
              </div>
            </div>
            <Field label={t("network.addresses")} help={t("network.addressesHelp")}>
              {(p) => (
                <textarea
                  {...p}
                  className="input min-h-24 py-2 font-mono"
                  value={addrText ?? cfg.addresses.join("\n")}
                  onChange={(e) => setAddrText(e.target.value)}
                  spellCheck={false}
                />
              )}
            </Field>
            <div className="grid gap-4 md:grid-cols-[2fr_2fr_1fr]">
              <Field label={t("network.dnsServers")} help={t("network.listHelp")}>
                {(p) => <input {...p} className="input font-mono" value={dnsText ?? cfg.dns.join(" ")} onChange={(e) => setDnsText(e.target.value)} />}
              </Field>
              <Field label={t("network.searchDomains")} help={t("network.listHelp")}>
                {(p) => <input {...p} className="input font-mono" value={searchText ?? cfg.search.join(" ")} onChange={(e) => setSearchText(e.target.value)} />}
              </Field>
              <Field label="MTU" help={t("network.mtuHelp")}>
                {(p) => (
                  <input
                    {...p}
                    className="input font-mono"
                    inputMode="numeric"
                    value={cfg.mtu ? String(cfg.mtu) : ""}
                    onChange={(e) => set({ mtu: Number(e.target.value.replace(/\D/g, "")) || undefined })}
                  />
                )}
              </Field>
            </div>
            <div className="flex flex-col gap-2">
              <h3 className="font-semibold">{t("network.staticRoutes")}</h3>
              {cfg.routes.length === 0 && <p className="text-sm text-faint">{t("network.noRoutes")}</p>}
              {cfg.routes.map((r, i) => (
                <div key={i} className="grid grid-cols-[2fr_2fr_1fr_auto] items-end gap-2">
                  <Field label={t("network.col.to")}>
                    {(p) => (
                      <input
                        {...p}
                        className="input font-mono"
                        value={r.to}
                        placeholder="10.0.0.0/8"
                        onChange={(e) => set({ routes: cfg.routes.map((x, j) => (j === i ? { ...x, to: e.target.value } : x)) })}
                      />
                    )}
                  </Field>
                  <Field label={t("network.col.via")}>
                    {(p) => (
                      <input
                        {...p}
                        className="input font-mono"
                        value={r.via}
                        onChange={(e) => set({ routes: cfg.routes.map((x, j) => (j === i ? { ...x, via: e.target.value } : x)) })}
                      />
                    )}
                  </Field>
                  <Field label={t("network.col.metric")}>
                    {(p) => (
                      <input
                        {...p}
                        className="input font-mono"
                        inputMode="numeric"
                        value={r.metric ? String(r.metric) : ""}
                        onChange={(e) =>
                          set({ routes: cfg.routes.map((x, j) => (j === i ? { ...x, metric: Number(e.target.value.replace(/\D/g, "")) || undefined } : x)) })
                        }
                      />
                    )}
                  </Field>
                  <button
                    type="button"
                    className="btn btn-ghost min-h-10 px-2"
                    title={t("network.removeRoute")}
                    onClick={() => set({ routes: cfg.routes.filter((_, j) => j !== i) })}
                  >
                    <Icon name="trash" className="h-4 w-4" />
                    <span className="sr-only">{t("network.removeRoute")}</span>
                  </button>
                </div>
              ))}
              <div>
                <button type="button" className="btn btn-secondary" onClick={() => set({ routes: [...cfg.routes, { to: "", via: "" }] })}>
                  <Icon name="plus" className="h-4 w-4" />
                  {t("network.addRoute")}
                </button>
              </div>
            </div>
          </fieldset>
          {needAck && (
            <Notice tone="bad">
              <label className="flex items-start gap-2">
                <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                <span>{t("network.lockoutAck", { name })}</span>
              </label>
            </Notice>
          )}
          {err && <Notice tone="bad">{err}</Notice>}
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary" disabled={!cfg.editable || busy || (needAck && !ack)}>
              {t("network.plan")}
            </button>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              {t("common.cancel")}
            </button>
          </div>
          <Explain>{t("network.explain")}</Explain>
        </form>
      )}
      {change && (
        <ChangeFlow
          change={change}
          ns="network"
          onChange={(c) => {
            if (c) setChange({ ...change, ...c });
            else setChange(undefined);
          }}
          onDone={(msg, tone) => {
            void qc.invalidateQueries({ queryKey: ["network"] });
            void qc.invalidateQueries({ queryKey: ["network-config", name] });
            onDone(msg, tone);
          }}
        >
          {hostGone && (
            <Notice tone="warn">
              {t("network.newUrl")}{" "}
              {newAddrs.map((a) => {
                const u = `${window.location.protocol}//${a.includes(":") ? `[${a}]` : a}${window.location.port ? `:${window.location.port}` : ""}/`;
                return (
                  <a key={a} className="mr-3 font-mono underline" href={u}>
                    {u}
                  </a>
                );
              })}
            </Notice>
          )}
        </ChangeFlow>
      )}
    </Modal>
  );
}
