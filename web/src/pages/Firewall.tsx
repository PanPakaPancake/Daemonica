import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ChangeFlow, type Change } from "../components/ChangeFlow";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, saveText } from "../lib/format";
import { explainRule, type Rule } from "../lib/firewall";
import { useSession } from "../lib/session";

interface Config {
  enabled: boolean;
  logging: string;
  ipv6: boolean;
  defaults: { incoming: string; outgoing: string; routed: string };
  rules: Rule[];
}
interface Hint {
  code: string;
  level: "red" | "yellow";
  arg?: string;
}
interface Access {
  allowed: boolean;
  reason: string;
  rule?: number;
  action?: string;
  limited?: boolean;
  restricted?: boolean;
}
interface ReachRow {
  proto: string;
  address: string;
  port: number;
  process?: string;
  local: boolean;
  access: Access;
}
interface FwView {
  backend: string;
  managed: boolean;
  installed: boolean;
  installable: boolean;
  active: boolean;
  config?: Config;
  light: "green" | "yellow" | "red";
  hints: Hint[];
  reach: ReachRow[];
  apps: string[];
  client_ip: string;
  session_iface?: string;
  dashboard_port: number;
  ssh_ports: number[];
  hostname: string;
  last_change?: { ts: string; event: string; actor?: string };
}
interface AddSpec {
  action: string;
  direction: string;
  iface?: string;
  proto: string;
  port?: string;
  app?: string;
  from: string;
  to: string;
  comment?: string;
}
export interface Op {
  kind: "add" | "delete" | "logging" | "default" | "enable" | "disable" | "reset";
  add?: AddSpec;
  nums?: number[];
  level?: string;
  direction?: string;
  policy?: string;
}
interface PlanView extends Change {
  auto: AddSpec[];
  lockout: string[];
  blocked?: boolean;
}

const lightTone = { green: "bg-ok", yellow: "bg-warn", red: "bg-bad" } as const;
const actionTone: Record<string, string> = { allow: "text-ok", limit: "text-warn", deny: "text-bad", reject: "text-bad" };
const levels = ["off", "low", "medium", "high", "full"];

function ufwCommand(r: Rule): string {
  const a = r.direction === "route" ? ["ufw", "route", r.action] : ["ufw", r.action, r.direction];
  if (r.log) a.push(r.log);
  if (r.iface) a.push(...(r.direction === "route" ? ["in", "on"] : ["on"]), r.iface);
  if (r.out_iface) a.push("out", "on", r.out_iface);
  if (!r.app && r.proto !== "any") a.push("proto", r.proto);
  a.push("from", r.src, "to", r.dst);
  if (r.app) a.push("app", r.app);
  else if (r.dport !== "any") a.push("port", r.dport);
  if (r.comment) a.push("comment", `'${r.comment}'`);
  return a.join(" ");
}

export function Firewall() {
  const { t, i18n } = useTranslation();
  const { me } = useSession();
  const qc = useQueryClient();
  const [tab, setTab] = useState<"rules" | "reach" | "raw">("rules");
  const [op, setOp] = useState<Op>();
  const [adding, setAdding] = useState<AddSpec>();
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "warn" }>();
  const q = useQuery({ queryKey: ["firewall"], queryFn: () => api<FwView>("GET", "/firewall"), refetchInterval: 10_000 });
  const f = q.data;
  const c = f?.config;
  const isAdmin = me?.role === "admin";
  const canWrite = isAdmin && !!f?.managed;

  const start = (o: Op) => {
    setDone(undefined);
    setOp(o);
  };
  const finish = (msg: string, tone: "ok" | "warn") => {
    setOp(undefined);
    setAdding(undefined);
    if (msg) setDone({ msg, tone });
    void qc.invalidateQueries({ queryKey: ["firewall"] });
  };

  const ruleItems = (r: Rule): MenuItem[] => [
    {
      label: t("firewall.similar"),
      icon: "copy",
      disabled: !canWrite || r.direction === "route",
      onSelect: () =>
        setAdding({
          action: r.action,
          direction: r.direction,
          iface: r.iface,
          proto: r.proto,
          port: r.app ? undefined : r.dport === "any" ? "" : r.dport,
          app: r.app,
          from: r.src,
          to: r.dst,
          comment: r.managed ? "" : r.comment,
        }),
    },
    { label: t("firewall.copyCommand"), icon: "terminal", onSelect: () => void navigator.clipboard?.writeText(ufwCommand(r)) },
    { label: t("common.delete"), icon: "trash", danger: true, disabled: !canWrite, onSelect: () => start({ kind: "delete", nums: [r.num] }) },
  ];

  const ruleCols: Column<Rule>[] = [
    { key: "num", label: "#", sortValue: (r) => r.num, filter: "number", tdClass: "font-mono text-faint", cell: (r) => r.num },
    {
      key: "action",
      label: t("firewall.col.action"),
      sortValue: (r) => r.action,
      filter: { options: ["allow", "limit", "deny", "reject"].map((x) => ({ value: x, label: t(`firewall.action.${x}`) })) },
      cell: (r) => <span className={`font-semibold ${actionTone[r.action] ?? ""}`}>{t(`firewall.action.${r.action}`)}</span>,
    },
    {
      key: "direction",
      label: t("firewall.col.direction"),
      sortValue: (r) => r.direction,
      filter: { options: ["in", "out", "route"].map((x) => ({ value: x, label: t(`firewall.dir.${x}`) })) },
      cell: (r) => t(`firewall.dir.${r.direction}`),
    },
    {
      key: "explain",
      label: t("firewall.col.explain"),
      sortValue: (r) => explainRule(t, r),
      tdClass: "min-w-56",
      cell: (r) => explainRule(t, r),
    },
    {
      key: "port",
      label: t("firewall.col.port"),
      sortValue: (r) => (r.app ? r.app : `${r.dport}/${r.proto}`),
      tdClass: "font-mono text-sm",
      cell: (r) => (r.app ? `${r.app} (${r.dport})` : r.dport === "any" ? r.proto : `${r.dport}${r.proto === "any" ? "" : "/" + r.proto}`),
    },
    {
      key: "src",
      label: t("firewall.col.src"),
      sortValue: (r) => r.src,
      tdClass: "font-mono text-sm",
      cell: (r) => (r.src === "any" ? t("firewall.any") : r.src),
    },
    {
      key: "dst",
      label: t("firewall.col.dst"),
      sortValue: (r) => r.dst,
      tdClass: "font-mono text-sm",
      cell: (r) => (r.dst === "any" ? t("firewall.any") : r.dst),
    },
    {
      key: "iface",
      label: t("firewall.col.iface"),
      sortValue: (r) => [r.iface, r.out_iface].filter(Boolean).join(" → "),
      tdClass: "font-mono text-sm",
      cell: (r) => [r.iface, r.out_iface].filter(Boolean).join(" → ") || "—",
    },
    {
      key: "family",
      label: "IP",
      sortValue: (r) => (r.v6 ? "IPv6" : "IPv4"),
      filter: { options: ["IPv4", "IPv6"].map((x) => ({ value: x, label: x })) },
      cell: (r) => (r.v6 ? "IPv6" : "IPv4"),
    },
    {
      key: "comment",
      label: t("firewall.col.comment"),
      sortValue: (r) => r.comment ?? "",
      cell: (r) =>
        r.managed ? (
          <span className="rounded-full border border-cyan px-1.5 text-[11px] whitespace-nowrap text-cyan" title={t("firewall.managedHint")}>
            {r.comment}
          </span>
        ) : (
          (r.comment ?? "")
        ),
    },
    {
      key: "packets",
      label: t("firewall.col.packets"),
      sortValue: (r) => r.packets,
      filter: "number",
      tdClass: "text-right tabular-nums",
      cell: (r) => (r.counted ? r.packets.toLocaleString(i18n.language) : "—"),
    },
    {
      key: "bytes",
      label: t("firewall.col.bytes"),
      sortValue: (r) => r.bytes,
      filter: "bytes",
      tdClass: "text-right tabular-nums",
      cell: (r) => (r.counted ? bytes(r.bytes, i18n.language) : "—"),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (r) => <Menu label={t("firewall.actionsFor", { num: r.num })} items={ruleItems(r)} />,
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("firewall.title")}</h1>
        <p className="mt-1 text-muted">{t("firewall.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}

      {f && (
        <Panel>
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:gap-8">
            <div className="flex min-w-0 flex-1 flex-col gap-3">
              <div className="flex items-center gap-3">
                <span aria-hidden="true" className={`h-4 w-4 shrink-0 rounded-full ${lightTone[f.light]}`} />
                <h2 className="text-lg font-semibold">{t(`firewall.light.${f.light}`)}</h2>
              </div>
              {f.hints.length > 0 && (
                <ul className="flex flex-col gap-1 text-sm">
                  {f.hints.map((h) => (
                    <li key={h.code + (h.arg ?? "")} className={h.level === "red" ? "text-bad" : "text-warn"}>
                      {t(`firewall.hint.${h.code}`, { arg: h.arg })}
                    </li>
                  ))}
                </ul>
              )}
              {f.light === "green" && <p className="text-sm text-muted">{t("firewall.allGood")}</p>}
            </div>
            <dl className="grid flex-1 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[auto_1fr]">
              <dt className="text-faint">{t("firewall.backend")}</dt>
              <dd>{t(`firewall.backends.${f.backend}`, { defaultValue: f.backend })}</dd>
              {c && (
                <>
                  <dt className="text-faint">{t("firewall.status")}</dt>
                  <dd className={f.active ? "text-ok" : "text-bad"}>
                    {f.active ? t("firewall.active") : t("firewall.inactive")}
                    <span className="ml-2 text-muted">({c.enabled ? t("firewall.onBoot") : t("firewall.notOnBoot")})</span>
                  </dd>
                  <dt className="text-faint">{t("firewall.defaults")}</dt>
                  <dd>
                    {(["incoming", "outgoing", "routed"] as const).map((d, i) => (
                      <span key={d}>
                        {i > 0 && ", "}
                        {t(`firewall.default.${d}`)}:{" "}
                        <span className="font-semibold">{t(`firewall.policy.${c.defaults[d]}`, { defaultValue: c.defaults[d] })}</span>
                      </span>
                    ))}
                  </dd>
                  <dt className="text-faint">{t("firewall.ruleCount")}</dt>
                  <dd>{c.rules.length}</dd>
                  <dt className="text-faint">IPv6</dt>
                  <dd>{c.ipv6 ? t("firewall.ipv6On") : t("firewall.ipv6Off")}</dd>
                  <dt className="text-faint">{t("firewall.logging")}</dt>
                  <dd>{t(`firewall.level.${c.logging}`, { defaultValue: c.logging })}</dd>
                </>
              )}
              <dt className="text-faint">{t("firewall.lastChange")}</dt>
              <dd>
                {f.last_change
                  ? t("firewall.lastChangeText", {
                      when: dateTime(f.last_change.ts, i18n.language),
                      who: f.last_change.actor ?? "?",
                      what: t(`firewall.event.${f.last_change.event}`, { defaultValue: f.last_change.event }),
                    })
                  : "—"}
              </dd>
            </dl>
          </div>

          {canWrite && c && (
            <div className="mt-4 flex flex-nowrap gap-2 overflow-x-auto border-t border-line pt-4">
              {f.active ? (
                <button type="button" className="btn btn-secondary shrink-0" onClick={() => start({ kind: "disable" })}>
                  <Icon name="stop" className="h-4 w-4" />
                  {t("firewall.disable")}
                </button>
              ) : (
                <button type="button" className="btn btn-primary shrink-0" onClick={() => start({ kind: "enable" })}>
                  <Icon name="shield" className="h-4 w-4" />
                  {t("firewall.enable")}
                </button>
              )}
              <button type="button" className="btn btn-secondary shrink-0" onClick={() => start({ kind: "logging", level: c.logging })}>
                <Icon name="logs" className="h-4 w-4" />
                {t("firewall.setLogging")}
              </button>
              <button
                type="button"
                className="btn btn-secondary shrink-0"
                onClick={() => start({ kind: "default", direction: "incoming", policy: c.defaults.incoming })}
              >
                <Icon name="settings" className="h-4 w-4" />
                {t("firewall.setDefault")}
              </button>
              <button type="button" className="btn btn-ghost shrink-0 text-bad" onClick={() => start({ kind: "reset" })}>
                <Icon name="restart" className="h-4 w-4" />
                {t("firewall.reset")}
              </button>
            </div>
          )}
          {!f.managed && <Unmanaged view={f} isAdmin={isAdmin} onDone={finish} />}
        </Panel>
      )}

      {f && (
        <>
          <div role="tablist" className="flex gap-1 border-b border-line">
            {(["rules", "reach", "raw"] as const).map((x) => (
              <button
                key={x}
                role="tab"
                type="button"
                aria-selected={tab === x}
                className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
                onClick={() => setTab(x)}
              >
                {t(`firewall.tab.${x}`)}
              </button>
            ))}
          </div>

          {tab === "rules" && c && (
            <section className="flex flex-col gap-2">
              <div className="flex flex-nowrap items-center justify-between gap-2">
                <p className="text-sm text-muted">{t("firewall.rulesIntro")}</p>
                {canWrite && (
                  <button
                    type="button"
                    className="btn btn-primary shrink-0"
                    onClick={() => setAdding({ action: "allow", direction: "in", proto: "tcp", port: "", from: "any", to: "any" })}
                  >
                    <Icon name="plus" className="h-4 w-4" />
                    {t("firewall.addRule")}
                  </button>
                )}
              </div>
              <div className="relative overflow-x-auto">
                <DataTable
                  label={t("firewall.tab.rules")}
                  columns={ruleCols}
                  rows={c.rules}
                  rowKey={(r) => String(r.num)}
                  loading={q.isLoading}
                  defaultSort={{ key: "num", desc: false }}
                  className="min-w-[960px]"
                  rowMenu={(r) => ({ label: t("firewall.actionsFor", { num: r.num }), items: ruleItems(r) })}
                  empty={t("firewall.noRules")}
                />
              </div>
            </section>
          )}
          {tab === "rules" && !c && <p className="text-muted">{t("firewall.noUfwRules")}</p>}
          {tab === "reach" && <Reach view={f} />}
          {tab === "raw" && <Raw />}
        </>
      )}

      {op && f && <FwChange op={op} view={f} onClose={() => setOp(undefined)} onDone={finish} />}
      {adding && f && <FwChange op={{ kind: "add", add: adding }} view={f} onClose={() => setAdding(undefined)} onDone={finish} />}
    </div>
  );
}

function Unmanaged({ view, isAdmin, onDone }: { view: FwView; isAdmin: boolean; onDone: (msg: string, tone: "ok" | "warn") => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const install = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      await withStepUp(() => api("POST", "/firewall/install"));
      onDone(t("firewall.installed"), "ok");
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mt-4 flex flex-col gap-3 border-t border-line pt-4">
      <Notice tone="info">{t(view.backend === "none" ? "firewall.noneInfo" : "firewall.readonlyInfo", { backend: view.backend })}</Notice>
      {view.installable && isAdmin && (
        <>
          <Explain>{t("firewall.installExplain")}</Explain>
          {err && <Notice tone="bad">{err}</Notice>}
          <div>
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void install()}>
              <Icon name="download" className="h-4 w-4" />
              {busy ? t("firewall.installing") : t("firewall.install")}
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function reachState(r: ReachRow): "local" | "open" | "unprotected" | "limited" | "restricted" | "blocked" {
  if (r.local) return "local";
  if (r.access.allowed) {
    if (r.access.reason === "inactive" || r.access.reason === "unfiltered" || r.access.reason === "default") return "unprotected";
    return r.access.limited ? "limited" : "open";
  }
  return r.access.restricted ? "restricted" : "blocked";
}
const reachTone: Record<string, string> = {
  local: "text-muted",
  open: "text-ok",
  limited: "text-ok",
  unprotected: "text-bad",
  restricted: "text-warn",
  blocked: "text-muted",
};

function Reach({ view }: { view: FwView }) {
  const { t } = useTranslation();
  const cols: Column<ReachRow>[] = useMemo(
    () => [
      {
        key: "proto",
        label: t("network.col.proto"),
        sortValue: (r) => r.proto,
        filter: { options: ["tcp", "udp"].map((x) => ({ value: x, label: x })) },
        cell: (r) => r.proto,
      },
      { key: "address", label: t("network.col.bind"), sortValue: (r) => r.address, tdClass: "font-mono text-sm", cell: (r) => r.address },
      { key: "port", label: t("network.col.port"), sortValue: (r) => r.port, filter: "number", tdClass: "font-mono", cell: (r) => r.port },
      { key: "process", label: t("network.col.process"), sortValue: (r) => r.process ?? "", cell: (r) => r.process ?? <span className="text-faint">—</span> },
      {
        key: "state",
        label: t("firewall.col.effect"),
        sortValue: (r) => reachState(r),
        filter: { options: ["open", "limited", "restricted", "blocked", "unprotected", "local"].map((x) => ({ value: x, label: t(`firewall.reach.${x}`) })) },
        cell: (r) => {
          const s = reachState(r);
          return (
            <span className={reachTone[s]}>
              {t(`firewall.reach.${s}`)}
              {r.access.rule ? <span className="ml-1 text-faint">({t("firewall.byRule", { num: r.access.rule })})</span> : null}
            </span>
          );
        },
      },
    ],
    [t],
  );
  return (
    <section className="flex flex-col gap-2">
      <p className="text-sm text-muted">{t("firewall.reachIntro")}</p>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("firewall.tab.reach")}
          columns={cols}
          rows={view.reach}
          rowKey={(r) => `${r.proto}-${r.address}-${r.port}`}
          defaultSort={{ key: "port", desc: false }}
        />
      </div>
    </section>
  );
}

function Raw() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["firewall-raw"], queryFn: () => api<{ source: string; text: string }>("GET", "/firewall/raw") });
  const [search, setSearch] = useState("");
  const lines = useMemo(() => {
    const all = (q.data?.text ?? "").split("\n");
    const s = search.trim().toLowerCase();
    return s ? all.filter((l) => l.toLowerCase().includes(s)) : all;
  }, [q.data, search]);
  return (
    <section className="flex flex-col gap-2">
      <div className="flex flex-nowrap items-center gap-2">
        <label className="relative min-w-0 flex-1">
          <span className="sr-only">{t("firewall.rawSearch")}</span>
          <Icon name="search" className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
          <input className="input w-full pl-9" placeholder={t("firewall.rawSearch")} value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <button type="button" className="btn btn-secondary shrink-0" title={t("common.refresh")} onClick={() => void q.refetch()}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
        <button
          type="button"
          className="btn btn-secondary shrink-0"
          disabled={!q.data}
          title={t("firewall.export")}
          onClick={() => q.data && saveText("firewall-ruleset.txt", q.data.text)}
        >
          <Icon name="download" className="h-4 w-4" />
          <span className="sr-only">{t("firewall.export")}</span>
        </button>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {q.data && (
        <p className="text-sm text-faint">
          {t("firewall.rawSource", { source: q.data.source })}
          {search && ` · ${t("firewall.rawMatches", { count: lines.length })}`}
        </p>
      )}
      <pre className="max-h-[70vh] overflow-auto rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-xs">
        {q.isLoading ? t("common.loading") : lines.join("\n")}
      </pre>
    </section>
  );
}

function lockoutText(t: TFunction, l: string) {
  const [kind, port] = l.split(":");
  return t(`firewall.lockout.${kind}`, { port });
}

/** Plan → Apply → Confirm dialog for one firewall operation. */
function FwChange({ op: initial, view, onClose, onDone }: { op: Op; view: FwView; onClose: () => void; onDone: (msg: string, tone: "ok" | "warn") => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [op, setOp] = useState<Op>(initial);
  const [name, setName] = useState("");
  const [lockout, setLockout] = useState<string[]>();
  const [ack, setAck] = useState(false);
  const [autoAck, setAutoAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [change, setChange] = useState<PlanView>();
  const c = view.config;

  const plan = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const p = await withStepUp(() => api<PlanView>("POST", "/firewall/plan", { op, confirm_lockout: ack, confirm_name: name || undefined }));
      if (p.blocked) setLockout(p.lockout);
      else setChange(p);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  const close = () => {
    if (change?.state === "applied") return;
    onClose();
  };
  const add = op.add;
  const setAdd = (p: Partial<AddSpec>) => add && setOp({ ...op, add: { ...add, ...p } });
  const deleting = op.kind === "delete" ? c?.rules.filter((r) => op.nums?.includes(r.num)) : undefined;
  const ready = op.kind !== "reset" || name.trim().toLowerCase() === view.hostname.toLowerCase();

  return (
    <Modal title={t(`firewall.op.${op.kind}`)} onClose={close} wide={op.kind === "add" || !!change}>
      {!change && (
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void plan();
          }}
        >
          <fieldset disabled={busy} className="flex flex-col gap-4">
            {op.kind === "add" && add && <AddForm spec={add} apps={view.apps} onChange={setAdd} />}
            {deleting && (
              <ul className="flex flex-col gap-1 text-sm">
                {deleting.map((r) => (
                  <li key={r.num}>
                    <span className="font-mono text-faint">#{r.num}</span> {explainRule(t, r)}
                  </li>
                ))}
              </ul>
            )}
            {op.kind === "logging" && (
              <Field label={t("firewall.logging")} help={t("firewall.loggingHelp")}>
                {(p) => (
                  <select {...p} className="input" value={op.level} onChange={(e) => setOp({ ...op, level: e.target.value })}>
                    {levels.map((l) => (
                      <option key={l} value={l}>
                        {t(`firewall.level.${l}`)}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            )}
            {op.kind === "default" && (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("firewall.col.direction")}>
                  {(p) => (
                    <select
                      {...p}
                      className="input"
                      value={op.direction}
                      onChange={(e) => setOp({ ...op, direction: e.target.value, policy: c?.defaults[e.target.value as "incoming"] ?? "deny" })}
                    >
                      {["incoming", "outgoing", "routed"].map((d) => (
                        <option key={d} value={d}>
                          {t(`firewall.default.${d}`)}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
                <Field label={t("firewall.policyLabel")}>
                  {(p) => (
                    <select {...p} className="input" value={op.policy} onChange={(e) => setOp({ ...op, policy: e.target.value })}>
                      {["deny", "reject", "allow"].map((x) => (
                        <option key={x} value={x}>
                          {t(`firewall.policy.${x}`)}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
              </div>
            )}
            {op.kind === "enable" && <Explain>{t("firewall.enableExplain", { ports: view.ssh_ports.join(", "), port: view.dashboard_port })}</Explain>}
            {op.kind === "disable" && <Notice tone="warn">{t("firewall.disableWarn")}</Notice>}
            {op.kind === "reset" && (
              <>
                <Notice tone="bad">{t("firewall.resetWarn")}</Notice>
                <Field label={t("firewall.typeName", { name: view.hostname })}>
                  {(p) => <input {...p} className="input font-mono" autoComplete="off" value={name} onChange={(e) => setName(e.target.value)} />}
                </Field>
              </>
            )}
            {lockout && lockout.length > 0 && (
              <div className="flex flex-col gap-2">
                <Notice tone="bad">
                  <p className="font-semibold">{t("firewall.lockoutTitle")}</p>
                  <ul className="mt-1 list-disc pl-5">
                    {lockout.map((l) => (
                      <li key={l}>{lockoutText(t, l)}</li>
                    ))}
                  </ul>
                </Notice>
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-1" checked={ack} onChange={(e) => setAck(e.target.checked)} />
                  <span>{t("firewall.lockoutAck", { ip: view.client_ip })}</span>
                </label>
              </div>
            )}
          </fieldset>
          {err && <Notice tone="bad">{err}</Notice>}
          <div className="flex flex-wrap gap-2">
            <button type="submit" className="btn btn-primary" disabled={busy || !ready || (!!lockout?.length && !ack)}>
              {t("firewall.preview")}
            </button>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              {t("common.cancel")}
            </button>
          </div>
        </form>
      )}
      {change && (
        <ChangeFlow
          change={change}
          ns="firewall"
          onChange={(x) => (x ? setChange({ ...change, ...x }) : onClose())}
          onDone={onDone}
          applyDisabled={change.auto.length > 0 && !autoAck}
          planned={
            change.auto.length > 0 && (
              <div className="flex flex-col gap-2">
                <p className="font-semibold">{t("firewall.autoTitle")}</p>
                <ul className="list-disc pl-5 text-sm">
                  {change.auto.map((a) => (
                    <li key={a.port + a.from}>
                      {t(a.comment === "daemonica:ssh:access" ? "firewall.autoSsh" : "firewall.autoDashboard", {
                        port: a.port,
                        from: a.from === "any" ? t("firewall.any") : a.from,
                      })}
                    </li>
                  ))}
                </ul>
                <label className="flex items-start gap-2">
                  <input type="checkbox" className="mt-1" checked={autoAck} onChange={(e) => setAutoAck(e.target.checked)} />
                  <span>{t("firewall.autoAck")}</span>
                </label>
              </div>
            )
          }
        />
      )}
    </Modal>
  );
}

function AddForm({ spec, apps, onChange }: { spec: AddSpec; apps: string[]; onChange: (p: Partial<AddSpec>) => void }) {
  const { t } = useTranslation();
  const mode = spec.app !== undefined ? "app" : "port";
  return (
    <div className="flex flex-col gap-4">
      <div role="radiogroup" className="flex flex-nowrap gap-2">
        {(["port", "app"] as const).map((m) => (
          <label key={m} className={`btn shrink-0 ${mode === m ? "btn-primary" : "btn-secondary"}`}>
            <input
              type="radio"
              className="sr-only"
              checked={mode === m}
              onChange={() => onChange(m === "app" ? { app: apps[0] ?? "", port: undefined } : { app: undefined, port: "" })}
            />
            {t(`firewall.mode.${m}`)}
          </label>
        ))}
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label={t("firewall.col.action")} help={t(`firewall.actionHelp.${spec.action}`)}>
          {(p) => (
            <select {...p} className="input" value={spec.action} onChange={(e) => onChange({ action: e.target.value })}>
              {["allow", "limit", "deny", "reject"].map((x) => (
                <option key={x} value={x}>
                  {t(`firewall.action.${x}`)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t("firewall.col.direction")}>
          {(p) => (
            <select {...p} className="input" value={spec.direction} onChange={(e) => onChange({ direction: e.target.value })}>
              {["in", "out"].map((x) => (
                <option key={x} value={x}>
                  {t(`firewall.dir.${x}`)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t("firewall.col.iface")} help={t("firewall.ifaceHelp")}>
          {(p) => (
            <input
              {...p}
              className="input font-mono"
              value={spec.iface ?? ""}
              placeholder="eth0"
              onChange={(e) => onChange({ iface: e.target.value || undefined })}
            />
          )}
        </Field>
      </div>
      {mode === "app" ? (
        <Field label={t("firewall.app")} help={t("firewall.appHelp")}>
          {(p) => (
            <select {...p} className="input" value={spec.app} onChange={(e) => onChange({ app: e.target.value })}>
              {apps.length === 0 && <option value="">{t("firewall.noApps")}</option>}
              {apps.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          )}
        </Field>
      ) : (
        <div className="grid gap-4 sm:grid-cols-[1fr_2fr]">
          <Field label={t("network.col.proto")}>
            {(p) => (
              <select {...p} className="input" value={spec.proto} onChange={(e) => onChange({ proto: e.target.value })}>
                {["tcp", "udp", "any"].map((x) => (
                  <option key={x} value={x}>
                    {x === "any" ? t("firewall.anyProto") : x.toUpperCase()}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label={t("network.col.port")} help={t("firewall.portHelp")}>
            {(p) => <input {...p} className="input font-mono" value={spec.port ?? ""} placeholder="443" onChange={(e) => onChange({ port: e.target.value })} />}
          </Field>
        </div>
      )}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t("firewall.col.src")} help={t("firewall.addrHelp")}>
          {(p) => <input {...p} className="input font-mono" value={spec.from} onChange={(e) => onChange({ from: e.target.value })} />}
        </Field>
        <Field label={t("firewall.col.dst")} help={t("firewall.addrHelp")}>
          {(p) => <input {...p} className="input font-mono" value={spec.to} onChange={(e) => onChange({ to: e.target.value })} />}
        </Field>
      </div>
      <Field label={t("firewall.col.comment")} help={t("firewall.commentHelp")}>
        {(p) => <input {...p} className="input" maxLength={80} value={spec.comment ?? ""} onChange={(e) => onChange({ comment: e.target.value })} />}
      </Field>
    </div>
  );
}
