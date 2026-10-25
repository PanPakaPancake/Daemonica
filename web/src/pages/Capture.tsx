import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { applyTable, DataTable, type Column, type Filters, type SortState } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Notice, Panel, Steps } from "../components/ui";
import { api } from "../lib/api";
import {
  exprAllowed,
  filterPreview,
  parsePorts,
  templateBuilder,
  templates,
  type Line,
  type Lines,
  type Meta,
  type Spec,
  type Stats,
  type Status,
  type Template,
} from "../lib/capture";
import { errorText } from "../lib/errors";
import { followEndText, useFollow } from "../lib/follow";
import { bytes, dateTime, num, rate } from "../lib/format";
import { useSession } from "../lib/session";

// SPEC §7.6 M1.5d: client buffer of at most 10,000 lines; the table shows the
// newest MAX_SHOWN of the filtered lines to stay responsive.
const MAX_BUFFER = 10_000;
const MAX_SHOWN = 1000;
const retentionOptions = [1, 6, 12, 24, 48, 72, 168];
const stateTone: Record<string, string> = { running: "text-ok", done: "text-muted", failed: "text-bad" };

export function Capture() {
  const { t, i18n } = useTranslation();
  const { me, withStepUp } = useSession();
  const qc = useQueryClient();
  const isAdmin = me?.role === "admin";
  const [wizard, setWizard] = useState(false);
  const [confirm, setConfirm] = useState<{ all: true } | { meta: Meta }>();
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "warn" | "bad" }>();
  const [busy, setBusy] = useState(false);
  const q = useQuery({
    queryKey: ["captures"],
    queryFn: () => api<Status>("GET", "/captures"),
    enabled: isAdmin,
    refetchInterval: (query) => (query.state.data?.current?.meta.state === "running" ? 2000 : 15_000),
  });
  const s = q.data;
  const running = s?.current?.meta.state === "running";
  const refresh = () => void qc.invalidateQueries({ queryKey: ["captures"] });

  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    setDone(undefined);
    try {
      await fn();
      if (ok) setDone({ msg: ok, tone: "ok" });
    } catch (e) {
      setDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const download = (m: Meta) =>
    act(async () => {
      const { token } = await withStepUp(() => api<{ token: string }>("POST", "/captures/download_token", { id: m.id }));
      const a = document.createElement("a");
      a.href = `/api/v1/captures/download/${encodeURIComponent(token)}`;
      a.rel = "noopener";
      document.body.append(a);
      a.click();
      a.remove();
    });

  const items = (m: Meta): MenuItem[] => [
    { label: t("capture.download"), icon: "download", disabled: m.state === "running" || m.bytes === 0, onSelect: () => void download(m) },
    {
      label: t("capture.copyFilter"),
      icon: "copy",
      disabled: !m.filter,
      onSelect: () => void navigator.clipboard?.writeText(m.filter),
    },
    { label: t("capture.stop"), icon: "stop", disabled: m.state !== "running", onSelect: () => void act(() => api("POST", "/captures/stop", { id: m.id })) },
    { label: t("common.delete"), icon: "trash", danger: true, disabled: m.state === "running", onSelect: () => setConfirm({ meta: m }) },
  ];

  const cols: Column<Meta>[] = [
    {
      key: "started",
      label: t("capture.col.started"),
      sortValue: (m) => m.started,
      filter: "date",
      tdClass: "whitespace-nowrap",
      cell: (m) => dateTime(m.started, i18n.language),
    },
    {
      key: "template",
      label: t("capture.col.template"),
      sortValue: (m) => m.template ?? "",
      filter: { options: templates.map((x) => ({ value: x, label: t(`capture.tpl.${x}.name`) })) },
      cell: (m) => (m.template ? t(`capture.tpl.${m.template}.name`, { defaultValue: m.template }) : "—"),
    },
    { key: "iface", label: t("capture.col.iface"), sortValue: (m) => m.iface, filter: "text", tdClass: "font-mono text-sm", cell: (m) => m.iface },
    {
      key: "filter",
      label: t("capture.col.filter"),
      sortValue: (m) => m.filter,
      filter: "text",
      tdClass: "max-w-[28rem] truncate font-mono text-xs",
      tdTitle: (m) => m.filter,
      cell: (m) => m.filter || t("capture.noFilter"),
    },
    {
      key: "state",
      label: t("capture.col.state"),
      sortValue: (m) => m.state,
      filter: { options: ["running", "done", "failed"].map((x) => ({ value: x, label: t(`capture.state.${x}`) })) },
      tdTitle: (m) => m.error ?? "",
      cell: (m) => (
        <span className={stateTone[m.state] ?? ""}>
          {t(`capture.state.${m.state}`)}
          {m.reason && <span className="ml-1 text-faint">({t(`capture.reason.${m.reason}`, { defaultValue: m.reason })})</span>}
        </span>
      ),
    },
    {
      key: "captured",
      label: t("capture.col.packets"),
      sortValue: (m) => m.captured,
      filter: "number",
      tdClass: "text-right tabular-nums",
      cell: (m) => m.captured.toLocaleString(i18n.language),
    },
    {
      key: "bytes",
      label: t("capture.col.size"),
      sortValue: (m) => m.bytes,
      filter: "bytes",
      tdClass: "text-right tabular-nums",
      cell: (m) => bytes(m.bytes, i18n.language),
    },
    { key: "account", label: t("capture.col.account"), sortValue: (m) => m.account ?? "", filter: "text", cell: (m) => m.account ?? "—" },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (m) => <Menu label={t("capture.actionsFor", { time: dateTime(m.started, i18n.language) })} items={items(m)} />,
    },
  ];

  if (!isAdmin) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-semibold">{t("capture.title")}</h1>
        <Notice tone="info">{t("capture.adminOnly")}</Notice>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("capture.title")}</h1>
        <p className="mt-1 text-muted">{t("capture.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}
      {s && !s.available && <Install installable={s.installable} onDone={refresh} />}

      {s?.current && (
        <LiveView
          key={s.current.meta.id}
          cur={s.current}
          busy={busy}
          onStop={() => void act(() => api("POST", "/captures/stop", { id: s.current?.meta.id }))}
        />
      )}

      {s && (
        <section className="flex flex-col gap-3">
          <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
            <h2 className="mr-auto shrink-0 text-lg font-semibold">{t("capture.list")}</h2>
            <button type="button" className="btn btn-primary min-h-9 shrink-0" disabled={!s.available || running} onClick={() => setWizard(true)}>
              <Icon name="plus" className="h-4 w-4" />
              {t("capture.new")}
            </button>
            <label className="flex shrink-0 items-center gap-2 text-sm text-muted">
              <Icon name="clock" className="h-4 w-4" />
              <span className="sr-only">{t("capture.retention")}</span>
              <select
                className="input min-h-9 py-1"
                value={s.retention_hours}
                title={t("capture.retention")}
                onChange={(e) => void act(() => api("POST", "/captures/settings", { retention_hours: Number(e.target.value) }), t("capture.retentionSaved"))}
              >
                {retentionOptions.map((h) => (
                  <option key={h} value={h}>
                    {t("capture.retentionN", { count: h })}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={refresh}>
              <Icon name="restart" className="h-4 w-4" />
              <span className="sr-only">{t("common.refresh")}</span>
            </button>
            <button
              type="button"
              className="btn btn-danger min-h-9 shrink-0"
              disabled={!s.captures.some((c) => c.state !== "running")}
              title={t("capture.deleteAll")}
              onClick={() => setConfirm({ all: true })}
            >
              <Icon name="trash" className="h-4 w-4" />
              <span className="sr-only">{t("capture.deleteAll")}</span>
            </button>
          </div>
          <p className="text-sm text-faint">
            {t("capture.usage", { used: bytes(s.total_bytes, i18n.language), limit: bytes(s.total_limit, i18n.language), count: s.captures.length })}
          </p>
          <div className="relative overflow-x-auto">
            <DataTable
              label={t("capture.list")}
              columns={cols}
              rows={s.captures}
              rowKey={(m) => m.id}
              defaultSort={{ key: "started", desc: true }}
              className="min-w-[900px]"
              rowMenu={(m) => ({ label: t("capture.actionsFor", { time: dateTime(m.started, i18n.language) }), items: items(m) })}
              empty={t("capture.empty")}
            />
          </div>
        </section>
      )}

      {wizard && s && (
        <Wizard
          status={s}
          onClose={() => setWizard(false)}
          onStarted={() => {
            setWizard(false);
            setDone({ msg: t("capture.started"), tone: "ok" });
            refresh();
          }}
        />
      )}
      {confirm && (
        <Modal title={"all" in confirm ? t("capture.deleteAll") : t("capture.deleteOne")} onClose={() => setConfirm(undefined)}>
          <p>
            {"all" in confirm
              ? t("capture.deleteAllConfirm", { count: s?.captures.length ?? 0 })
              : t("capture.deleteConfirm", { time: dateTime(confirm.meta.started, i18n.language) })}
          </p>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setConfirm(undefined)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={busy}
              onClick={() => {
                const c = confirm;
                setConfirm(undefined);
                void act(() => ("all" in c ? api("POST", "/captures/delete_all") : api("POST", "/captures/delete", { id: c.meta.id })), t("capture.deleted"));
              }}
            >
              <Icon name="trash" className="h-4 w-4" />
              {t("common.delete")}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Install({ installable, onDone }: { installable: boolean; onDone: () => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const install = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      await withStepUp(() => api("POST", "/captures/install"));
      onDone();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Notice tone="warn">
      <p>{t("capture.missing")}</p>
      {installable && (
        <>
          {err && <p className="mt-2 text-bad">{err}</p>}
          <button type="button" className="btn btn-primary mt-2" disabled={busy} onClick={() => void install()}>
            <Icon name="download" className="h-4 w-4" />
            {busy ? t("capture.installing") : t("capture.install")}
          </button>
        </>
      )}
    </Notice>
  );
}

// ---------- wizard ----------

interface Draft {
  template: Template;
  iface: string;
  proto: "" | "tcp" | "udp" | "icmp" | "arp";
  host: string;
  ports: string;
  dir: "" | "src" | "dst";
  advanced: boolean;
  expr: string;
  minutes: number;
  packets: number;
  sizeMiB: number;
  full: boolean;
  fullAck: boolean;
  promisc: boolean;
  includeDash: boolean;
  ack: boolean;
}

function toSpec(d: Draft): Spec {
  const useExpr = d.advanced && d.expr.trim() !== "";
  return {
    template: d.template,
    iface: d.iface,
    builder: useExpr ? {} : { proto: d.proto, host: d.host.trim() || undefined, ports: parsePorts(d.ports) ?? [], dir: d.dir },
    expr: useExpr ? d.expr.trim() : undefined,
    duration_sec: Math.round(d.minutes * 60),
    packets: d.packets,
    size_bytes: d.sizeMiB * 1024 * 1024,
    full_packets: d.advanced && d.full,
    accept_full_warning: d.advanced && d.full && d.fullAck,
    promisc: d.promisc,
    include_dashboard: d.includeDash,
    accept_warning: d.ack,
  };
}

const hostRE = /^[0-9A-Fa-f:.]+(\/\d{1,3})?$/;

function Wizard({ status, onClose, onStarted }: { status: Status; onClose: () => void; onStarted: () => void }) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const firstIface = status.ifaces.find((i) => i !== "lo") ?? status.ifaces[0] ?? "";
  const [d, setD] = useState<Draft>({
    template: "host",
    iface: firstIface,
    proto: "",
    host: "",
    ports: "",
    dir: "",
    advanced: false,
    expr: "",
    minutes: 5,
    packets: 100_000,
    sizeMiB: 100,
    full: false,
    fullAck: false,
    promisc: false,
    includeDash: false,
    ack: false,
  });
  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));
  const pickTemplate = (tpl: Template) => {
    const b = templateBuilder(tpl);
    set({
      template: tpl,
      proto: b.proto ?? "",
      dir: b.dir ?? "",
      ports: (b.ports ?? []).join(", "),
      host: "",
      advanced: tpl === "custom" ? d.advanced : false,
    });
  };

  const spec = toSpec(d);
  const preview = filterPreview(spec, status.dashboard_port);
  const portsBad = parsePorts(d.ports) === undefined;
  const hostBad = d.host.trim() !== "" && !hostRE.test(d.host.trim());
  const exprBad = d.advanced && !exprAllowed(d.expr);
  const needsHost = d.template === "host" && !d.advanced && !d.host.trim();
  const needsPort = d.template === "port" && !d.advanced && !d.ports.trim();
  const portsNoProto = !d.advanced && d.ports.trim() !== "" && (d.proto === "icmp" || d.proto === "arp");
  const filterOK = !portsBad && !hostBad && !exprBad && !needsHost && !needsPort && !portsNoProto;
  const limitsOK =
    d.minutes >= 1 / 60 && d.minutes <= 30 && d.packets >= 1 && d.packets <= 10_000_000 && d.sizeMiB >= 1 && d.sizeMiB <= 1024 && (!d.full || d.fullAck);
  const stepsOK = [d.ack, !!d.iface && filterOK, limitsOK, true];

  const start = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      await withStepUp(() => api<Meta>("POST", "/captures/start", spec));
      onStarted();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const check = (label: string, checked: boolean, onChange: (v: boolean) => void, help?: string) => (
    <label className="flex items-start gap-2">
      <input type="checkbox" className="mt-1" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {help && <span className="block text-sm text-muted">{help}</span>}
      </span>
    </label>
  );

  return (
    <Modal title={t("capture.new")} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        <Steps steps={[t("capture.step.warning"), t("capture.step.filter"), t("capture.step.limits"), t("capture.step.review")]} current={step} />

        {step === 0 && (
          <>
            <Notice tone="warn">
              <p className="font-semibold">{t("capture.warning.title")}</p>
              <p className="mt-1">{t("capture.warning.text")}</p>
            </Notice>
            {check(t("capture.warning.ack"), d.ack, (v) => set({ ack: v }))}
          </>
        )}

        {step === 1 && (
          <>
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1 font-medium">{t("capture.purpose")}</legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {templates.map((x) => (
                  <label
                    key={x}
                    className={`flex cursor-pointer items-start gap-2 rounded-[8px] border px-3 py-2 ${d.template === x ? "border-cyan" : "border-line"}`}
                  >
                    <input type="radio" name="tpl" className="mt-1" checked={d.template === x} onChange={() => pickTemplate(x)} />
                    <span>
                      <span className="block font-medium">{t(`capture.tpl.${x}.name`)}</span>
                      <span className="block text-sm text-muted">{t(`capture.tpl.${x}.help`)}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field label={t("capture.col.iface")} help={t("capture.ifaceHelp")}>
              {(p) => (
                <select {...p} className="input" value={d.iface} onChange={(e) => set({ iface: e.target.value })}>
                  {status.ifaces.map((i) => (
                    <option key={i} value={i}>
                      {i}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {!d.advanced && (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("capture.proto")}>
                  {(p) => (
                    <select {...p} className="input" value={d.proto} onChange={(e) => set({ proto: e.target.value as Draft["proto"] })}>
                      {(["", "tcp", "udp", "icmp", "arp"] as const).map((x) => (
                        <option key={x} value={x}>
                          {x ? x.toUpperCase() : t("capture.anyProto")}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
                <Field label={t("capture.dir")}>
                  {(p) => (
                    <select {...p} className="input" value={d.dir} onChange={(e) => set({ dir: e.target.value as Draft["dir"] })}>
                      {(["", "src", "dst"] as const).map((x) => (
                        <option key={x} value={x}>
                          {t(`capture.dirs.${x || "both"}`)}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
                <Field
                  label={t("capture.host")}
                  help={t("capture.hostHelp")}
                  error={hostBad ? t("capture.hostBad") : needsHost ? t("capture.hostNeeded") : undefined}
                >
                  {(p) => <input {...p} className="input font-mono" value={d.host} placeholder="192.0.2.10" onChange={(e) => set({ host: e.target.value })} />}
                </Field>
                <Field
                  label={t("capture.ports")}
                  help={t("capture.portsHelp")}
                  error={portsBad ? t("capture.portsBad") : needsPort ? t("capture.portNeeded") : portsNoProto ? t("capture.portsNoProto") : undefined}
                >
                  {(p) => <input {...p} className="input font-mono" value={d.ports} placeholder="443" onChange={(e) => set({ ports: e.target.value })} />}
                </Field>
              </div>
            )}
            {check(t("capture.advanced"), d.advanced, (v) => set({ advanced: v }), t("capture.advancedHelp"))}
            {d.advanced && (
              <Field label={t("capture.expr")} help={t("capture.exprHelp")} error={exprBad ? t("capture.exprBad") : undefined}>
                {(p) => (
                  <input
                    {...p}
                    className="input font-mono"
                    value={d.expr}
                    placeholder="tcp port 443 and not net 10.0.0.0/8"
                    spellCheck={false}
                    onChange={(e) => set({ expr: e.target.value })}
                  />
                )}
              </Field>
            )}
            {check(t("capture.includeDash"), d.includeDash, (v) => set({ includeDash: v }), t("capture.includeDashHelp", { port: status.dashboard_port }))}
            <FilterPreview text={preview} />
          </>
        )}

        {step === 2 && (
          <>
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label={t("capture.minutes")} help={t("capture.minutesHelp")}>
                {(p) => (
                  <input {...p} type="number" min={1} max={30} className="input" value={d.minutes} onChange={(e) => set({ minutes: Number(e.target.value) })} />
                )}
              </Field>
              <Field label={t("capture.packets")} help={t("capture.packetsHelp")}>
                {(p) => (
                  <input
                    {...p}
                    type="number"
                    min={1}
                    max={10_000_000}
                    step={1000}
                    className="input"
                    value={d.packets}
                    onChange={(e) => set({ packets: Number(e.target.value) })}
                  />
                )}
              </Field>
              <Field label={t("capture.size")} help={t("capture.sizeHelp")}>
                {(p) => (
                  <input
                    {...p}
                    type="number"
                    min={1}
                    max={1024}
                    className="input"
                    value={d.sizeMiB}
                    onChange={(e) => set({ sizeMiB: Number(e.target.value) })}
                  />
                )}
              </Field>
            </div>
            {!limitsOK && !d.full && <Notice tone="bad">{t("capture.limitsBad")}</Notice>}
            {check(t("capture.promisc"), d.promisc, (v) => set({ promisc: v }), t("capture.promiscHelp"))}
            {d.advanced ? (
              <>
                {check(t("capture.full"), d.full, (v) => set({ full: v, fullAck: false }), t("capture.fullHelp"))}
                {d.full && (
                  <Notice tone="warn">
                    <p>{t("capture.fullWarning")}</p>
                    <div className="mt-2">{check(t("capture.fullAck"), d.fullAck, (v) => set({ fullAck: v }))}</div>
                  </Notice>
                )}
              </>
            ) : (
              <p className="text-sm text-muted">{t("capture.snaplenNote")}</p>
            )}
          </>
        )}

        {step === 3 && (
          <>
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
              <dt className="text-muted">{t("capture.purpose")}</dt>
              <dd>{t(`capture.tpl.${d.template}.name`)}</dd>
              <dt className="text-muted">{t("capture.col.iface")}</dt>
              <dd className="font-mono">{d.iface}</dd>
              <dt className="text-muted">{t("capture.limits")}</dt>
              <dd>
                {t("capture.limitsSummary", {
                  minutes: num(d.minutes, i18n.language, 0),
                  packets: d.packets.toLocaleString(i18n.language),
                  size: bytes(d.sizeMiB * 1024 * 1024, i18n.language),
                })}
              </dd>
              <dt className="text-muted">{t("capture.snaplen")}</dt>
              <dd>{d.advanced && d.full ? t("capture.snaplenFull") : t("capture.snaplenHeaders")}</dd>
              <dt className="text-muted">{t("capture.promiscShort")}</dt>
              <dd>{d.promisc ? t("common.yes") : t("common.no")}</dd>
            </dl>
            <FilterPreview text={preview} />
            <Explain>{t("capture.explain")}</Explain>
            {err && <Notice tone="bad">{err}</Notice>}
          </>
        )}

        <div className="flex justify-between gap-2 border-t border-line pt-4">
          <button type="button" className="btn btn-secondary" onClick={() => (step === 0 ? onClose() : setStep(step - 1))}>
            {step === 0 ? t("common.cancel") : t("common.back")}
          </button>
          {step < 3 ? (
            <button type="button" className="btn btn-primary" disabled={!stepsOK[step]} onClick={() => setStep(step + 1)}>
              {t("common.next")}
            </button>
          ) : (
            <button type="button" className="btn btn-primary" disabled={busy || !stepsOK.every(Boolean)} onClick={() => void start()}>
              <Icon name="play" className="h-4 w-4" />
              {busy ? t("capture.starting") : t("capture.start")}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function FilterPreview({ text }: { text: string }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-[8px] border border-line bg-bg-2 px-4 py-2">
      <p className="text-sm text-muted">{t("capture.preview")}</p>
      <code className="block break-all font-mono text-sm">{text || t("capture.noFilter")}</code>
    </div>
  );
}

// ---------- live view ----------

function LiveView({ cur, busy, onStop }: { cur: { meta: Meta; stats: Stats }; busy: boolean; onStop: () => void }) {
  const { t, i18n } = useTranslation();
  const m = cur.meta;
  const running = m.state === "running";
  const [extra, setExtra] = useState<Line[]>([]);
  // Lines the server dropped (rate limit, its buffer) plus all lines received.
  const [skipped, setSkipped] = useState(0);
  const [received, setReceived] = useState(0);
  const [paused, setPaused] = useState<Line[]>();
  const [err, setErr] = useState<string>();
  const [text, setText] = useState("");
  const [filters, setFilters] = useState<Filters>({});
  const [sort, setSort] = useState<SortState | null>({ key: "seq", desc: true });
  const last = useRef(0);

  const q = useQuery({
    queryKey: ["capture-lines", m.id],
    queryFn: async () => {
      const l = await api<Lines>("POST", "/captures/lines", { id: m.id });
      last.current = Number(l.cursor);
      setExtra([]);
      setSkipped(l.skipped);
      setReceived(l.entries.length);
      return l;
    },
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const add = (es: Line[], sk: number) => {
    const fresh = es.filter((l) => l.seq > last.current);
    if (fresh.length) last.current = fresh[fresh.length - 1]?.seq ?? last.current;
    setExtra((x) => [...x, ...fresh].slice(-MAX_BUFFER));
    setReceived((n) => n + fresh.length);
    if (sk) setSkipped((n) => n + sk);
  };
  const start = q.data?.cursor;
  useFollow<Line>("capture.lines", running && start ? { id: m.id, after: start } : undefined, add, (reason) => setErr(followEndText(t, reason)));
  // Pick up the last lines once the capture has ended.
  const tail = useQuery({
    queryKey: ["capture-tail", m.id],
    enabled: !running && !!q.data,
    queryFn: () => api<Lines>("POST", "/captures/lines", { id: m.id, after: String(last.current) }),
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const tailRows = (tail.data?.entries ?? []).filter((l) => l.seq > (extra.at(-1)?.seq ?? Number(start ?? 0)));
  const combined = [...(q.data?.entries ?? []), ...extra, ...tailRows];
  const all = combined.length > MAX_BUFFER ? combined.slice(combined.length - MAX_BUFFER) : combined;
  const hidden = skipped + (tail.data?.skipped ?? 0) + Math.max(0, received + tailRows.length - all.length);
  const rows = paused ?? all;

  const fmtTime = (s: string) => {
    const d = new Date(s);
    return `${d.toLocaleTimeString(i18n.language)}.${String(d.getMilliseconds()).padStart(3, "0")}`;
  };
  const lineItems = (l: Line): MenuItem[] => [
    { label: t("capture.live.filterSrc"), icon: "filter", onSelect: () => setFilters((f) => ({ ...f, src: l.src })) },
    { label: t("capture.live.filterDst"), icon: "filter", onSelect: () => setFilters((f) => ({ ...f, dst: l.dst })) },
    {
      label: t("capture.live.copy"),
      icon: "copy",
      onSelect: () => void navigator.clipboard?.writeText(`${l.time} ${l.proto} ${l.src} -> ${l.dst} ${l.len} ${l.info}`),
    },
  ];
  const cols: Column<Line>[] = [
    { key: "seq", label: "#", sortValue: (l) => l.seq, filter: "number", tdClass: "text-right tabular-nums text-faint", cell: (l) => l.seq },
    {
      key: "time",
      label: t("capture.live.time"),
      sortValue: (l) => l.time,
      filter: false,
      tdClass: "whitespace-nowrap tabular-nums",
      cell: (l) => fmtTime(l.time),
    },
    { key: "src", label: t("capture.live.src"), sortValue: (l) => l.src, filter: "text", tdClass: "font-mono text-sm", cell: (l) => l.src },
    { key: "dst", label: t("capture.live.dst"), sortValue: (l) => l.dst, filter: "text", tdClass: "font-mono text-sm", cell: (l) => l.dst },
    { key: "proto", label: t("capture.proto"), sortValue: (l) => l.proto, filter: "text", cell: (l) => l.proto },
    { key: "len", label: t("capture.live.len"), sortValue: (l) => l.len, filter: "number", tdClass: "text-right tabular-nums", cell: (l) => l.len },
    { key: "info", label: t("capture.live.info"), sortValue: (l) => l.info, filter: "text", tdClass: "font-mono text-xs", cell: (l) => l.info },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (l) => <Menu label={t("capture.live.actionsFor", { seq: l.seq })} items={lineItems(l)} />,
    },
  ];
  const needle = text.trim().toLowerCase();
  const sorted = applyTable(rows, cols, sort, filters);
  const matched = needle ? sorted.filter((l) => `${l.src} ${l.dst} ${l.proto} ${l.info}`.toLowerCase().includes(needle)) : sorted;
  const shown = matched.slice(0, MAX_SHOWN);

  const elapsed = cur.stats.seconds;
  return (
    <Panel>
      <div className="flex flex-col gap-4">
        <div className="relative flex flex-nowrap items-center gap-3 overflow-x-auto">
          <span aria-hidden="true" className={`h-3 w-3 shrink-0 rounded-full ${running ? "animate-pulse bg-ok" : "bg-faint"}`} />
          <h2 className="mr-auto shrink-0 text-lg font-semibold">
            {running ? t("capture.live.running", { iface: m.iface }) : t("capture.live.ended", { iface: m.iface })}
            {!running && m.reason && (
              <span className="ml-2 text-sm font-normal text-muted">({t(`capture.reason.${m.reason}`, { defaultValue: m.reason })})</span>
            )}
          </h2>
          <label className="relative min-w-40 max-w-80 flex-1">
            <span className="sr-only">{t("capture.live.search")}</span>
            <Icon name="search" className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
            <input className="input min-h-9 w-full py-1 pl-9" placeholder={t("capture.live.search")} value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <button
            type="button"
            aria-pressed={!!paused}
            className={`btn min-h-9 shrink-0 ${paused ? "btn-primary" : "btn-secondary"}`}
            title={paused ? t("capture.live.resume") : t("capture.live.pause")}
            onClick={() => setPaused(paused ? undefined : all)}
          >
            <Icon name={paused ? "play" : "stop"} className="h-4 w-4" />
            {paused ? t("capture.live.resume") : t("capture.live.pause")}
          </button>
          {running && (
            <button type="button" className="btn btn-danger min-h-9 shrink-0" disabled={busy} onClick={onStop}>
              <Icon name="stop" className="h-4 w-4" />
              {t("capture.stop")}
            </button>
          )}
        </div>
        <p className="break-all font-mono text-xs text-muted">{m.filter || t("capture.noFilter")}</p>

        <LiveStats stats={cur.stats} meta={m} elapsed={elapsed} />

        {err && <Notice tone="warn">{err}</Notice>}
        <p className="text-sm text-faint">
          {t("capture.live.summary", { shown: shown.length, matched: matched.length, buffered: rows.length })}
          {paused && <span className="text-warn"> · {t("capture.live.paused", { count: Math.max(0, all.length - paused.length) })}</span>}
          {hidden > 0 && <span className="text-warn"> · {t("capture.live.hidden", { count: hidden })}</span>}
        </p>
        <div className="relative max-h-[60vh] overflow-auto">
          <DataTable
            label={t("capture.live.label")}
            columns={cols}
            rows={shown}
            rowKey={(l) => String(l.seq)}
            loading={q.isLoading}
            sort={sort}
            onSort={setSort}
            filters={filters}
            onFilters={setFilters}
            stickyHeader
            className="min-w-[900px]"
            rowMenu={(l) => ({ label: t("capture.live.actionsFor", { seq: l.seq }), items: lineItems(l) })}
            empty={running ? t("capture.live.waiting") : t("capture.live.none")}
          />
        </div>
      </div>
    </Panel>
  );
}

function LiveStats({ stats, meta, elapsed }: { stats: Stats; meta: Meta; elapsed: number }) {
  const { t, i18n } = useTranslation();
  const protos = Object.entries(stats.protos ?? {}).sort((a, b) => b[1] - a[1]);
  const total = Math.max(1, stats.packets);
  const bar = (v: number, max: number) => `${Math.max(2, Math.round((v / Math.max(1, max)) * 100))}%`;
  const progress = [
    { label: t("capture.live.progressTime"), v: elapsed, max: meta.duration_sec, text: `${Math.round(elapsed)} / ${meta.duration_sec} s` },
    {
      label: t("capture.live.progressPackets"),
      v: stats.packets,
      max: meta.packets,
      text: `${stats.packets.toLocaleString(i18n.language)} / ${meta.packets.toLocaleString(i18n.language)}`,
    },
    {
      label: t("capture.live.progressSize"),
      v: meta.bytes,
      max: meta.size_bytes,
      text: `${bytes(meta.bytes, i18n.language)} / ${bytes(meta.size_bytes, i18n.language)}`,
    },
  ];
  const maxTalker = Math.max(1, ...stats.talkers.map((x) => x.bytes));
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      <div className="flex min-w-0 flex-col gap-2">
        <h3 className="text-sm font-semibold">{t("capture.live.limits")}</h3>
        {progress.map((p) => (
          <div key={p.label} className="text-sm">
            <div className="flex justify-between gap-2">
              <span className="text-muted">{p.label}</span>
              <span className="tabular-nums">{p.text}</span>
            </div>
            <div className="mt-0.5 h-1.5 rounded-full bg-bg-2">
              <div className="h-1.5 rounded-full bg-cyan" style={{ width: bar(Math.min(p.v, p.max), p.max) }} />
            </div>
          </div>
        ))}
      </div>
      <div className="min-w-0">
        <h3 className="mb-1 text-sm font-semibold">{t("capture.live.rates")}</h3>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-sm">
          <dt className="text-muted">{t("capture.live.pps")}</dt>
          <dd className="text-right tabular-nums">{num(stats.pps, i18n.language, 1)}</dd>
          <dt className="text-muted">{t("capture.live.bps")}</dt>
          <dd className="text-right tabular-nums">{rate(stats.bps, i18n.language)}</dd>
          <dt className="text-muted">{t("capture.live.totalPackets")}</dt>
          <dd className="text-right tabular-nums">{stats.packets.toLocaleString(i18n.language)}</dd>
          <dt className="text-muted">{t("capture.live.totalBytes")}</dt>
          <dd className="text-right tabular-nums">{bytes(stats.bytes, i18n.language)}</dd>
        </dl>
      </div>
      <div className="min-w-0">
        <h3 className="mb-1 text-sm font-semibold">{t("capture.live.protos")}</h3>
        {protos.length === 0 ? (
          <p className="text-sm text-faint">—</p>
        ) : (
          <ol className="flex flex-col gap-1 text-sm">
            {protos.slice(0, 6).map(([k, n]) => (
              <li key={k}>
                <div className="flex justify-between gap-3">
                  <span className="truncate">{k}</span>
                  <span className="tabular-nums text-muted">{Math.round((n / total) * 100)} %</span>
                </div>
                <div className="h-1 rounded-full bg-bg-2">
                  <div className="h-1 rounded-full bg-cyan/70" style={{ width: bar(n, total) }} />
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
      <div className="min-w-0">
        <h3 className="mb-1 text-sm font-semibold">{t("capture.live.talkers")}</h3>
        {stats.talkers.length === 0 ? (
          <p className="text-sm text-faint">—</p>
        ) : (
          <ol className="flex flex-col gap-1 text-sm">
            {stats.talkers.slice(0, 6).map((x) => (
              <li key={x.host}>
                <div className="flex justify-between gap-3">
                  <span className="truncate font-mono">{x.host}</span>
                  <span className="shrink-0 tabular-nums text-muted">{bytes(x.bytes, i18n.language)}</span>
                </div>
                <div className="h-1 rounded-full bg-bg-2">
                  <div className="h-1 rounded-full bg-cyan/70" style={{ width: bar(x.bytes, maxTalker) }} />
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}
