// Updates and packages (SPEC §7.8 M1.7a, DEC-031): upgradable packages with
// the security flag, package jobs with live progress, automatic security
// updates, installed packages and search, package sources (read only).
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Meter, Notice } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, duration, relative, saveText } from "../lib/format";
import { useSession } from "../lib/session";
import {
  appendLog,
  extraRemovals,
  hhmmRE,
  removalNames,
  securityNames,
  statusKey,
  suiteOf,
  termRE,
  rebootOnly,
  upgrades,
  type AptJob,
  type Found,
  type Installed,
  type JobLog,
  type Kind,
  type NeedRestart,
  type Overview,
  type Pkg,
  type Plan,
  type SourceEntry,
  type Sources,
  type Unattended,
  type UnattendedWanted,
} from "../lib/updates";

type Tab = "updates" | "auto" | "packages" | "sources" | "history";
const tabs: Tab[] = ["updates", "auto", "packages", "sources", "history"];

type Done = (d: { msg: string; tone: "ok" | "bad" } | undefined) => void;

/** A job the user is about to start: the plan is simulated first. */
interface Pending {
  kind: Kind;
  packages: string[];
  title: string;
}

function aptError(t: (k: string) => string, e: unknown, fallback: (e: unknown) => string): string {
  if (e instanceof ApiError && ["package_job_running", "plan_changed", "critical_unconfirmed", "protected_package", "simulation_failed"].includes(e.code)) {
    return t(`updates.err.${e.code}`);
  }
  return fallback(e);
}

export function Updates() {
  const { t } = useTranslation();
  const { me } = useSession();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("updates");
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "bad" }>();
  const [pending, setPending] = useState<Pending>();
  const [shown, setShown] = useState<string>();
  const isAdmin = me?.role === "admin";
  const q = useQuery({
    queryKey: ["packages", "overview"],
    queryFn: () => api<Overview>("GET", "/packages/overview"),
    refetchInterval: (query) => (query.state.data?.running ? 5000 : 60_000),
  });
  const o = q.data;
  const running = o?.running;
  const jobId = shown ?? running?.id;
  const refresh = () => void qc.invalidateQueries({ queryKey: ["packages"] });
  const start = (p: Pending) => {
    setDone(undefined);
    setPending(p);
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("updates.title")}</h1>
        <p className="mt-1 text-muted">
          {t("updates.intro")}
          {o && (
            <span className="text-faint">
              {" "}
              · {o.distro.pretty} · {t("updates.kernel")} <span className="font-mono">{o.kernel}</span>
            </span>
          )}
        </p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}
      {o && <StatusBar o={o} isAdmin={isAdmin} busy={!!running} onStart={start} />}
      {jobId && <JobPanel key={jobId} id={jobId} onClose={shown ? () => setShown(undefined) : undefined} onFinished={refresh} />}

      <div role="tablist" aria-label={t("updates.title")} className="relative flex flex-nowrap gap-1 overflow-x-auto border-b border-line">
        {tabs.map((x) => (
          <button
            key={x}
            type="button"
            role="tab"
            id={`updates-tab-${x}`}
            aria-selected={tab === x}
            aria-controls={`updates-panel-${x}`}
            className={`-mb-px shrink-0 border-b-2 px-4 py-2 ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
            onClick={() => setTab(x)}
          >
            {t(`updates.tab.${x}`)}
            {x === "updates" && o && <span className="ml-2 text-sm text-faint">{upgrades(o.upgrade).length}</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`updates-panel-${tab}`} aria-labelledby={`updates-tab-${tab}`}>
        {tab === "updates" && <Upgradable o={o} loading={q.isLoading} isAdmin={isAdmin} busy={!!running} onStart={start} />}
        {tab === "auto" && <Auto isAdmin={isAdmin} busy={!!running} onStart={start} onDone={setDone} />}
        {tab === "packages" && <Packages isAdmin={isAdmin} busy={!!running} onStart={start} />}
        {tab === "sources" && <SourcesTab />}
        {tab === "history" && <History onShow={setShown} />}
      </div>

      {pending && (
        <PlanModal
          pending={pending}
          onClose={() => setPending(undefined)}
          onStarted={(j) => {
            setPending(undefined);
            setShown(j.id);
            refresh();
          }}
          onError={(msg) => {
            setPending(undefined);
            setDone({ msg, tone: "bad" });
          }}
        />
      )}
    </div>
  );
}

type RestartState = "busy" | "ok" | "bad";

/** needrestart's list with a restart button per service and for all at once. */
function RestartServices({ services, canRestart }: { services: string[]; canRestart: boolean }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const qc = useQueryClient();
  const [state, setState] = useState<Record<string, RestartState>>({});
  const [err, setErr] = useState<string>();
  const restartable = services.filter((u) => !rebootOnly(u));
  const working = Object.values(state).includes("busy");
  const restart = async (units: string[]) => {
    setErr(undefined);
    for (const u of units) {
      setState((s) => ({ ...s, [u]: "busy" }));
      try {
        await withStepUp(() => api("POST", "/services/action", { unit: u, action: "restart" }));
        setState((s) => ({ ...s, [u]: "ok" }));
      } catch (e) {
        setState((s) => ({ ...s, [u]: "bad" }));
        setErr(`${u}: ${errorText(t, e)}`);
        if (e instanceof Error && e.message === "cancelled") break;
      }
    }
    void qc.invalidateQueries({ queryKey: ["packages", "needrestart"] });
  };
  const mark: Record<RestartState, string> = { busy: "…", ok: "✓", bad: "✖" };
  return (
    <div className="flex flex-col gap-2 rounded-[8px] border border-line bg-bg-2 px-4 py-3">
      <div className="flex flex-nowrap items-center gap-3 overflow-x-auto">
        <span aria-hidden="true" className="font-bold text-info">
          ℹ
        </span>
        <span className="min-w-0 flex-1">
          {t("updates.needRestart", { count: services.length })}{" "}
          <Link className="underline" to="/services">
            {t("updates.toServices")}
          </Link>
        </span>
        {restartable.length > 1 && (
          <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!canRestart || working} onClick={() => void restart(restartable)}>
            <Icon name="restart" className="h-4 w-4" />
            {t("updates.restartAll", { count: restartable.length })}
          </button>
        )}
      </div>
      <ul className="flex flex-wrap gap-2" aria-label={t("updates.needRestartList")}>
        {services.map((u) => (
          <li key={u} className="flex items-center gap-1 rounded-[6px] border border-line bg-bg-1 py-0.5 pl-2 pr-0.5 font-mono text-xs">
            <span>{u}</span>
            {state[u] && (
              <span
                className={state[u] === "ok" ? "text-ok" : state[u] === "bad" ? "text-bad" : "text-muted"}
                aria-label={t(`updates.restartState.${state[u]}`)}
              >
                {mark[state[u]]}
              </span>
            )}
            {rebootOnly(u) ? (
              <span className="px-1.5 font-sans text-faint" title={t("updates.rebootOnly")}>
                {t("updates.rebootOnlyShort")}
              </span>
            ) : (
              <button
                type="button"
                className="rounded-[4px] p-1 text-muted hover:bg-bg-2 hover:text-fg disabled:opacity-40"
                disabled={!canRestart || working}
                title={t("updates.restartOne", { unit: u })}
                aria-label={t("updates.restartOne", { unit: u })}
                onClick={() => void restart([u])}
              >
                <Icon name="restart" className="h-3.5 w-3.5" />
              </button>
            )}
          </li>
        ))}
      </ul>
      {err && <p className="text-sm text-bad">{err}</p>}
    </div>
  );
}

function StatusBar({ o, isAdmin, busy, onStart }: { o: Overview; isAdmin: boolean; busy: boolean; onStart: (p: Pending) => void }) {
  const { t, i18n } = useTranslation();
  const { me } = useSession();
  const canRestart = !!me && me.role !== "readonly";
  const nr = useQuery({ queryKey: ["packages", "needrestart"], queryFn: () => api<NeedRestart>("GET", "/packages/needrestart"), staleTime: 300_000 });
  const n = nr.data;
  const ups = upgrades(o.upgrade);
  const kernelPending = !!n && n.kernel > 1;
  return (
    <div className="flex flex-col gap-2">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">
          {t("updates.lastUpdate")}:{" "}
          <span className="text-fg" title={o.last_update ? dateTime(o.last_update, i18n.language) : undefined}>
            {o.last_update ? relative(o.last_update, i18n.language) : t("updates.never")}
          </span>
          {" · "}
          {t("updates.available", { count: ups.length })}
          {o.security > 0 && <span className="text-warn"> · {t("updates.securityCount", { count: o.security })}</span>}
        </p>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!isAdmin || busy}
          title={t("updates.refreshListsHint")}
          onClick={() => onStart({ kind: "update", packages: [], title: t("updates.refreshLists") })}
        >
          <Icon name="download" className="h-4 w-4" />
          {t("updates.refreshLists")}
        </button>
      </div>
      {o.sim_error && <Notice tone="bad">{t("updates.simError", { msg: o.sim_error })}</Notice>}
      {(o.broken ?? []).length > 0 && !busy && (
        <div role="alert" className="flex flex-nowrap items-center gap-3 overflow-x-auto rounded-[8px] border border-bad bg-bg-2 px-4 py-3">
          <span aria-hidden="true" className="font-bold text-bad">
            ✖
          </span>
          <span className="min-w-0 flex-1">
            {t("updates.broken", { count: o.broken.length })} <span className="font-mono text-sm">{o.broken.slice(0, 8).join(", ")}</span>
            {o.broken.length > 8 && " …"}
          </span>
          <button
            type="button"
            className="btn btn-primary min-h-9 shrink-0"
            disabled={!isAdmin}
            onClick={() => onStart({ kind: "repair", packages: [], title: t("updates.kind.repair") })}
          >
            <Icon name="play" className="h-4 w-4" />
            {t("updates.repair")}
          </button>
        </div>
      )}
      {o.lock && !busy && <Notice tone="warn">{t("updates.locked", { comm: o.lock.comm || "?", pid: o.lock.pid, file: o.lock.file })}</Notice>}
      {(o.reboot || kernelPending) && (
        <Notice tone="warn">
          {t("updates.rebootRequired")}
          {o.reboot_pkgs.length > 0 && <span className="text-muted"> ({o.reboot_pkgs.slice(0, 6).join(", ")})</span>}
          {kernelPending && n?.kernel_expected && (
            <span className="text-muted"> {t("updates.kernelPending", { cur: n.kernel_current, next: n.kernel_expected })}</span>
          )}
        </Notice>
      )}
      {n && n.services.length > 0 && <RestartServices services={n.services} canRestart={canRestart} />}
      {n && !n.available && <p className="text-xs text-faint">{t("updates.noNeedrestart")}</p>}
    </div>
  );
}

function Progress({ job }: { job: AptJob }) {
  const { t } = useTranslation();
  const label = job.phase ? t(`updates.phase.${job.phase}`) : t("updates.phase.start");
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="min-w-0 truncate">
          {label}
          {job.current && <span className="text-muted"> · {job.current}</span>}
        </span>
        {job.phase !== "lock" && <span className="tabular-nums text-muted">{Math.round(job.percent)} %</span>}
      </div>
      <Meter value={job.phase === "lock" ? 0 : job.percent} label={label} warn={101} bad={101} />
    </div>
  );
}

function stateTone(s: AptJob["state"]) {
  return s === "succeeded" ? "ok" : s === "running" ? "info" : s === "unknown" ? "warn" : "bad";
}

/** Live view of a job: progress, log, warnings and the result. */
function JobPanel({ id, onClose, onFinished }: { id: string; onClose?: () => void; onFinished: () => void }) {
  const { t, i18n } = useTranslation();
  const [job, setJob] = useState<AptJob>();
  const [log, setLog] = useState("");
  const [err, setErr] = useState<string>();
  const [follow, setFollow] = useState(true);
  const offset = useRef(0);
  const pre = useRef<HTMLPreElement>(null);
  const finished = useRef(onFinished);
  useEffect(() => {
    finished.current = onFinished;
  }, [onFinished]);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const r = await api<JobLog>("POST", "/packages/job", { id, offset: offset.current });
        if (stop) return;
        offset.current = r.next;
        if (r.log) setLog((l) => appendLog(l, r.log));
        setJob(r.job);
        setErr(undefined);
        if (r.job.state !== "running") {
          // Drain what is left of the log, then stop.
          if (r.log) timer = setTimeout(() => void tick(), 200);
          else finished.current();
          return;
        }
      } catch (e) {
        if (stop) return;
        setErr(errorText(t, e));
      }
      timer = setTimeout(() => void tick(), 1000);
    };
    void tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [id, t]);

  useEffect(() => {
    if (follow && pre.current) pre.current.scrollTop = pre.current.scrollHeight;
  }, [log, follow]);

  const title = job ? jobTitle(t, job) : t("updates.job");
  return (
    <section className="panel flex flex-col gap-3 p-4" aria-label={title}>
      <div className="flex flex-nowrap items-center gap-2">
        <h2 className="mr-auto min-w-0 truncate font-semibold">
          {title}
          {job && <span className="ml-2 text-sm font-normal text-faint">{dateTime(job.started, i18n.language)}</span>}
        </h2>
        <label className="flex shrink-0 items-center gap-1 text-sm text-muted">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          {t("updates.follow")}
        </label>
        <button
          type="button"
          className="btn btn-secondary min-h-8 shrink-0 px-2"
          title={t("updates.downloadLog")}
          onClick={() => saveText(`apt-${id}.log`, log)}
        >
          <Icon name="download" className="h-4 w-4" />
          <span className="sr-only">{t("updates.downloadLog")}</span>
        </button>
        {onClose && (
          <button type="button" className="btn btn-secondary min-h-8 shrink-0 px-2" aria-label={t("common.close")} onClick={onClose}>
            <Icon name="close" className="h-4 w-4" />
          </button>
        )}
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {job?.state === "running" && <Progress job={job} />}
      {job && job.state !== "running" && (
        <Notice tone={stateTone(job.state)} live>
          {t(`updates.state.${job.state}`)}
          {job.state === "failed" && job.exit > 0 && <span className="text-muted"> ({t("updates.exit", { code: job.exit })})</span>}
          {job.ended && <span className="text-muted"> · {duration((Date.parse(job.ended) - Date.parse(job.started)) / 1000, i18n.language)}</span>}
        </Notice>
      )}
      {job && job.issues.length > 0 && (
        <Notice tone="warn">
          <p className="font-medium">{t("updates.issues")}</p>
          <ul className="mt-1 list-disc pl-5 font-mono text-xs">
            {job.issues.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </Notice>
      )}
      {job && job.conffiles.length > 0 && (
        <Notice tone="info">
          <p>{t("updates.conffiles")}</p>
          <ul className="mt-1 list-disc pl-5 font-mono text-xs">
            {job.conffiles.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </Notice>
      )}
      <pre
        ref={pre}
        className="max-h-[40vh] min-h-24 overflow-auto whitespace-pre-wrap break-all rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-xs"
        tabIndex={0}
      >
        {log || t("updates.noOutput")}
      </pre>
    </section>
  );
}

function jobTitle(t: (k: string, o?: Record<string, unknown>) => string, j: AptJob): string {
  const pk = j.packages.length ? j.packages.slice(0, 4).join(", ") + (j.packages.length > 4 ? " …" : "") : "";
  return t(`updates.kind.${j.kind}`, { packages: pk, count: j.packages.length });
}

function PkgList({ title, pkgs, highlight }: { title: string; pkgs: Pkg[]; highlight?: Set<string> }) {
  const { t } = useTranslation();
  if (pkgs.length === 0) return null;
  return (
    <div>
      <p className="font-medium">
        {title} <span className="text-faint">({pkgs.length})</span>
      </p>
      <ul className="mt-1 max-h-48 overflow-auto rounded-[8px] border border-line p-2 font-mono text-xs">
        {pkgs.map((p) => (
          <li key={`${p.name}-${p.arch ?? ""}`} className={highlight?.has(p.name) ? "text-warn" : ""}>
            {p.name}
            {p.old && p.new ? ` ${p.old} → ${p.new}` : p.new ? ` ${p.new}` : p.old ? ` ${p.old}` : ""}
            {p.security && <span className="ml-1 text-warn">[{t("updates.security")}]</span>}
            {highlight?.has(p.name) && <span className="ml-1">({t("updates.extra")})</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Simulates a job, shows what it changes and starts it after confirmation. */
function PlanModal({
  pending,
  onClose,
  onStarted,
  onError,
}: {
  pending: Pending;
  onClose: () => void;
  onStarted: (j: AptJob) => void;
  onError: (msg: string) => void;
}) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const simulated = pending.kind !== "update" && pending.kind !== "dry-run";
  const q = useQuery({
    queryKey: ["packages", "plan", pending.kind, pending.packages],
    queryFn: () => api<Plan>("POST", "/packages/simulate", { kind: pending.kind, packages: pending.packages }),
    enabled: simulated,
    gcTime: 0,
  });
  const plan = q.data;
  const [ackExtra, setAckExtra] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const extra = plan ? extraRemovals(plan, pending.packages) : [];
  const critical = plan?.critical ?? [];
  // Finishing interrupted installs may only configure, which the simulation does not list.
  const nothing = pending.kind !== "repair" && !!plan && !plan.error && plan.sim.install.length === 0 && plan.sim.remove.length === 0;
  const ready =
    !simulated ||
    (!!plan && !plan.error && !plan.protected && !nothing && (extra.length === 0 || ackExtra) && (critical.length === 0 || typed.trim() === critical[0]));

  const go = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const j = await withStepUp(() =>
        api<AptJob>("POST", "/packages/start", {
          kind: pending.kind,
          packages: pending.packages,
          expect_remove: plan ? removalNames(plan) : [],
          ack_critical: critical.length > 0,
        }),
      );
      onStarted(j);
    } catch (e) {
      if (e instanceof ApiError && e.code === "plan_changed") {
        setErr(t("updates.err.plan_changed"));
        setAckExtra(false);
        void q.refetch();
      } else {
        onError(aptError(t, e, (x) => errorText(t, x)));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={pending.title} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        {!simulated && <p>{t(pending.kind === "update" ? "updates.updateExplain" : "updates.dryRunExplain")}</p>}
        {pending.kind === "repair" && <p>{t("updates.repairExplain")}</p>}
        {simulated && q.isLoading && <p className="text-muted">{t("updates.simulating")}</p>}
        {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
        {plan?.error && <Notice tone="bad">{t("updates.simError", { msg: plan.error })}</Notice>}
        {plan?.protected && <Notice tone="bad">{t("updates.err.protected_package")}</Notice>}
        {nothing && <Notice tone="info">{t("updates.nothingToDo")}</Notice>}
        {plan && !plan.error && (
          <>
            <PkgList title={t("updates.willInstall")} pkgs={plan.sim.install} />
            <PkgList title={t("updates.willRemove")} pkgs={plan.sim.remove} highlight={new Set(extra)} />
            {plan.sim.kept.length > 0 && <Notice tone="info">{t("updates.kept", { pkgs: plan.sim.kept.join(", ") })}</Notice>}
          </>
        )}
        {extra.length > 0 && (
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={ackExtra} onChange={(e) => setAckExtra(e.target.checked)} />
            <span>{t("updates.ackExtra", { count: extra.length })}</span>
          </label>
        )}
        {critical.length > 0 && (
          <>
            <Notice tone="warn">{t("updates.critical", { pkgs: critical.join(", ") })}</Notice>
            <Field label={t("updates.typeName", { name: critical[0] })}>
              {(p) => <input {...p} className="input font-mono" value={typed} autoComplete="off" onChange={(e) => setTyped(e.target.value)} />}
            </Field>
          </>
        )}
        {simulated && (
          <Explain>
            <p>{t("updates.explainJob")}</p>
          </Explain>
        )}
        {err && <Notice tone="bad">{err}</Notice>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button
            type="button"
            className={`btn ${pending.kind === "remove" || pending.kind === "purge" || pending.kind === "autoremove" ? "btn-danger" : "btn-primary"}`}
            disabled={!ready || busy}
            onClick={() => void go()}
          >
            <Icon name="play" className="h-4 w-4" />
            {t("updates.start")}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function Upgradable({
  o,
  loading,
  isAdmin,
  busy,
  onStart,
}: {
  o?: Overview;
  loading: boolean;
  isAdmin: boolean;
  busy: boolean;
  onStart: (p: Pending) => void;
}) {
  const { t } = useTranslation();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const rows = useMemo(() => upgrades(o?.upgrade), [o]);
  const sec = securityNames(o?.upgrade);
  const selected = rows.filter((p) => sel.has(p.name)).map((p) => p.name);
  const toggle = (n: string, on: boolean) =>
    setSel((s) => {
      const c = new Set(s);
      if (on) c.add(n);
      else c.delete(n);
      return c;
    });
  const can = isAdmin && !busy;
  const items = (p: Pkg): MenuItem[] => [
    {
      label: t("updates.installOne", { name: p.name }),
      icon: "download",
      disabled: !can,
      onSelect: () => onStart({ kind: "selected", packages: [p.name], title: t("updates.kind.selected", { packages: p.name, count: 1 }) }),
    },
    { label: sel.has(p.name) ? t("updates.unselect") : t("updates.select"), icon: "check", onSelect: () => toggle(p.name, !sel.has(p.name)) },
  ];
  const cols: Column<Pkg>[] = [
    {
      key: "sel",
      label: t("updates.select"),
      srOnly: true,
      filter: false,
      cell: (p) => (
        <input
          type="checkbox"
          aria-label={t("updates.selectName", { name: p.name })}
          checked={sel.has(p.name)}
          onChange={(e) => toggle(p.name, e.target.checked)}
        />
      ),
    },
    { key: "name", label: t("updates.col.package"), sortValue: (p) => p.name, filter: "text", tdClass: "font-mono", cell: (p) => p.name },
    { key: "old", label: t("updates.col.installed"), sortValue: (p) => p.old ?? "", filter: "text", tdClass: "font-mono text-xs", cell: (p) => p.old },
    { key: "new", label: t("updates.col.available"), sortValue: (p) => p.new ?? "", filter: "text", tdClass: "font-mono text-xs", cell: (p) => p.new },
    {
      key: "security",
      label: t("updates.col.type"),
      // Security first when sorted ascending; the filter matches the words.
      sortValue: (p) => (p.security ? 0 : 1),
      filterValue: (p) => (p.security ? "security" : "regular"),
      filter: {
        options: [
          { value: "security", label: t("updates.security") },
          { value: "regular", label: t("updates.regular") },
        ],
      },
      cell: (p) => (p.security ? <span className="text-warn">⚠ {t("updates.security")}</span> : <span className="text-muted">{t("updates.regular")}</span>),
    },
    {
      key: "origin",
      label: t("updates.col.origin"),
      sortValue: (p) => (p.origins ?? []).map(suiteOf).join(", "),
      filter: "text",
      tdClass: "text-xs",
      tdTitle: (p) => (p.origins ?? []).join("\n"),
      cell: (p) => (p.origins ?? []).map(suiteOf).join(", "),
    },
    { key: "arch", label: t("updates.col.arch"), sortValue: (p) => p.arch ?? "", filter: "text", tdClass: "text-xs", cell: (p) => p.arch },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (p) => <Menu label={t("updates.actionsFor", { name: p.name })} items={items(p)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">{t("updates.upgradableIntro")}</p>
        <button
          type="button"
          className="btn btn-primary min-h-9 shrink-0"
          disabled={!can || sec.length === 0}
          onClick={() => onStart({ kind: "selected", packages: sec, title: t("updates.installSecurity", { count: sec.length }) })}
        >
          <Icon name="shield" className="h-4 w-4" />
          {t("updates.installSecurity", { count: sec.length })}
        </button>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!can || rows.length === 0}
          onClick={() => onStart({ kind: "upgrade", packages: [], title: t("updates.installAll", { count: rows.length }) })}
        >
          <Icon name="download" className="h-4 w-4" />
          {t("updates.installAll", { count: rows.length })}
        </button>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!can || selected.length === 0}
          onClick={() => onStart({ kind: "selected", packages: selected, title: t("updates.installSelected", { count: selected.length }) })}
        >
          <Icon name="check" className="h-4 w-4" />
          {t("updates.installSelected", { count: selected.length })}
        </button>
      </div>
      {o && o.upgrade.kept.length > 0 && <Notice tone="info">{t("updates.kept", { pkgs: o.upgrade.kept.join(", ") })}</Notice>}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("updates.tab.updates")}
          columns={cols}
          rows={o ? rows : undefined}
          rowKey={(p) => `${p.name}:${p.arch ?? ""}`}
          loading={loading}
          defaultSort={{ key: "security", desc: false }}
          className="min-w-[900px]"
          rowMenu={(p) => ({ label: t("updates.actionsFor", { name: p.name }), items: items(p) })}
          empty={t("updates.upToDate")}
        />
      </div>
    </section>
  );
}

function Auto({ isAdmin, busy, onStart, onDone }: { isAdmin: boolean; busy: boolean; onStart: (p: Pending) => void; onDone: Done }) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["packages", "unattended"], queryFn: () => api<Unattended>("GET", "/packages/unattended") });
  const u = q.data;
  const [draft, setForm] = useState<UnattendedWanted>();
  // Until the user changes something, the form shows the stored values.
  const form: UnattendedWanted | undefined =
    draft ??
    (u &&
      (u.wanted ?? {
        enabled: true,
        auto_reboot: u.auto_reboot,
        reboot_time: u.reboot_time && hhmmRE.test(u.reboot_time) ? u.reboot_time : "03:30",
      }));
  const [saving, setSaving] = useState(false);
  const timeErr = form?.auto_reboot && !hhmmRE.test(form.reboot_time) ? t("updates.auto.timeInvalid") : undefined;

  const save = async () => {
    if (!form) return;
    setSaving(true);
    onDone(undefined);
    try {
      const r = await withStepUp(() => api<Unattended>("POST", "/packages/unattended", form));
      qc.setQueryData(["packages", "unattended"], r);
      onDone({ msg: t("updates.auto.saved"), tone: "ok" });
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setSaving(false);
    }
  };

  if (q.isError) return <Notice tone="bad">{errorText(t, q.error)}</Notice>;
  if (!u || !form) return <p className="text-muted">{t("common.loading")}</p>;
  const yesNo = (b: boolean) => (b ? <span className="text-ok">✓ {t("common.yes")}</span> : <span className="text-muted">✖ {t("common.no")}</span>);
  const active = u.installed && u.update_lists && u.upgrade;
  return (
    <section className="flex flex-col gap-4">
      {!u.installed && (
        <Notice tone="warn">
          {t("updates.auto.notInstalled")}{" "}
          <button
            type="button"
            className="btn btn-primary ml-2 min-h-8"
            disabled={!isAdmin || busy}
            onClick={() =>
              onStart({ kind: "install", packages: ["unattended-upgrades"], title: t("updates.kind.install", { packages: "unattended-upgrades", count: 1 }) })
            }
          >
            <Icon name="download" className="h-4 w-4" />
            {t("updates.auto.install")}
          </button>
        </Notice>
      )}
      {u.installed && !u.supported && <Notice tone="warn">{t("updates.auto.unsupported")}</Notice>}
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-4">
          <h2 className="mb-3 font-semibold">{t("updates.auto.status")}</h2>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">{t("updates.auto.active")}</dt>
            <dd>{yesNo(active)}</dd>
            <dt className="text-muted">{t("updates.auto.securityOnly")}</dt>
            <dd>{yesNo(u.security_only)}</dd>
            <dt className="text-muted">{t("updates.auto.autoReboot")}</dt>
            <dd>
              {yesNo(u.auto_reboot)}
              {u.auto_reboot && u.reboot_time && <span className="ml-1 text-muted">{u.reboot_time}</span>}
            </dd>
            <dt className="text-muted">{t("updates.auto.managed")}</dt>
            <dd>{yesNo(u.managed)}</dd>
            <dt className="text-muted">{t("updates.auto.lastRun")}</dt>
            <dd>{u.last_run ? dateTime(u.last_run.replace(" ", "T"), i18n.language) : "–"}</dd>
            <dt className="text-muted">{t("updates.auto.version")}</dt>
            <dd className="font-mono text-xs">{u.version || "–"}</dd>
          </dl>
          {[...u.origins, ...u.patterns].length > 0 && (
            <>
              <p className="mt-3 text-sm text-muted">{t("updates.auto.origins")}</p>
              <ul className="mt-1 font-mono text-xs">
                {[...u.origins, ...u.patterns].map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
            </>
          )}
        </div>
        <div className="panel flex flex-col gap-3 p-4">
          <h2 className="font-semibold">{t("updates.auto.setup")}</h2>
          <p className="text-sm text-muted">{t("updates.auto.setupIntro")}</p>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={form.enabled}
              disabled={!isAdmin}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            />
            <span>{t("updates.auto.enable")}</span>
          </label>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={form.auto_reboot}
              disabled={!isAdmin || !form.enabled}
              onChange={(e) => setForm({ ...form, auto_reboot: e.target.checked })}
            />
            <span>
              {t("updates.auto.rebootLabel")}
              <span className="block text-sm text-muted">{t("updates.auto.rebootHelp")}</span>
            </span>
          </label>
          {form.auto_reboot && form.enabled && (
            <Field label={t("updates.auto.rebootTime")} error={timeErr}>
              {(p) => (
                <input
                  {...p}
                  type="time"
                  className="input w-40"
                  value={form.reboot_time}
                  disabled={!isAdmin}
                  onChange={(e) => setForm({ ...form, reboot_time: e.target.value })}
                />
              )}
            </Field>
          )}
          <Explain>
            <p>{t("updates.auto.explain")}</p>
          </Explain>
          <div className="flex flex-nowrap justify-end gap-2">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!isAdmin || busy || !u.installed}
              onClick={() => onStart({ kind: "dry-run", packages: [], title: t("updates.kind.dry-run") })}
            >
              <Icon name="play" className="h-4 w-4" />
              {t("updates.auto.dryRun")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!isAdmin || saving || !!timeErr || !u.installed || !u.supported}
              onClick={() => void save()}
            >
              <Icon name="save" className="h-4 w-4" />
              {t("common.save")}
            </button>
          </div>
        </div>
      </div>
      <div className="panel p-4">
        <div className="mb-2 flex items-center gap-2">
          <h2 className="mr-auto font-semibold">{t("updates.auto.log")}</h2>
          <button type="button" className="btn btn-secondary min-h-8 px-2" title={t("common.refresh")} onClick={() => void q.refetch()}>
            <Icon name="restart" className="h-4 w-4" />
            <span className="sr-only">{t("common.refresh")}</span>
          </button>
        </div>
        <pre className="max-h-[40vh] overflow-auto whitespace-pre-wrap break-all rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-xs" tabIndex={0}>
          {u.log || t("updates.auto.noLog")}
        </pre>
      </div>
    </section>
  );
}

function Packages({ isAdmin, busy, onStart }: { isAdmin: boolean; busy: boolean; onStart: (p: Pending) => void }) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<"installed" | "search">("installed");
  const [term, setTerm] = useState("");
  const [query, setQuery] = useState("");
  const inst = useQuery({ queryKey: ["packages", "installed"], queryFn: () => api<Installed[]>("GET", "/packages/installed"), enabled: mode === "installed" });
  const found = useQuery({
    queryKey: ["packages", "search", query],
    queryFn: () => api<{ results: Found[]; more: boolean }>("POST", "/packages/search", { q: query }),
    enabled: mode === "search" && termRE.test(query),
  });
  const can = isAdmin && !busy;
  const rm = (name: string, purge = false): Pending => ({
    kind: purge ? "purge" : "remove",
    packages: [name],
    title: t(purge ? "updates.kind.purge" : "updates.kind.remove", { packages: name, count: 1 }),
  });
  const instItems = (p: Installed): MenuItem[] => [
    { label: t("updates.remove"), icon: "trash", danger: true, disabled: !can || p.status.startsWith("rc"), onSelect: () => onStart(rm(p.name)) },
    { label: t("updates.purge"), icon: "trash", danger: true, disabled: !can, onSelect: () => onStart(rm(p.name, true)) },
    { label: t("updates.copyName"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(p.name).catch(() => undefined) },
  ];
  const foundItems = (f: Found): MenuItem[] =>
    f.installed
      ? [{ label: t("updates.remove"), icon: "trash", danger: true, disabled: !can, onSelect: () => onStart(rm(f.name)) }]
      : [
          {
            label: t("updates.install"),
            icon: "download",
            disabled: !can,
            onSelect: () => onStart({ kind: "install", packages: [f.name], title: t("updates.kind.install", { packages: f.name, count: 1 }) }),
          },
        ];
  const statusOpts = ["installed", "held", "config", "broken", "other"].map((k) => ({ value: t(`updates.status.${k}`), label: t(`updates.status.${k}`) }));
  const instCols: Column<Installed>[] = [
    { key: "name", label: t("updates.col.package"), sortValue: (p) => p.name, filter: "text", tdClass: "font-mono", cell: (p) => p.name },
    { key: "version", label: t("updates.col.version"), sortValue: (p) => p.version, filter: "text", tdClass: "font-mono text-xs", cell: (p) => p.version },
    { key: "arch", label: t("updates.col.arch"), sortValue: (p) => p.arch, filter: "text", tdClass: "text-xs", cell: (p) => p.arch },
    {
      key: "status",
      label: t("updates.col.status"),
      sortValue: (p) => t(`updates.status.${statusKey(p.status)}`),
      filter: { options: statusOpts },
      tdTitle: (p) => p.status,
      cell: (p) => t(`updates.status.${statusKey(p.status)}`),
    },
    {
      key: "auto",
      label: t("updates.col.auto"),
      sortValue: (p) => (p.auto ? "auto" : "manual"),
      filter: {
        options: [
          { value: "manual", label: t("updates.manual") },
          { value: "auto", label: t("updates.auto.short") },
        ],
      },
      cell: (p) => (p.auto ? t("updates.auto.short") : t("updates.manual")),
    },
    {
      key: "size",
      label: t("updates.col.size"),
      sortValue: (p) => p.size_kib * 1024,
      filter: "bytes",
      tdClass: "whitespace-nowrap",
      cell: (p) => <SizeCell kib={p.size_kib} />,
    },
    { key: "section", label: t("updates.col.section"), sortValue: (p) => p.section ?? "", filter: "text", tdClass: "text-xs", cell: (p) => p.section },
    {
      key: "summary",
      label: t("updates.col.summary"),
      sortValue: (p) => p.summary ?? "",
      filter: "text",
      tdClass: "max-w-[24rem] truncate text-muted",
      tdTitle: (p) => p.summary ?? "",
      cell: (p) => p.summary,
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (p) => <Menu label={t("updates.actionsFor", { name: p.name })} items={instItems(p)} />,
    },
  ];
  const foundCols: Column<Found>[] = [
    { key: "name", label: t("updates.col.package"), sortValue: (f) => f.name, filter: "text", tdClass: "font-mono", cell: (f) => f.name },
    { key: "summary", label: t("updates.col.summary"), sortValue: (f) => f.summary, filter: "text", tdClass: "text-muted", cell: (f) => f.summary },
    {
      key: "installed",
      label: t("updates.col.installed"),
      sortValue: (f) => f.installed ?? "",
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (f) => f.installed || "–",
    },
    {
      key: "candidate",
      label: t("updates.col.available"),
      sortValue: (f) => f.candidate ?? "",
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (f) => f.candidate || "–",
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (f) => <Menu label={t("updates.actionsFor", { name: f.name })} items={foundItems(f)} />,
    },
  ];
  const termBad = term !== "" && !termRE.test(term);
  return (
    <section className="flex flex-col gap-3">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <div role="group" aria-label={t("updates.packagesView")} className="flex shrink-0 gap-1">
          {(["installed", "search"] as const).map((m) => (
            <button
              key={m}
              type="button"
              aria-pressed={mode === m}
              className={`btn min-h-9 ${mode === m ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setMode(m)}
            >
              {t(`updates.mode.${m}`)}
            </button>
          ))}
        </div>
        {mode === "search" && (
          <form
            className="flex min-w-0 flex-1 flex-nowrap gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (termRE.test(term)) setQuery(term);
            }}
          >
            <input
              className="input min-w-0 flex-1 font-mono"
              aria-label={t("updates.searchLabel")}
              aria-invalid={termBad || undefined}
              placeholder={t("updates.searchPlaceholder")}
              value={term}
              maxLength={64}
              onChange={(e) => setTerm(e.target.value)}
            />
            <button type="submit" className="btn btn-secondary min-h-9 shrink-0" disabled={!termRE.test(term)}>
              <Icon name="search" className="h-4 w-4" />
              {t("updates.search")}
            </button>
          </form>
        )}
        {mode === "installed" && (
          <button
            type="button"
            className="btn btn-secondary ml-auto min-h-9 shrink-0"
            disabled={!can}
            onClick={() => onStart({ kind: "autoremove", packages: [], title: t("updates.kind.autoremove") })}
          >
            <Icon name="trash" className="h-4 w-4" />
            {t("updates.autoremove")}
          </button>
        )}
      </div>
      {termBad && <p className="text-sm text-bad">✖ {t("updates.termInvalid")}</p>}
      {mode === "installed" && (
        <>
          {inst.isError && <Notice tone="bad">{errorText(t, inst.error)}</Notice>}
          <div className="relative overflow-x-auto">
            <DataTable
              label={t("updates.mode.installed")}
              columns={instCols}
              rows={inst.data}
              rowKey={(p) => `${p.name}:${p.arch}`}
              loading={inst.isLoading}
              defaultSort={{ key: "name", desc: false }}
              className="min-w-[1100px]"
              rowMenu={(p) => ({ label: t("updates.actionsFor", { name: p.name }), items: instItems(p) })}
              empty={t("updates.noPackages")}
              stickyHeader
            />
          </div>
        </>
      )}
      {mode === "search" && (
        <>
          {found.isError && <Notice tone="bad">{errorText(t, found.error)}</Notice>}
          {found.data?.more && <Notice tone="info">{t("updates.moreResults")}</Notice>}
          {query ? (
            <div className="relative overflow-x-auto">
              <DataTable
                label={t("updates.mode.search")}
                columns={foundCols}
                rows={found.data?.results}
                rowKey={(f) => f.name}
                loading={found.isLoading}
                defaultSort={{ key: "name", desc: false }}
                className="min-w-[900px]"
                rowMenu={(f) => ({ label: t("updates.actionsFor", { name: f.name }), items: foundItems(f) })}
                empty={t("updates.noResults")}
              />
            </div>
          ) : (
            <p className="text-muted">{t("updates.searchHint")}</p>
          )}
        </>
      )}
    </section>
  );
}

function SizeCell({ kib }: { kib: number }) {
  const { i18n } = useTranslation();
  return <>{bytes(kib * 1024, i18n.language)}</>;
}

function SourcesTab() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["packages", "sources"], queryFn: () => api<Sources>("GET", "/packages/sources") });
  const yes = t("common.yes");
  const no = t("common.no");
  const yn = [
    { value: yes, label: yes },
    { value: no, label: no },
  ];
  const cols: Column<SourceEntry>[] = [
    {
      key: "file",
      label: t("updates.col.file"),
      sortValue: (s) => `${s.file}:${String(s.line).padStart(5, "0")}`,
      filterValue: (s) => s.file,
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (s) => `${s.file}:${s.line}`,
    },
    {
      key: "format",
      label: t("updates.col.format"),
      sortValue: (s) => s.format,
      filter: {
        options: [
          { value: "one-line", label: "one-line" },
          { value: "deb822", label: "deb822" },
        ],
      },
      cell: (s) => s.format,
    },
    { key: "types", label: t("updates.col.types"), sortValue: (s) => s.types.join(" "), filter: "text", tdClass: "text-xs", cell: (s) => s.types.join(" ") },
    {
      key: "uris",
      label: t("updates.col.uris"),
      sortValue: (s) => s.uris.join(" "),
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (s) => s.uris.join(" "),
    },
    {
      key: "suites",
      label: t("updates.col.suites"),
      sortValue: (s) => s.suites.join(" "),
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (s) => s.suites.join(" "),
    },
    {
      key: "components",
      label: t("updates.col.components"),
      sortValue: (s) => s.components.join(" "),
      filter: "text",
      tdClass: "text-xs",
      cell: (s) => s.components.join(" "),
    },
    {
      key: "signed",
      label: t("updates.col.signedBy"),
      sortValue: (s) => s.signed_by ?? "",
      filter: "text",
      tdClass: "max-w-[16rem] truncate font-mono text-xs",
      tdTitle: (s) => s.signed_by ?? "",
      cell: (s) => s.signed_by || <span className="text-faint">{t("updates.systemKeyring")}</span>,
    },
    {
      key: "https",
      label: "HTTPS",
      sortValue: (s) => (s.https ? yes : no),
      filter: { options: yn },
      cell: (s) => (s.https ? <span className="text-ok">✓ {yes}</span> : <span className="text-muted">{no}</span>),
    },
    {
      key: "official",
      label: t("updates.col.official"),
      sortValue: (s) => (s.official ? yes : no),
      filter: { options: yn },
      cell: (s) => (s.official ? <span className="text-ok">✓ {yes}</span> : <span className="text-warn">⚠ {no}</span>),
    },
    {
      key: "enabled",
      label: t("updates.col.enabled"),
      sortValue: (s) => (s.enabled ? yes : no),
      filter: { options: yn },
      cell: (s) => (s.enabled ? yes : <span className="text-muted">{no}</span>),
    },
  ];
  const errs = (q.data?.files ?? []).filter((f) => (f.errors ?? []).length > 0);
  return (
    <section className="flex flex-col gap-3">
      <p className="text-sm text-muted">{t("updates.sourcesIntro")}</p>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {errs.map((f) => (
        <Notice key={f.path} tone="warn">
          <span className="font-mono">{f.path}</span>: {(f.errors ?? []).join(" · ")}
        </Notice>
      ))}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("updates.tab.sources")}
          columns={cols}
          rows={q.data?.entries}
          rowKey={(s) => `${s.file}:${s.line}`}
          loading={q.isLoading}
          defaultSort={{ key: "file", desc: false }}
          className="min-w-[1100px]"
          empty={t("updates.noSources")}
        />
      </div>
    </section>
  );
}

function History({ onShow }: { onShow: (id: string) => void }) {
  const { t, i18n } = useTranslation();
  const q = useQuery({ queryKey: ["packages", "jobs"], queryFn: () => api<AptJob[]>("GET", "/packages/jobs"), refetchInterval: 10_000 });
  const kinds: Kind[] = ["update", "upgrade", "selected", "install", "remove", "purge", "autoremove", "dry-run", "repair"];
  const states: AptJob["state"][] = ["running", "succeeded", "failed", "unknown"];
  const items = (j: AptJob): MenuItem[] => [{ label: t("updates.showLog"), icon: "eye", onSelect: () => onShow(j.id) }];
  const cols: Column<AptJob>[] = [
    {
      key: "started",
      label: t("updates.col.started"),
      sortValue: (j) => j.started,
      filter: "date",
      tdClass: "whitespace-nowrap",
      tdTitle: (j) => dateTime(j.started, i18n.language),
      cell: (j) => relative(j.started, i18n.language),
    },
    {
      key: "kind",
      label: t("updates.col.kind"),
      sortValue: (j) => t(`updates.kindShort.${j.kind}`),
      filter: { options: kinds.map((k) => ({ value: t(`updates.kindShort.${k}`), label: t(`updates.kindShort.${k}`) })) },
      cell: (j) => t(`updates.kindShort.${j.kind}`),
    },
    {
      key: "packages",
      label: t("updates.col.packages"),
      sortValue: (j) => j.packages.join(", "),
      filter: "text",
      tdClass: "max-w-[24rem] truncate font-mono text-xs",
      tdTitle: (j) => j.packages.join(", "),
      cell: (j) => j.packages.join(", ") || "–",
    },
    {
      key: "state",
      label: t("updates.col.state"),
      sortValue: (j) => t(`updates.state.${j.state}`),
      filter: { options: states.map((s) => ({ value: t(`updates.state.${s}`), label: t(`updates.state.${s}`) })) },
      cell: (j) => <span className={`text-${stateTone(j.state)}`}>{t(`updates.state.${j.state}`)}</span>,
    },
    {
      key: "duration",
      label: t("updates.col.duration"),
      sortValue: (j) => (j.ended ? (Date.parse(j.ended) - Date.parse(j.started)) / 1000 : null),
      filter: "number",
      tdClass: "whitespace-nowrap",
      cell: (j) => (j.ended ? duration((Date.parse(j.ended) - Date.parse(j.started)) / 1000, i18n.language) : "–"),
    },
    { key: "issues", label: t("updates.col.issues"), sortValue: (j) => j.issues.length, filter: "number", cell: (j) => j.issues.length || "–" },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (j) => <Menu label={t("updates.actionsForJob")} items={items(j)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3">
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("updates.tab.history")}
          columns={cols}
          rows={q.data}
          rowKey={(j) => j.id}
          loading={q.isLoading}
          defaultSort={{ key: "started", desc: true }}
          className="min-w-[900px]"
          onRowClick={(j) => onShow(j.id)}
          rowMenu={(j) => ({ label: t("updates.actionsForJob"), items: items(j) })}
          empty={t("updates.noJobs")}
        />
      </div>
    </section>
  );
}
