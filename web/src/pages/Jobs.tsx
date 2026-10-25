import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Notice, Steps } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { dateTime, relative } from "../lib/format";
import {
  cleanPath,
  describe,
  duplicate,
  idRE,
  interpreters,
  joinArgs,
  kinds,
  noControl,
  slug,
  splitArgs,
  timeRE,
  weekdays,
  type CalendarResult,
  type CronEntry,
  type CronFile,
  type FieldError,
  type Job,
  type JobCheck,
  type JobDetail,
  type JobView,
  type Kind,
  type Mode,
  type Overview,
  type Run,
  type Timer,
} from "../lib/jobs";
import { useSession } from "../lib/session";
import { cronErrors, cronKinds, fromCron, hourSteps, minuteSteps, toCron, type CronDraft, type CronKind } from "../lib/cron";
import { interpreterFor } from "../lib/scripts";
import { Scripts, useLibrary } from "./Scripts";

type Tab = "managed" | "timers" | "cron" | "scripts";
const tabs: Tab[] = ["managed", "timers", "cron", "scripts"];
const isEmpty = (s?: string) => !s || s.startsWith("0001-");

function resultTone(r?: string) {
  if (!r || r === "running") return "text-muted";
  return r === "success" ? "text-ok" : "text-bad";
}

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const h = setTimeout(() => setD(v), ms);
    return () => clearTimeout(h);
  }, [v, ms]);
  return d;
}

export function Jobs() {
  const { t } = useTranslation();
  const { me } = useSession();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("managed");
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "bad" }>();
  const q = useQuery({ queryKey: ["jobs"], queryFn: () => api<Overview>("GET", "/jobs"), refetchInterval: 15_000 });
  const lib = useLibrary();
  const [planned, setPlanned] = useState<Job>();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["jobs"] });
  const isAdmin = me?.role === "admin";
  const canRun = me?.role === "admin" || me?.role === "operator";

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("jobs.title")}</h1>
        <p className="mt-1 text-muted">{t("jobs.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}
      <div role="tablist" aria-label={t("jobs.title")} className="relative flex flex-nowrap gap-1 overflow-x-auto border-b border-line">
        {tabs.map((x) => (
          <button
            key={x}
            type="button"
            role="tab"
            id={`jobs-tab-${x}`}
            aria-selected={tab === x}
            aria-controls={`jobs-panel-${x}`}
            className={`-mb-px shrink-0 border-b-2 px-4 py-2 ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
            onClick={() => setTab(x)}
          >
            {t(`jobs.tab.${x}`)}
            {q.data && (
              <span className="ml-2 text-sm text-faint">
                {x === "managed"
                  ? q.data.managed.length
                  : x === "timers"
                    ? q.data.timers.length
                    : x === "cron"
                      ? q.data.cron.entries.length
                      : (lib.data?.files.length ?? "")}
              </span>
            )}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`jobs-panel-${tab}`} aria-labelledby={`jobs-tab-${tab}`}>
        {tab === "managed" && (
          <Managed
            data={q.data}
            loading={q.isLoading}
            isAdmin={isAdmin}
            canRun={canRun}
            onDone={setDone}
            refresh={refresh}
            start={planned}
            onStarted={() => setPlanned(undefined)}
          />
        )}
        {tab === "timers" && <Timers data={q.data} loading={q.isLoading} refresh={refresh} />}
        {tab === "cron" && <Cron data={q.data} loading={q.isLoading} isAdmin={isAdmin} onDone={setDone} refresh={refresh} />}
        {tab === "scripts" && (
          <Scripts
            isAdmin={isAdmin}
            onDone={setDone}
            onSchedule={(j) => {
              setPlanned(j);
              setTab("managed");
            }}
          />
        )}
      </div>
    </div>
  );
}

// ---------- managed jobs ----------

function commandText(j: Job): string {
  switch (j.mode) {
    case "exec":
      return [j.program ?? "", joinArgs(j.args ?? [])].filter(Boolean).join(" ");
    case "script":
      return [j.interpreter, j.script, joinArgs(j.args ?? [])].filter(Boolean).join(" ");
    case "shell":
      return j.shell ?? "";
  }
}

function Managed({
  data,
  loading,
  isAdmin,
  canRun,
  onDone,
  refresh,
  start,
  onStarted,
}: {
  data?: Overview;
  loading: boolean;
  isAdmin: boolean;
  canRun: boolean;
  onDone: (d: { msg: string; tone: "ok" | "bad" } | undefined) => void;
  refresh: () => void;
  /** A job to open in the wizard (from the script library). */
  start?: Job;
  onStarted: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const [edit, setEdit] = useState<{ job?: Job; create: boolean } | undefined>(() => (start ? { job: start, create: true } : undefined));
  const [detail, setDetail] = useState<string>();
  const [del, setDel] = useState<JobView>();
  const jobs = data?.managed ?? [];
  useEffect(() => {
    if (start) onStarted();
  }, [start, onStarted]);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    onDone(undefined);
    try {
      await fn();
      onDone({ msg: ok, tone: "ok" });
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      refresh();
    }
  };
  const loadFull = async (id: string) => api<JobDetail>("POST", "/jobs/get", { id });
  const items = (j: JobView): MenuItem[] => [
    { label: t("jobs.details"), icon: "eye", onSelect: () => setDetail(j.id) },
    {
      label: t("jobs.runNow"),
      icon: "play",
      disabled: !canRun,
      onSelect: () => void act(() => api("POST", "/jobs/run", { id: j.id }), t("jobs.started", { id: j.id })),
    },
    {
      label: j.enabled ? t("jobs.disable") : t("jobs.enable"),
      icon: j.enabled ? "stop" : "check",
      disabled: !canRun,
      onSelect: () =>
        void act(() => api("POST", "/jobs/enable", { id: j.id, enabled: !j.enabled }), t(j.enabled ? "jobs.disabled" : "jobs.enabled", { id: j.id })),
    },
    { label: t("common.edit"), icon: "edit", disabled: !isAdmin, onSelect: () => void loadFull(j.id).then((d) => setEdit({ job: d, create: false })) },
    {
      label: t("jobs.duplicate"),
      icon: "copy",
      disabled: !isAdmin,
      onSelect: () =>
        void loadFull(j.id).then((d) =>
          setEdit({
            job: duplicate(
              d,
              jobs.map((x) => x.id),
            ),
            create: true,
          }),
        ),
    },
    { label: t("common.delete"), icon: "trash", danger: true, disabled: !isAdmin, onSelect: () => setDel(j) },
  ];

  const cols: Column<JobView>[] = [
    {
      key: "id",
      label: t("jobs.col.name"),
      sortValue: (j) => j.id,
      filterValue: (j) => `${j.id} ${j.description ?? ""}`,
      filter: "text",
      cell: (j) => (
        <button type="button" className="text-left" onClick={() => setDetail(j.id)}>
          <span className="block font-medium">{j.description || j.id}</span>
          <span className="block font-mono text-xs text-faint">{j.id}</span>
        </button>
      ),
    },
    {
      key: "command",
      label: t("jobs.col.command"),
      sortValue: (j) => commandText(j),
      filter: "text",
      tdClass: "max-w-[24rem] truncate font-mono text-xs",
      tdTitle: (j) => commandText(j),
      cell: (j) => commandText(j),
    },
    { key: "user", label: t("jobs.col.user"), sortValue: (j) => j.user, filter: "text", cell: (j) => j.user },
    {
      key: "schedule",
      label: t("jobs.col.schedule"),
      sortValue: (j) => describe(t, j.schedule, i18n.language),
      filter: "text",
      cell: (j) => describe(t, j.schedule, i18n.language),
    },
    {
      key: "next",
      label: t("jobs.col.next"),
      sortValue: (j) => (isEmpty(j.state.next) ? "" : j.state.next),
      filter: false,
      tdClass: "whitespace-nowrap",
      tdTitle: (j) => dateTime(j.state.next, i18n.language),
      cell: (j) => (j.enabled ? relative(j.state.next, i18n.language) : "–"),
    },
    {
      key: "last",
      label: t("jobs.col.last"),
      sortValue: (j) => (isEmpty(j.state.last) ? "" : j.state.last),
      filter: "date",
      tdClass: "whitespace-nowrap",
      tdTitle: (j) => dateTime(j.state.last, i18n.language),
      cell: (j) => relative(j.state.last, i18n.language),
    },
    {
      key: "result",
      label: t("jobs.col.result"),
      sortValue: (j) => (j.state.service_active === "activating" ? "running" : (j.state.result ?? "")),
      filter: "text",
      cell: (j) => <ResultCell timer={j.state} />,
    },
    {
      key: "enabled",
      label: t("jobs.col.state"),
      sortValue: (j) => (j.enabled ? "on" : "off"),
      filter: {
        options: [
          { value: "on", label: t("jobs.active") },
          { value: "off", label: t("jobs.inactive") },
        ],
      },
      cell: (j) => (
        <span className={j.enabled ? "text-ok" : "text-muted"}>
          {j.enabled ? t("jobs.active") : t("jobs.inactive")}
          {j.drift && (
            <span className="ml-2 text-warn" title={t("jobs.driftHelp")}>
              ⚠ {t("jobs.drift")}
            </span>
          )}
        </span>
      ),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (j) => <Menu label={t("jobs.actionsFor", { id: j.id })} items={items(j)} />,
    },
  ];

  return (
    <section className="flex flex-col gap-3 pt-4">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">{t("jobs.managedIntro")}</p>
        {isAdmin && (
          <button type="button" className="btn btn-primary min-h-9 shrink-0" onClick={() => setEdit({ create: true })}>
            <Icon name="plus" className="h-4 w-4" />
            {t("jobs.new")}
          </button>
        )}
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={refresh}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
      </div>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("jobs.tab.managed")}
          columns={cols}
          rows={jobs}
          rowKey={(j) => j.id}
          loading={loading}
          defaultSort={{ key: "id", desc: false }}
          className="min-w-[1000px]"
          rowMenu={(j) => ({ label: t("jobs.actionsFor", { id: j.id }), items: items(j) })}
          empty={t("jobs.empty")}
        />
      </div>
      {detail && (
        <Detail
          id={detail}
          canRun={canRun}
          isAdmin={isAdmin}
          onClose={() => setDetail(undefined)}
          onEdit={(d) => {
            setDetail(undefined);
            setEdit({ job: d, create: false });
          }}
          onDuplicate={(d) => {
            setDetail(undefined);
            setEdit({
              job: duplicate(
                d,
                jobs.map((x) => x.id),
              ),
              create: true,
            });
          }}
          onDelete={(d) => {
            setDetail(undefined);
            setDel(d);
          }}
          onChanged={refresh}
        />
      )}
      {edit && (
        <Wizard
          initial={edit.job}
          create={edit.create}
          taken={jobs.map((j) => j.id)}
          onClose={() => setEdit(undefined)}
          onSaved={(j) => {
            setEdit(undefined);
            onDone({ msg: t(edit.create ? "jobs.created" : "jobs.saved", { id: j.id }), tone: "ok" });
            refresh();
          }}
        />
      )}
      {del && (
        <Modal title={t("jobs.deleteTitle")} onClose={() => setDel(undefined)}>
          <p>{t("jobs.deleteConfirm", { id: del.id })}</p>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setDel(undefined)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                const j = del;
                setDel(undefined);
                void act(() => withStepUp(() => api("POST", "/jobs/delete", { id: j.id })), t("jobs.deleted", { id: j.id }));
              }}
            >
              <Icon name="trash" className="h-4 w-4" />
              {t("common.delete")}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function ResultCell({ timer }: { timer: Timer }) {
  const { t } = useTranslation();
  if (timer.service_active === "activating") return <span className="text-info">{t("jobs.result.running")}</span>;
  if (!timer.result || isEmpty(timer.last)) return <span className="text-faint">–</span>;
  return (
    <span className={resultTone(timer.result)}>
      {t(`jobs.result.${timer.result}`, { defaultValue: timer.result })}
      {timer.exit_code !== undefined && timer.result !== "success" && (
        <span className="ml-1 text-faint">({t("jobs.exitCode", { code: timer.exit_code })})</span>
      )}
    </span>
  );
}

function Detail({
  id,
  canRun,
  isAdmin,
  onClose,
  onEdit,
  onDuplicate,
  onDelete,
  onChanged,
}: {
  id: string;
  canRun: boolean;
  isAdmin: boolean;
  onClose: () => void;
  onEdit: (j: JobDetail) => void;
  onDuplicate: (j: JobDetail) => void;
  onDelete: (j: JobDetail) => void;
  onChanged: () => void;
}) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const [msg, setMsg] = useState<{ text: string; tone: "ok" | "bad" }>();
  const q = useQuery({
    queryKey: ["job", id],
    queryFn: () => api<JobDetail>("POST", "/jobs/get", { id }),
    refetchInterval: (query) => (query.state.data?.state.service_active === "activating" ? 2000 : 10_000),
  });
  const d = q.data;
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg(undefined);
    try {
      await fn();
      setMsg({ text: ok, tone: "ok" });
    } catch (e) {
      setMsg({ text: errorText(t, e), tone: "bad" });
    } finally {
      void qc.invalidateQueries({ queryKey: ["job", id] });
      onChanged();
    }
  };
  const running = d?.state.service_active === "activating";

  const runCols: Column<Run>[] = [
    {
      key: "start",
      label: t("jobs.run.start"),
      sortValue: (r) => r.start,
      filter: "date",
      tdClass: "whitespace-nowrap",
      cell: (r) => dateTime(r.start, i18n.language),
    },
    {
      key: "duration",
      label: t("jobs.run.duration"),
      sortValue: (r) => r.duration_ms ?? -1,
      filter: "number",
      tdClass: "text-right tabular-nums",
      cell: (r) => (r.duration_ms === undefined ? "–" : `${(r.duration_ms / 1000).toLocaleString(i18n.language, { maximumFractionDigits: 1 })} s`),
    },
    {
      key: "result",
      label: t("jobs.col.result"),
      sortValue: (r) => r.result,
      filter: "text",
      cell: (r) => <span className={resultTone(r.result)}>{t(`jobs.result.${r.result}`, { defaultValue: r.result })}</span>,
    },
    {
      key: "exit",
      label: t("jobs.run.exit"),
      sortValue: (r) => r.exit_code ?? null,
      filter: "number",
      tdClass: "tabular-nums",
      cell: (r) => r.exit_code ?? "–",
    },
    {
      key: "log",
      label: t("jobs.run.log"),
      filter: false,
      cell: (r) =>
        r.excerpt?.length ? (
          <details>
            <summary className="cursor-pointer text-sm">{t("jobs.run.lines", { count: r.excerpt.length })}</summary>
            <pre className="mt-2 max-h-64 max-w-[36rem] overflow-auto whitespace-pre-wrap break-all rounded-[6px] bg-bg-2 p-2 font-mono text-xs">
              {r.excerpt.join("\n")}
            </pre>
          </details>
        ) : (
          <span className="text-faint">–</span>
        ),
    },
  ];

  return (
    <Modal title={d ? d.description || d.id : t("jobs.details")} onClose={onClose} wide>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {d && (
        <div className="flex flex-col gap-4">
          <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
            <button
              type="button"
              className="btn btn-primary min-h-9 shrink-0"
              disabled={!canRun || running}
              onClick={() => void act(() => api("POST", "/jobs/run", { id }), t("jobs.started", { id }))}
            >
              <Icon name="play" className="h-4 w-4" />
              {t("jobs.runNow")}
            </button>
            {running && (
              <button
                type="button"
                className="btn btn-danger min-h-9 shrink-0"
                disabled={!canRun}
                onClick={() => void act(() => api("POST", "/jobs/stop", { id }), t("jobs.stopped", { id }))}
              >
                <Icon name="stop" className="h-4 w-4" />
                {t("jobs.stopRun")}
              </button>
            )}
            <button
              type="button"
              className="btn btn-secondary min-h-9 shrink-0"
              disabled={!canRun}
              onClick={() => void act(() => api("POST", "/jobs/enable", { id, enabled: !d.enabled }), t(d.enabled ? "jobs.disabled" : "jobs.enabled", { id }))}
            >
              <Icon name={d.enabled ? "stop" : "check"} className="h-4 w-4" />
              {d.enabled ? t("jobs.disable") : t("jobs.enable")}
            </button>
            <span className="mr-auto" />
            <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!isAdmin} title={t("common.edit")} onClick={() => onEdit(d)}>
              <Icon name="edit" className="h-4 w-4" />
              <span className="sr-only">{t("common.edit")}</span>
            </button>
            <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!isAdmin} title={t("jobs.duplicate")} onClick={() => onDuplicate(d)}>
              <Icon name="copy" className="h-4 w-4" />
              <span className="sr-only">{t("jobs.duplicate")}</span>
            </button>
            <button type="button" className="btn btn-danger min-h-9 shrink-0" disabled={!isAdmin} title={t("common.delete")} onClick={() => onDelete(d)}>
              <Icon name="trash" className="h-4 w-4" />
              <span className="sr-only">{t("common.delete")}</span>
            </button>
          </div>
          {msg && (
            <Notice tone={msg.tone} live>
              {msg.text}
            </Notice>
          )}
          {d.drift && <Notice tone="warn">{t("jobs.driftHelp")}</Notice>}
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-muted">{t("jobs.col.command")}</dt>
            <dd className="break-all font-mono">{commandText(d)}</dd>
            <dt className="text-muted">{t("jobs.col.user")}</dt>
            <dd>{d.user}</dd>
            <dt className="text-muted">{t("jobs.col.schedule")}</dt>
            <dd>
              {describe(t, d.schedule, i18n.language)}
              {d.preview.normalized && <span className="ml-2 font-mono text-xs text-faint">{d.preview.normalized}</span>}
            </dd>
            <dt className="text-muted">{t("jobs.col.state")}</dt>
            <dd className={d.enabled ? "text-ok" : "text-muted"}>{d.enabled ? t("jobs.active") : t("jobs.inactive")}</dd>
            <dt className="text-muted">{t("jobs.hardening")}</dt>
            <dd>{t(`jobs.harden.${d.hardening}`)}</dd>
          </dl>
          <NextRuns preview={d.preview} />
          <h3 className="font-semibold">{t("jobs.history", { count: d.history.length })}</h3>
          <div className="relative overflow-x-auto">
            <DataTable
              label={t("jobs.historyLabel")}
              columns={runCols}
              rows={d.history}
              rowKey={(r) => r.invocation}
              defaultSort={{ key: "start", desc: true }}
              className="min-w-[640px]"
              empty={t("jobs.noRuns")}
            />
          </div>
          <UnitFiles service={d.service_unit} timer={d.timer_unit} />
        </div>
      )}
    </Modal>
  );
}

function NextRuns({ preview, error }: { preview?: { next: string[]; approx?: boolean }; error?: string }) {
  const { t, i18n } = useTranslation();
  return (
    <div className="rounded-[8px] border border-line bg-bg-2 px-4 py-2">
      <p className="text-sm text-muted">{preview?.approx ? t("jobs.nextApprox") : t("jobs.next5")}</p>
      {error ? (
        <p className="text-sm text-bad">✖ {error}</p>
      ) : preview?.next.length ? (
        <ol className="mt-1 list-decimal pl-5 text-sm tabular-nums">
          {preview.next.map((n) => (
            <li key={n}>{dateTime(n, i18n.language)}</li>
          ))}
        </ol>
      ) : (
        <p className="text-sm text-faint">–</p>
      )}
    </div>
  );
}

function UnitFiles({ service, timer }: { service: string; timer: string }) {
  const { t } = useTranslation();
  return (
    <details className="rounded-[8px] border border-line px-4 py-2">
      <summary className="cursor-pointer font-medium">{t("jobs.unitFiles")}</summary>
      <pre className="mt-2 overflow-auto whitespace-pre font-mono text-xs">{service}</pre>
      <pre className="mt-2 overflow-auto whitespace-pre border-t border-line pt-2 font-mono text-xs">{timer}</pre>
    </details>
  );
}

// ---------- wizard ----------

interface Draft {
  description: string;
  id: string;
  idTouched: boolean;
  user: string;
  mode: Mode;
  program: string;
  script: string;
  interpreter: string;
  shell: string;
  args: string;
  kind: Kind;
  minute: number;
  time: string;
  weekdays: string[];
  day: number;
  every: number;
  unit: "min" | "h";
  calendar: string;
  timezone: string;
  persistent: boolean;
  randomDelayMin: number;
  timeoutMin: number;
  workdir: string;
  env: { name: string; value: string }[];
  hardening: "safe" | "none";
  protectHome: "read-only" | "yes" | "no";
  writePaths: string;
  memoryMiB: number;
  cpu: number;
  tasks: number;
  enabled: boolean;
  shellAck: boolean;
}

function fromJob(j: Job | undefined, user: string): Draft {
  const s = j?.schedule;
  return {
    description: j?.description ?? "",
    id: j?.id ?? "",
    idTouched: !!j,
    user: j?.user ?? user,
    mode: j?.mode ?? "exec",
    program: j?.program ?? "",
    script: j?.script ?? "",
    interpreter: j?.interpreter ?? "",
    shell: j?.shell ?? "",
    args: joinArgs(j?.args ?? []),
    kind: s?.kind ?? "daily",
    minute: s?.minute ?? 0,
    time: s?.time ?? "03:00",
    weekdays: s?.weekdays ?? ["Mon"],
    day: s?.day ?? 1,
    every: s?.every ?? 15,
    unit: s?.unit ?? "min",
    calendar: s?.calendar ?? "",
    timezone: s?.timezone ?? "",
    persistent: s?.persistent ?? true,
    randomDelayMin: Math.round((s?.random_delay_sec ?? 0) / 60),
    timeoutMin: Math.round((j?.timeout_sec ?? 3600) / 60),
    workdir: j?.workdir ?? "",
    env: j?.env ?? [],
    hardening: j?.hardening ?? "safe",
    protectHome: j?.protect_home ?? "read-only",
    writePaths: (j?.write_paths ?? []).join("\n"),
    memoryMiB: j?.memory_max_mib ?? 0,
    cpu: j?.cpu_quota ?? 0,
    tasks: j?.tasks_max ?? 0,
    enabled: j?.enabled ?? true,
    shellAck: j?.mode === "shell",
  };
}

function scheduleOf(d: Draft) {
  const base = { kind: d.kind, timezone: d.timezone || undefined, random_delay_sec: d.randomDelayMin * 60 };
  const cal = { ...base, persistent: d.persistent };
  switch (d.kind) {
    case "hourly":
      return { ...cal, minute: d.minute };
    case "daily":
      return { ...cal, time: d.time };
    case "weekly":
      return { ...cal, time: d.time, weekdays: d.weekdays };
    case "monthly":
      return { ...cal, time: d.time, day: d.day };
    case "interval":
      return { kind: d.kind, every: d.every, unit: d.unit, random_delay_sec: d.randomDelayMin * 60 };
    case "calendar":
      return { ...cal, calendar: d.calendar };
  }
}

function toJob(d: Draft): Job {
  const args = splitArgs(d.args) ?? [];
  return {
    id: d.id,
    description: d.description.trim() || undefined,
    mode: d.mode,
    program: d.mode === "exec" ? d.program.trim() : undefined,
    script: d.mode === "script" ? d.script.trim() : undefined,
    interpreter: d.mode === "script" ? d.interpreter : undefined,
    shell: d.mode === "shell" ? d.shell : undefined,
    args: d.mode === "shell" ? undefined : args,
    user: d.user,
    schedule: scheduleOf(d),
    timeout_sec: d.timeoutMin * 60,
    env: d.env.filter((e) => e.name !== ""),
    workdir: d.workdir.trim() || undefined,
    hardening: d.hardening,
    protect_home: d.hardening === "safe" ? d.protectHome : undefined,
    write_paths:
      d.hardening === "safe"
        ? d.writePaths
            .split(/\s+/)
            .map((p) => p.trim())
            .filter(Boolean)
        : undefined,
    memory_max_mib: d.memoryMiB || undefined,
    cpu_quota: d.cpu || undefined,
    tasks_max: d.tasks || undefined,
    enabled: d.enabled,
  };
}

const stepOfField: Record<string, number> = {
  id: 0,
  description: 0,
  user: 0,
  mode: 1,
  program: 1,
  script: 1,
  interpreter: 1,
  shell: 1,
  args: 1,
  kind: 2,
  minute: 2,
  time: 2,
  weekdays: 2,
  day: 2,
  every: 2,
  unit: 2,
  calendar: 2,
  timezone: 2,
  random_delay_sec: 2,
};
const envNameRE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const tzRE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+){0,2}$/;

function Wizard({
  initial,
  create,
  taken,
  onClose,
  onSaved,
}: {
  initial?: Job;
  create: boolean;
  taken: string[];
  onClose: () => void;
  onSaved: (j: Job) => void;
}) {
  const { t, i18n } = useTranslation();
  const { me, withStepUp } = useSession();
  const [step, setStep] = useState(0);
  const [d, setD] = useState<Draft>(() => fromJob(initial, me?.linux_user || "root"));
  const lib = useLibrary();
  const [check, setCheck] = useState<JobCheck>();
  const [serverErr, setServerErr] = useState<FieldError>();
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<Draft>) => {
    setD((x) => ({ ...x, ...p }));
    setCheck(undefined);
    setServerErr(undefined);
  };
  const users = useQuery({
    queryKey: ["linux-users-names"],
    queryFn: () => api<{ users: { name: string; system: boolean; uid: number }[] }>("POST", "/users/list"),
  });
  const userNames = [...new Set(["root", d.user, ...(users.data?.users ?? []).filter((u) => !u.system).map((u) => u.name)])].filter(Boolean);
  const tzs: string[] = (() => {
    try {
      return (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
    } catch {
      return [];
    }
  })();

  // Client-side checks (the server checks everything again).
  const errs: Record<string, string | undefined> = {};
  if (!idRE.test(d.id)) errs.id = t("jobs.err.id");
  else if (create && taken.includes(d.id)) errs.id = t("jobs.err.taken");
  if (!noControl(d.description) || d.description.includes("\\") || d.description.length > 200) errs.description = t("jobs.err.description");
  const argList = splitArgs(d.args);
  if (d.mode !== "shell" && (argList === undefined || argList.some((a) => !noControl(a)))) errs.args = t("jobs.err.args");
  if (d.mode === "exec" && !cleanPath(d.program.trim())) errs.program = t("jobs.err.path");
  if (d.mode === "script" && !cleanPath(d.script.trim())) errs.script = t("jobs.err.path");
  if (d.mode === "shell" && (!d.shell.trim() || !noControl(d.shell))) errs.shell = t("jobs.err.shell");
  if (["daily", "weekly", "monthly"].includes(d.kind) && !timeRE.test(d.time)) errs.time = t("jobs.err.time");
  if (d.kind === "weekly" && d.weekdays.length === 0) errs.weekdays = t("jobs.err.weekdays");
  if (d.kind === "monthly" && (d.day < 1 || d.day > 31)) errs.day = t("jobs.err.day");
  if (d.kind === "hourly" && (d.minute < 0 || d.minute > 59)) errs.minute = t("jobs.err.minute");
  if (d.kind === "interval" && (d.every < 1 || d.every > (d.unit === "h" ? 168 : 10080))) errs.every = t("jobs.err.every");
  if (d.kind === "calendar" && !/^[A-Za-z0-9*:,./~ +-]{1,200}$/.test(d.calendar.trim())) errs.calendar = t("jobs.err.calendar");
  if (d.timezone && !tzRE.test(d.timezone)) errs.timezone = t("jobs.err.timezone");
  if (d.timeoutMin < 1 || d.timeoutMin > 10080) errs.timeout = t("jobs.err.timeout");
  if (d.workdir.trim() && !cleanPath(d.workdir.trim())) errs.workdir = t("jobs.err.path");
  const names = d.env.map((e) => e.name).filter(Boolean);
  if (d.env.some((e) => (e.name && !envNameRE.test(e.name)) || !noControl(e.value)) || new Set(names).size !== names.length) errs.env = t("jobs.err.env");
  if (
    d.hardening === "safe" &&
    d.writePaths
      .split(/\s+/)
      .filter(Boolean)
      .some((p) => !cleanPath(p) || p === "/")
  )
    errs.write_paths = t("jobs.err.path");
  if (serverErr) {
    const label = t(`jobs.err.${serverErr.code}`, { defaultValue: t("jobs.err.invalid") });
    const key = serverErr.field === "interpreter" ? "script" : serverErr.field === "limits" ? "memory" : serverErr.field;
    errs[key] = errs[key] ?? label;
  }
  const stepFields = [
    ["id", "description", "user"],
    ["program", "script", "shell", "args", "interpreter"],
    ["time", "weekdays", "day", "minute", "every", "calendar", "timezone"],
    ["timeout", "workdir", "env", "write_paths", "memory"],
  ];
  const stepOK = (i: number) => (stepFields[i] ?? []).every((f) => !errs[f]) && (i !== 1 || d.mode !== "shell" || d.shellAck);

  const schedule = scheduleOf(d);
  const debounced = useDebounced(JSON.stringify(schedule), 400);
  const cal = useQuery({
    queryKey: ["jobs-calendar", debounced],
    queryFn: () => api<CalendarResult>("POST", "/jobs/calendar", { schedule: JSON.parse(debounced) }),
    enabled: step === 2 && stepOK(2),
    staleTime: 60_000,
  });
  const calErr = cal.data?.error ? t(`jobs.err.${cal.data.error.code}`, { defaultValue: t("jobs.err.invalid") }) : undefined;

  const job = toJob(d);
  const runCheck = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const c = await api<JobCheck>("POST", "/jobs/check", { job });
      if (c.error) {
        setServerErr(c.error);
        setStep(stepOfField[c.error.field] ?? 3);
      } else setCheck(c);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  const save = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      await withStepUp(() => api("POST", "/jobs/save", { job, create }));
      onSaved(job);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const box = (label: string, checked: boolean, onChange: (v: boolean) => void, help?: string) => (
    <label className="flex items-start gap-2">
      <input type="checkbox" className="mt-1" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        {label}
        {help && <span className="block text-sm text-muted">{help}</span>}
      </span>
    </label>
  );
  const num = (label: string, value: number, onChange: (v: number) => void, opts: { min: number; max: number; help?: string; error?: string }) => (
    <Field label={label} help={opts.help} error={opts.error}>
      {(p) => <input {...p} type="number" className="input" min={opts.min} max={opts.max} value={value} onChange={(e) => onChange(Number(e.target.value))} />}
    </Field>
  );
  const stepNames = [t("jobs.step.basics"), t("jobs.step.command"), t("jobs.step.schedule"), t("jobs.step.options"), t("jobs.step.review")];

  return (
    <Modal title={create ? t("jobs.new") : t("jobs.editTitle", { id: d.id })} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        <Steps steps={stepNames} current={step} />

        {step === 0 && (
          <>
            <Field label={t("jobs.description")} help={t("jobs.descriptionHelp")} error={errs.description}>
              {(p) => (
                <input
                  {...p}
                  className="input"
                  value={d.description}
                  maxLength={200}
                  onChange={(e) => set({ description: e.target.value, id: create && !d.idTouched ? slug(e.target.value) : d.id })}
                />
              )}
            </Field>
            <Field label={t("jobs.id")} help={t("jobs.idHelp", { unit: `daemonica-job-${d.id || "…"}` })} error={errs.id}>
              {(p) => (
                <input
                  {...p}
                  className="input font-mono"
                  value={d.id}
                  disabled={!create}
                  maxLength={48}
                  onChange={(e) => set({ id: e.target.value, idTouched: true })}
                />
              )}
            </Field>
            <Field label={t("jobs.col.user")} help={t("jobs.userHelp")} error={errs.user}>
              {(p) => (
                <select {...p} className="input" value={d.user} onChange={(e) => set({ user: e.target.value })}>
                  {userNames.map((u) => (
                    <option key={u} value={u}>
                      {u}
                      {u === me?.linux_user ? ` (${t("jobs.yourUser")})` : ""}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            {d.user === "root" && <Notice tone="warn">{t("jobs.rootWarning")}</Notice>}
          </>
        )}

        {step === 1 && (
          <>
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1 font-medium">{t("jobs.mode")}</legend>
              <div className="grid gap-2 sm:grid-cols-3">
                {(["exec", "script", "shell"] as const).map((m) => (
                  <label
                    key={m}
                    className={`flex cursor-pointer items-start gap-2 rounded-[8px] border px-3 py-2 ${d.mode === m ? "border-cyan" : "border-line"}`}
                  >
                    <input type="radio" name="mode" className="mt-1" checked={d.mode === m} onChange={() => set({ mode: m })} />
                    <span>
                      <span className="block font-medium">{t(`jobs.modes.${m}.name`)}</span>
                      <span className="block text-sm text-muted">{t(`jobs.modes.${m}.help`)}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            {d.mode === "exec" && (
              <Field label={t("jobs.program")} help={t("jobs.programHelp")} error={errs.program}>
                {(p) => (
                  <input
                    {...p}
                    className="input font-mono"
                    value={d.program}
                    placeholder="/usr/local/bin/backup"
                    spellCheck={false}
                    onChange={(e) => set({ program: e.target.value })}
                  />
                )}
              </Field>
            )}
            {d.mode === "script" && (lib.data?.files.length ?? 0) > 0 && (
              <Field label={t("jobs.fromLibrary")} help={t("jobs.fromLibraryHelp")}>
                {(p) => (
                  <select
                    {...p}
                    className="input font-mono"
                    value={lib.data?.files.find((f) => f.abs === d.script)?.abs ?? ""}
                    onChange={(e) => {
                      const f = lib.data?.files.find((x) => x.abs === e.target.value);
                      if (f) set({ script: f.abs, interpreter: interpreterFor(f) });
                    }}
                  >
                    <option value="">{t("jobs.fromLibraryPick")}</option>
                    {lib.data?.files.map((f) => (
                      <option key={f.abs} value={f.abs}>
                        {f.source === "local" ? t("scripts.local") : f.source}: {f.path}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
            )}
            {d.mode === "script" && (
              <div className="grid gap-4 sm:grid-cols-[2fr_1fr]">
                <Field label={t("jobs.script")} help={t("jobs.scriptHelp")} error={errs.script}>
                  {(p) => (
                    <input
                      {...p}
                      className="input font-mono"
                      value={d.script}
                      placeholder="/opt/scripts/backup.sh"
                      spellCheck={false}
                      onChange={(e) => set({ script: e.target.value })}
                    />
                  )}
                </Field>
                <Field label={t("jobs.interpreter")}>
                  {(p) => (
                    <select {...p} className="input font-mono" value={d.interpreter} onChange={(e) => set({ interpreter: e.target.value })}>
                      {interpreters.map((x) => (
                        <option key={x} value={x}>
                          {x || t("jobs.direct")}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
              </div>
            )}
            {d.mode !== "shell" && (
              <Field label={t("jobs.args")} help={t("jobs.argsHelp")} error={errs.args}>
                {(p) => (
                  <input
                    {...p}
                    className="input font-mono"
                    value={d.args}
                    placeholder={`--target "/srv/backup dir"`}
                    spellCheck={false}
                    onChange={(e) => set({ args: e.target.value })}
                  />
                )}
              </Field>
            )}
            {d.mode !== "shell" && argList && argList.length > 0 && (
              <ol className="flex flex-wrap gap-1 text-xs" aria-label={t("jobs.argsParsed")}>
                {argList.map((a, i) => (
                  <li key={`${i}-${a}`} className="rounded-[6px] border border-line bg-bg-2 px-2 py-0.5 font-mono">
                    {a === "" ? "∅" : a}
                  </li>
                ))}
              </ol>
            )}
            {d.mode === "shell" && (
              <>
                <Notice tone="warn">{t("jobs.shellWarning")}</Notice>
                <Field label={t("jobs.shell")} error={errs.shell}>
                  {(p) => (
                    <input
                      {...p}
                      className="input font-mono"
                      value={d.shell}
                      placeholder="tar czf /srv/backup/etc-$(date +%F).tgz /etc"
                      spellCheck={false}
                      onChange={(e) => set({ shell: e.target.value })}
                    />
                  )}
                </Field>
                {box(t("jobs.shellAck"), d.shellAck, (v) => set({ shellAck: v }))}
              </>
            )}
          </>
        )}

        {step === 2 && (
          <>
            <Field label={t("jobs.kind")}>
              {(p) => (
                <select {...p} className="input" value={d.kind} onChange={(e) => set({ kind: e.target.value as Kind })}>
                  {kinds.map((k) => (
                    <option key={k} value={k}>
                      {t(`jobs.kinds.${k}`)}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              {d.kind === "hourly" && num(t("jobs.minute"), d.minute, (v) => set({ minute: v }), { min: 0, max: 59, error: errs.minute })}
              {["daily", "weekly", "monthly"].includes(d.kind) && (
                <Field label={t("jobs.time")} error={errs.time}>
                  {(p) => <input {...p} type="time" className="input" value={d.time} onChange={(e) => set({ time: e.target.value })} />}
                </Field>
              )}
              {d.kind === "monthly" &&
                num(t("jobs.day"), d.day, (v) => set({ day: v }), { min: 1, max: 31, error: errs.day, help: d.day > 28 ? t("jobs.shortMonths") : undefined })}
              {d.kind === "interval" && (
                <>
                  {num(t("jobs.every"), d.every, (v) => set({ every: v }), { min: 1, max: d.unit === "h" ? 168 : 10080, error: errs.every })}
                  <Field label={t("jobs.unit")}>
                    {(p) => (
                      <select {...p} className="input" value={d.unit} onChange={(e) => set({ unit: e.target.value as "min" | "h" })}>
                        <option value="min">{t("jobs.minutes")}</option>
                        <option value="h">{t("jobs.hours")}</option>
                      </select>
                    )}
                  </Field>
                </>
              )}
              {d.kind === "calendar" && (
                <div className="sm:col-span-2">
                  <Field label={t("jobs.calendar")} help={t("jobs.calendarHelp")} error={errs.calendar}>
                    {(p) => (
                      <input
                        {...p}
                        className="input font-mono"
                        value={d.calendar}
                        placeholder="Mon..Fri *-*-* 07:30"
                        spellCheck={false}
                        onChange={(e) => set({ calendar: e.target.value })}
                      />
                    )}
                  </Field>
                </div>
              )}
            </div>
            {d.kind === "weekly" && (
              <fieldset>
                <legend className="mb-1 font-medium">{t("jobs.weekdays")}</legend>
                <div className="flex flex-wrap gap-3">
                  {weekdays.map((w, i) => (
                    <label key={w} className="flex items-center gap-1.5">
                      <input
                        type="checkbox"
                        checked={d.weekdays.includes(w)}
                        onChange={(e) => set({ weekdays: e.target.checked ? [...d.weekdays, w] : d.weekdays.filter((x) => x !== w) })}
                      />
                      {new Date(Date.UTC(2024, 0, 1 + i)).toLocaleDateString(i18n.language, { weekday: "short", timeZone: "UTC" })}
                    </label>
                  ))}
                </div>
                {errs.weekdays && <p className="mt-1 text-sm text-bad">✖ {errs.weekdays}</p>}
              </fieldset>
            )}
            {d.kind !== "interval" && (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("jobs.timezone")} help={t("jobs.timezoneHelp")} error={errs.timezone}>
                  {(p) => (
                    <>
                      <input
                        {...p}
                        className="input"
                        list="jobs-tz"
                        value={d.timezone}
                        placeholder="Europe/Berlin"
                        onChange={(e) => set({ timezone: e.target.value })}
                      />
                      <datalist id="jobs-tz">
                        {tzs.map((z) => (
                          <option key={z} value={z} />
                        ))}
                      </datalist>
                    </>
                  )}
                </Field>
                {num(t("jobs.randomDelay"), d.randomDelayMin, (v) => set({ randomDelayMin: v }), { min: 0, max: 1440, help: t("jobs.randomDelayHelp") })}
              </div>
            )}
            {d.kind !== "interval" && box(t("jobs.persistent"), d.persistent, (v) => set({ persistent: v }), t("jobs.persistentHelp"))}
            <p className="font-medium">{describe(t, schedule, i18n.language)}</p>
            <NextRuns preview={cal.data?.preview} error={calErr} />
          </>
        )}

        {step === 3 && (
          <>
            <div className="grid gap-4 sm:grid-cols-2">
              {num(t("jobs.timeout"), d.timeoutMin, (v) => set({ timeoutMin: v }), { min: 1, max: 10080, help: t("jobs.timeoutHelp"), error: errs.timeout })}
              <Field label={t("jobs.workdir")} help={t("jobs.workdirHelp")} error={errs.workdir}>
                {(p) => <input {...p} className="input font-mono" value={d.workdir} placeholder="/srv" onChange={(e) => set({ workdir: e.target.value })} />}
              </Field>
            </div>
            <EnvEditor env={d.env} onChange={(env) => set({ env })} error={errs.env} />
            <fieldset className="flex flex-col gap-2">
              <legend className="mb-1 font-medium">{t("jobs.hardening")}</legend>
              {(["safe", "none"] as const).map((h) => (
                <label key={h} className="flex items-start gap-2">
                  <input type="radio" name="harden" className="mt-1" checked={d.hardening === h} onChange={() => set({ hardening: h })} />
                  <span>
                    {t(`jobs.harden.${h}`)}
                    <span className="block text-sm text-muted">{t(`jobs.harden.${h}Help`)}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            {d.hardening === "safe" ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label={t("jobs.writePaths")} help={t("jobs.writePathsHelp")} error={errs.write_paths}>
                  {(p) => (
                    <textarea
                      {...p}
                      className="input min-h-20 font-mono"
                      value={d.writePaths}
                      placeholder={"/srv/backup\n/var/log/myjob"}
                      onChange={(e) => set({ writePaths: e.target.value })}
                    />
                  )}
                </Field>
                <Field label={t("jobs.protectHome")}>
                  {(p) => (
                    <select {...p} className="input" value={d.protectHome} onChange={(e) => set({ protectHome: e.target.value as Draft["protectHome"] })}>
                      {(["read-only", "yes", "no"] as const).map((x) => (
                        <option key={x} value={x}>
                          {t(`jobs.home.${x}`)}
                        </option>
                      ))}
                    </select>
                  )}
                </Field>
              </div>
            ) : (
              <Notice tone="warn">{t("jobs.noHardeningWarning")}</Notice>
            )}
            <div className="grid gap-4 sm:grid-cols-3">
              {num(t("jobs.memory"), d.memoryMiB, (v) => set({ memoryMiB: v }), { min: 0, max: 1048576, help: t("jobs.zeroNoLimit"), error: errs.memory })}
              {num(t("jobs.cpu"), d.cpu, (v) => set({ cpu: v }), { min: 0, max: 10000, help: t("jobs.cpuHelp") })}
              {num(t("jobs.tasks"), d.tasks, (v) => set({ tasks: v }), { min: 0, max: 1048576, help: t("jobs.zeroNoLimit") })}
            </div>
          </>
        )}

        {step === 4 && (
          <>
            {!check && !err && <p className="text-muted">{busy ? t("jobs.checking") : t("jobs.checkFirst")}</p>}
            {check && (
              <>
                <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
                  <dt className="text-muted">{t("jobs.col.name")}</dt>
                  <dd>
                    {d.description || d.id} <span className="font-mono text-xs text-faint">daemonica-job-{d.id}</span>
                  </dd>
                  <dt className="text-muted">{t("jobs.col.command")}</dt>
                  <dd className="break-all font-mono">{commandText(check.job)}</dd>
                  <dt className="text-muted">{t("jobs.col.user")}</dt>
                  <dd>{check.job.user}</dd>
                  <dt className="text-muted">{t("jobs.col.schedule")}</dt>
                  <dd>{describe(t, check.job.schedule, i18n.language)}</dd>
                </dl>
                {check.warnings.map((w) => (
                  <Notice key={w} tone="warn">
                    {t(`jobs.warn.${w}`)}
                  </Notice>
                ))}
                <NextRuns preview={check.preview} />
                <UnitFiles service={check.service_unit} timer={check.timer_unit} />
                {box(t("jobs.enableNow"), d.enabled, (v) => setD((x) => ({ ...x, enabled: v })))}
                <Explain>{t("jobs.explain")}</Explain>
              </>
            )}
          </>
        )}
        {err && <Notice tone="bad">{err}</Notice>}
        {serverErr && step < 4 && <Notice tone="bad">{t("jobs.serverRejected")}</Notice>}

        <div className="flex justify-between gap-2 border-t border-line pt-4">
          <button type="button" className="btn btn-secondary" onClick={() => (step === 0 ? onClose() : setStep(step - 1))}>
            {step === 0 ? t("common.cancel") : t("common.back")}
          </button>
          {step < 4 ? (
            <button
              type="button"
              className="btn btn-primary"
              disabled={!stepOK(step)}
              onClick={() => {
                const next = step + 1;
                setStep(next);
                if (next === 4) void runCheck();
              }}
            >
              {t("common.next")}
            </button>
          ) : (
            <button type="button" className="btn btn-primary" disabled={busy || !check} onClick={() => void save()}>
              <Icon name="save" className="h-4 w-4" />
              {create ? t("jobs.create") : t("common.save")}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function EnvEditor({
  env,
  onChange,
  error,
}: {
  env: { name: string; value: string }[];
  onChange: (e: { name: string; value: string }[]) => void;
  error?: string;
}) {
  const { t } = useTranslation();
  const upd = (i: number, p: Partial<{ name: string; value: string }>) => onChange(env.map((e, j) => (j === i ? { ...e, ...p } : e)));
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-1 font-medium">{t("jobs.env")}</legend>
      {env.map((e, i) => (
        <div key={i} className="flex flex-nowrap gap-2">
          <input
            className="input w-48 shrink-0 font-mono"
            aria-label={t("jobs.envName")}
            value={e.name}
            placeholder="NAME"
            onChange={(ev) => upd(i, { name: ev.target.value })}
          />
          <input
            className="input min-w-0 flex-1 font-mono"
            aria-label={t("jobs.envValue")}
            value={e.value}
            onChange={(ev) => upd(i, { value: ev.target.value })}
          />
          <button
            type="button"
            className="btn btn-ghost min-h-9 shrink-0 px-2"
            title={t("common.delete")}
            onClick={() => onChange(env.filter((_, j) => j !== i))}
          >
            <Icon name="trash" className="h-4 w-4" />
            <span className="sr-only">{t("common.delete")}</span>
          </button>
        </div>
      ))}
      <div>
        <button type="button" className="btn btn-secondary min-h-9" disabled={env.length >= 32} onClick={() => onChange([...env, { name: "", value: "" }])}>
          <Icon name="plus" className="h-4 w-4" />
          {t("jobs.envAdd")}
        </button>
      </div>
      <p className="text-sm text-muted">{t("jobs.envHelp")}</p>
      {error && <p className="text-sm text-bad">✖ {error}</p>}
    </fieldset>
  );
}

// ---------- systemd timers ----------

function Timers({ data, loading, refresh }: { data?: Overview; loading: boolean; refresh: () => void }) {
  const { t, i18n } = useTranslation();
  const items = (x: Timer): MenuItem[] => [
    { label: t("jobs.copyName"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(x.name).catch(() => undefined) },
    { label: t("jobs.copyUnit"), icon: "copy", disabled: !x.unit, onSelect: () => void navigator.clipboard?.writeText(x.unit).catch(() => undefined) },
  ];
  const cols: Column<Timer>[] = [
    {
      key: "name",
      label: t("jobs.col.timer"),
      sortValue: (x) => x.name,
      filterValue: (x) => `${x.name} ${x.description}`,
      filter: "text",
      cell: (x) => (
        <>
          <span className="block font-mono text-sm">
            {x.name}
            {x.name.startsWith("daemonica-job-") && <span className="ml-2 rounded-full border border-cyan px-2 text-xs">{t("jobs.managedBadge")}</span>}
          </span>
          <span className="block text-xs text-faint">{x.description}</span>
        </>
      ),
    },
    {
      key: "schedule",
      label: t("jobs.col.schedule"),
      sortValue: (x) => (x.schedule ?? []).join(" "),
      filter: "text",
      tdClass: "max-w-[18rem] font-mono text-xs",
      cell: (x) =>
        (x.schedule ?? []).map((s) => (
          <span key={s} className="block truncate" title={s}>
            {s}
          </span>
        )),
    },
    {
      key: "next",
      label: t("jobs.col.next"),
      sortValue: (x) => (isEmpty(x.next) ? "" : x.next),
      filter: false,
      tdClass: "whitespace-nowrap",
      tdTitle: (x) => dateTime(x.next, i18n.language),
      cell: (x) => relative(x.next, i18n.language),
    },
    {
      key: "last",
      label: t("jobs.col.last"),
      sortValue: (x) => (isEmpty(x.last) ? "" : x.last),
      filter: "date",
      tdClass: "whitespace-nowrap",
      tdTitle: (x) => dateTime(x.last, i18n.language),
      cell: (x) => relative(x.last, i18n.language),
    },
    { key: "unit", label: t("jobs.col.unit"), sortValue: (x) => x.unit, filter: "text", tdClass: "font-mono text-xs", cell: (x) => x.unit },
    { key: "result", label: t("jobs.col.result"), sortValue: (x) => x.result ?? "", filter: "text", cell: (x) => <ResultCell timer={x} /> },
    {
      key: "active",
      label: t("jobs.col.state"),
      sortValue: (x) => `${x.active} ${x.file_state}`,
      filter: "text",
      cell: (x) => (
        <span className={x.active === "active" ? "text-ok" : "text-muted"}>
          {x.active}
          {x.file_state && <span className="ml-1 text-faint">({x.file_state})</span>}
        </span>
      ),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (x) => <Menu label={t("jobs.actionsFor", { id: x.name })} items={items(x)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3 pt-4">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">{t("jobs.timersIntro")}</p>
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={refresh}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
      </div>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("jobs.tab.timers")}
          columns={cols}
          rows={data?.timers}
          rowKey={(x) => x.name}
          loading={loading}
          defaultSort={{ key: "next", desc: false }}
          className="min-w-[1000px]"
          rowMenu={(x) => ({ label: t("jobs.actionsFor", { id: x.name }), items: items(x) })}
          empty={t("jobs.noTimers")}
        />
      </div>
    </section>
  );
}

// ---------- cron ----------

function Cron({
  data,
  loading,
  isAdmin,
  onDone,
  refresh,
}: {
  data?: Overview;
  loading: boolean;
  isAdmin: boolean;
  onDone: (d: { msg: string; tone: "ok" | "bad" } | undefined) => void;
  refresh: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const [edit, setEdit] = useState<{ entry?: CronEntry; user: string }>();
  const [del, setDel] = useState<CronEntry>();
  const cron = data?.cron;
  const remove = async (e: CronEntry) => {
    onDone(undefined);
    try {
      const user = e.user ?? "";
      const f = await api<CronFile>("POST", "/cron/get", { user });
      await withStepUp(() => api("POST", "/cron/save", { user, hash: f.hash, line: e.line, delete: true }));
      onDone({ msg: t("jobs.cronDeleted"), tone: "ok" });
    } catch (err) {
      onDone({ msg: errorText(t, err), tone: "bad" });
    } finally {
      refresh();
    }
  };
  const items = (e: CronEntry): MenuItem[] => [
    { label: t("jobs.copyCommand"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(e.command).catch(() => undefined) },
    { label: t("common.edit"), icon: "edit", disabled: !isAdmin || !e.editable, onSelect: () => setEdit({ entry: e, user: e.user ?? "" }) },
    { label: t("common.delete"), icon: "trash", danger: true, disabled: !isAdmin || !e.editable, onSelect: () => setDel(e) },
  ];
  const cols: Column<CronEntry>[] = [
    {
      key: "source",
      label: t("jobs.col.source"),
      sortValue: (e) => e.source,
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (e) => (e.source.startsWith("user:") ? t("jobs.userCrontab", { user: e.source.slice(5) }) : e.source),
    },
    { key: "user", label: t("jobs.col.user"), sortValue: (e) => e.user ?? "", filter: "text", cell: (e) => e.user ?? "–" },
    {
      key: "schedule",
      label: t("jobs.col.schedule"),
      sortValue: (e) => e.schedule,
      filter: "text",
      tdClass: "whitespace-nowrap font-mono text-sm",
      cell: (e) =>
        e.error ? (
          <span className="text-bad" title={e.error}>
            ✖ {e.schedule || t("jobs.cronInvalid")}
          </span>
        ) : (
          e.schedule
        ),
    },
    {
      key: "next",
      label: t("jobs.col.next"),
      sortValue: (e) => e.next?.[0] ?? "",
      filter: false,
      tdClass: "whitespace-nowrap",
      tdTitle: (e) => (e.next ?? []).map((n) => dateTime(n, i18n.language)).join("\n"),
      cell: (e) =>
        e.reboot ? t("jobs.atBoot") : e.source.startsWith("/etc/cron.") && e.line === -1 ? t("jobs.periodic") : relative(e.next?.[0], i18n.language),
    },
    {
      key: "command",
      label: t("jobs.col.command"),
      sortValue: (e) => e.command,
      filter: "text",
      tdClass: "max-w-[32rem] truncate font-mono text-xs",
      tdTitle: (e) => e.command,
      cell: (e) => e.command,
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (e) => <Menu label={t("jobs.cronActions")} items={items(e)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3 pt-4">
      {cron && !cron.installed && <Notice tone="info">{t("jobs.cronMissing")}</Notice>}
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">{t("jobs.cronIntro")}</p>
        {isAdmin && cron?.installed && (
          <button type="button" className="btn btn-primary min-h-9 shrink-0" onClick={() => setEdit({ user: "" })}>
            <Icon name="plus" className="h-4 w-4" />
            {t("jobs.cronNew")}
          </button>
        )}
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={refresh}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
      </div>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("jobs.tab.cron")}
          columns={cols}
          rows={cron?.entries}
          rowKey={(e) => `${e.source}:${e.line}:${e.command}`}
          loading={loading}
          defaultSort={{ key: "source", desc: false }}
          className="min-w-[900px]"
          rowMenu={(e) => ({ label: t("jobs.cronActions"), items: items(e) })}
          empty={t("jobs.noCron")}
        />
      </div>
      {edit && (
        <CronEditor
          entry={edit.entry}
          user={edit.user}
          onClose={() => setEdit(undefined)}
          onSaved={() => {
            setEdit(undefined);
            onDone({ msg: t("jobs.cronSaved"), tone: "ok" });
            refresh();
          }}
        />
      )}
      {del && (
        <Modal title={t("jobs.cronDeleteTitle")} onClose={() => setDel(undefined)}>
          <p>{t("jobs.cronDeleteConfirm", { user: del.user })}</p>
          <code className="mt-2 block break-all rounded-[6px] bg-bg-2 p-2 font-mono text-xs">
            {del.schedule} {del.command}
          </code>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setDel(undefined)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                const e = del;
                setDel(undefined);
                void remove(e);
              }}
            >
              <Icon name="trash" className="h-4 w-4" />
              {t("common.delete")}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function CronScheduleBuilder({
  d,
  set,
  errs,
  exprError,
}: {
  d: CronDraft;
  set: (p: Partial<CronDraft>) => void;
  errs: ReturnType<typeof cronErrors>;
  exprError: boolean;
}) {
  const { t, i18n } = useTranslation();
  const err = (k?: string) => (k ? t(`jobs.err.${k}`) : undefined);
  const number = (label: string, v: number, on: (n: number) => void, min: number, max: number, error?: string) => (
    <Field label={label} error={error}>
      {(p) => <input {...p} type="number" className="input" min={min} max={max} value={v} onChange={(e) => on(e.target.valueAsNumber)} />}
    </Field>
  );
  const plain =
    d.kind === "reboot"
      ? t("jobs.atBoot")
      : d.kind === "custom"
        ? t("jobs.describe.cron", { expr: toCron(d) })
        : describe(t, { kind: d.kind, minute: d.minute, time: d.time, weekdays: d.weekdays, day: d.day, every: d.every, unit: d.unit }, i18n.language) +
          (d.kind === "interval" && d.unit === "h" ? ` (${t("jobs.atMinute", { minute: String(d.minute).padStart(2, "0") })})` : "");
  return (
    <>
      <Field label={t("jobs.kind")}>
        {(p) => (
          <select {...p} className="input" value={d.kind} onChange={(e) => set({ kind: e.target.value as CronKind, expr: toCron(d) })}>
            {cronKinds.map((k) => (
              <option key={k} value={k}>
                {k === "reboot" || k === "custom" ? t(`jobs.cronKinds.${k}`) : t(`jobs.kinds.${k}`)}
              </option>
            ))}
          </select>
        )}
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        {d.kind === "hourly" && number(t("jobs.minute"), d.minute, (v) => set({ minute: v }), 0, 59, err(errs.minute))}
        {["daily", "weekly", "monthly"].includes(d.kind) && (
          <Field label={t("jobs.time")} error={err(errs.time)}>
            {(p) => <input {...p} type="time" className="input" value={d.time} onChange={(e) => set({ time: e.target.value })} />}
          </Field>
        )}
        {d.kind === "monthly" && number(t("jobs.day"), d.day, (v) => set({ day: v }), 1, 31, err(errs.day))}
        {d.kind === "interval" && (
          <>
            <Field label={t("jobs.every")}>
              {(p) => (
                <select {...p} className="input" value={d.every} onChange={(e) => set({ every: Number(e.target.value) })}>
                  {(d.unit === "h" ? hourSteps : minuteSteps).map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <Field label={t("jobs.unit")}>
              {(p) => (
                <select
                  {...p}
                  className="input"
                  value={d.unit}
                  onChange={(e) => {
                    const unit = e.target.value as "min" | "h";
                    const steps = unit === "h" ? hourSteps : minuteSteps;
                    set({ unit, every: steps.includes(d.every) ? d.every : (steps[0] ?? 1) });
                  }}
                >
                  <option value="min">{t("jobs.minutes")}</option>
                  <option value="h">{t("jobs.hours")}</option>
                </select>
              )}
            </Field>
            {d.unit === "h" && number(t("jobs.minute"), d.minute, (v) => set({ minute: v }), 0, 59, err(errs.minute))}
          </>
        )}
        {d.kind === "custom" && (
          <div className="sm:col-span-2">
            <Field label={t("jobs.cronSchedule")} help={t("jobs.cronScheduleHelp")} error={exprError ? t("jobs.err.cron") : undefined}>
              {(p) => <input {...p} className="input font-mono" value={d.expr} spellCheck={false} onChange={(e) => set({ expr: e.target.value })} />}
            </Field>
          </div>
        )}
      </div>
      {d.kind === "weekly" && (
        <fieldset>
          <legend className="mb-1 font-medium">{t("jobs.weekdays")}</legend>
          <div className="flex flex-wrap gap-3">
            {weekdays.map((w, i) => (
              <label key={w} className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={d.weekdays.includes(w)}
                  onChange={(e) => set({ weekdays: e.target.checked ? [...d.weekdays, w] : d.weekdays.filter((x) => x !== w) })}
                />
                {new Date(Date.UTC(2024, 0, 1 + i)).toLocaleDateString(i18n.language, { weekday: "short", timeZone: "UTC" })}
              </label>
            ))}
          </div>
          {errs.weekdays && <p className="mt-1 text-sm text-bad">✖ {t("jobs.err.weekdays")}</p>}
        </fieldset>
      )}
      <p className="font-medium">
        {plain} <span className="ml-2 font-mono text-sm text-faint">{toCron(d)}</span>
      </p>
      {d.kind !== "custom" && d.kind !== "reboot" && <p className="text-sm text-muted">{t("jobs.cronServerTime")}</p>}
    </>
  );
}

function CronEditor({ entry, user: initialUser, onClose, onSaved }: { entry?: CronEntry; user: string; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const { me, withStepUp } = useSession();
  const [user, setUser] = useState(initialUser || me?.linux_user || "");
  const [cd, setCd] = useState<CronDraft>(() => fromCron(entry?.schedule ?? "0 3 * * *"));
  const schedule = toCron(cd);
  const fieldErrs = cronErrors(cd);
  const setC = (p: Partial<CronDraft>) => setCd((x) => ({ ...x, ...p }));
  // Cron runs commands through /bin/sh; % is written escaped (literal).
  const [command, setCommand] = useState(entry?.command.replace(/\\%/g, "%") ?? "");
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const users = useQuery({
    queryKey: ["linux-users-names"],
    queryFn: () => api<{ users: { name: string; system: boolean; uid: number }[] }>("POST", "/users/list"),
  });
  const names = [...new Set(["root", user, ...(users.data?.users ?? []).filter((u) => !u.system).map((u) => u.name)])].filter(Boolean);
  const debounced = useDebounced(schedule, 300);
  const pv = useQuery({
    queryKey: ["cron-preview", debounced],
    queryFn: () => api<CalendarResult>("POST", "/cron/preview", { schedule: debounced }),
    staleTime: 60_000,
  });
  const cmdBad = !command.trim() || !noControl(command) || command.length > 1000;
  const schedBad = !!pv.data?.error || Object.keys(fieldErrs).length > 0 || !schedule;
  const save = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const f = await api<CronFile>("POST", "/cron/get", { user });
      await withStepUp(() => api("POST", "/cron/save", { user, hash: f.hash, line: entry?.line ?? -1, schedule, command }));
      onSaved();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  let previewNode: ReactNode;
  if (schedule === "@reboot") previewNode = <p className="text-sm">{t("jobs.atBoot")}</p>;
  else previewNode = <NextRuns preview={pv.data?.preview} error={pv.data?.error ? t("jobs.err.cron") : undefined} />;
  return (
    <Modal title={entry ? t("jobs.cronEdit") : t("jobs.cronNew")} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        <Field label={t("jobs.col.user")} help={t("jobs.cronUserHelp")}>
          {(p) => (
            <select {...p} className="input" value={user} disabled={!!entry} onChange={(e) => setUser(e.target.value)}>
              {names.map((u) => (
                <option key={u} value={u}>
                  {u}
                </option>
              ))}
            </select>
          )}
        </Field>
        <CronScheduleBuilder d={cd} set={setC} errs={fieldErrs} exprError={cd.kind === "custom" && !!pv.data?.error} />
        {previewNode}
        <Notice tone="info">{t("jobs.cronShell")}</Notice>
        <Field label={t("jobs.col.command")} error={command && cmdBad ? t("jobs.err.shell") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={command} spellCheck={false} maxLength={1000} onChange={(e) => setCommand(e.target.value)} />}
        </Field>
        {user === "root" && <Notice tone="warn">{t("jobs.rootWarning")}</Notice>}
        {err && <Notice tone="bad">{err}</Notice>}
        <div className="flex justify-end gap-2 border-t border-line pt-4">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || cmdBad || schedBad || !user} onClick={() => void save()}>
            <Icon name="save" className="h-4 w-4" />
            {t("common.save")}
          </button>
        </div>
      </div>
    </Modal>
  );
}
