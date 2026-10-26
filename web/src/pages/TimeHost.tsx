// Time and host (SPEC §7.8 M1.7c, DEC-033): time zone, NTP, host name with
// /etc/hosts, and reboot or power-off with a typed confirmation, delay,
// cancel and a reconnect overlay that waits for the new boot.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { DiffView } from "../components/ChangeFlow";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Modal } from "../components/Modal";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import {
  browserZone,
  confirmName,
  countdown,
  delays,
  groupZones,
  hostnameProblem,
  inZone,
  nextPhase,
  sameZone,
  secondsUntil,
  type HostnamePlan,
  type HostState,
  type Inhibitor,
  type Phase,
  type PowerAction,
  type PowerResult,
  type TimeHost as State,
  type TimeState,
} from "../lib/timehost";
import { useNow } from "./Terminal";

type Done = (d: { msg: string; tone: "ok" | "bad" | "warn" } | undefined) => void;

export function TimeHost() {
  const { t, i18n } = useTranslation();
  const { me } = useSession();
  const qc = useQueryClient();
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "bad" | "warn" }>();
  const [power, setPower] = useState<PowerAction>();
  const [waiting, setWaiting] = useState<{ action: PowerAction; bootId: string }>();
  const q = useQuery({ queryKey: ["timehost"], queryFn: () => api<State>("GET", "/timehost"), refetchInterval: waiting ? false : 15_000 });
  const s = q.data;
  const isAdmin = me?.role === "admin";
  const refresh = () => void qc.invalidateQueries({ queryKey: ["timehost"] });
  const now = useNow(!!s?.scheduled && !waiting);
  const due = s?.scheduled && secondsUntil(s.scheduled.at, now) === 0;

  // A scheduled reboot that is due while the page is open shows the overlay too.
  useEffect(() => {
    if (!due || waiting || !s?.scheduled) return;
    const id = setTimeout(() => setWaiting({ action: s.scheduled?.type === "poweroff" ? "poweroff" : "reboot", bootId: s.boot_id }), 0);
    return () => clearTimeout(id);
  }, [due, waiting, s]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("timehost.title")}</h1>
        <p className="mt-1 text-muted">{t("timehost.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {(s?.errors ?? []).length > 0 && <Notice tone="warn">{t("timehost.daemonsMissing", { names: (s?.errors ?? []).join(", ") })}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}
      {s?.scheduled && <ScheduledBar s={s} now={now} isAdmin={isAdmin} onDone={setDone} refresh={refresh} />}
      <div className="grid gap-6 xl:grid-cols-2">
        <TimePanel time={s?.time ?? undefined} fetchedAt={q.dataUpdatedAt} isAdmin={isAdmin} onDone={setDone} refresh={refresh} />
        <HostPanel s={s} isAdmin={isAdmin} onDone={setDone} refresh={refresh} />
      </div>
      <PowerPanel s={s} isAdmin={isAdmin} onAsk={setPower} />
      {power && s && (
        <PowerModal
          action={power}
          host={s.host}
          inhibitors={s.inhibitors}
          onClose={() => setPower(undefined)}
          onDone={(r) => {
            setPower(undefined);
            if (r.at && Date.parse(r.at) - Date.now() > 30_000) {
              setDone({
                msg: t(`timehost.scheduledOk.${r.action}`, { at: inZone(Date.parse(r.at), s.time?.timezone ?? "UTC", i18n.language) }),
                tone: "ok",
              });
              refresh();
            } else {
              setWaiting({ action: r.action, bootId: r.boot_id });
            }
          }}
        />
      )}
      {waiting && (
        <Reconnect
          action={waiting.action}
          bootId={waiting.bootId}
          onBack={() => {
            setWaiting(undefined);
            setDone({ msg: t("timehost.backOnline"), tone: "ok" });
            void qc.invalidateQueries();
          }}
        />
      )}
    </div>
  );
}

function ScheduledBar({ s, now, isAdmin, onDone, refresh }: { s: State; now: number; isAdmin: boolean; onDone: Done; refresh: () => void }) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const [busy, setBusy] = useState(false);
  if (!s.scheduled) return null;
  const left = secondsUntil(s.scheduled.at, now);
  const cancel = async () => {
    setBusy(true);
    try {
      const r = await withStepUp(() => api<{ cancelled: boolean }>("POST", "/power/cancel"));
      onDone({ msg: t(r.cancelled ? "timehost.cancelled" : "timehost.nothingToCancel"), tone: r.cancelled ? "ok" : "warn" });
      refresh();
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setBusy(false);
    }
  };
  const kind = s.scheduled.type === "poweroff" ? "poweroff" : "reboot";
  return (
    <div role="status" className="flex flex-nowrap items-center gap-3 overflow-x-auto rounded-[8px] border border-warn bg-bg-2 px-4 py-3">
      <span aria-hidden="true" className="font-bold text-warn">
        ⚠
      </span>
      <span className="min-w-0 flex-1">
        {t(`timehost.pending.${kind}`, { at: inZone(Date.parse(s.scheduled.at), s.time?.timezone ?? "UTC", i18n.language) })}{" "}
        <span className="font-mono tabular-nums">{countdown(left)}</span>
      </span>
      <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!isAdmin || busy} onClick={() => void cancel()}>
        <Icon name="close" className="h-4 w-4" />
        {t("timehost.cancel")}
      </button>
    </div>
  );
}

function TimePanel({
  time,
  fetchedAt,
  isAdmin,
  onDone,
  refresh,
}: {
  time?: TimeState;
  fetchedAt: number;
  isAdmin: boolean;
  onDone: Done;
  refresh: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { withStepUp } = useSession();
  const zones = useQuery({ queryKey: ["timezones"], queryFn: () => api<string[]>("GET", "/timehost/timezones"), staleTime: Infinity });
  const [zone, setZone] = useState<string>();
  const [busy, setBusy] = useState(false);
  const now = useNow(!!time);
  // Server clock = fetched time + elapsed browser time since the fetch.
  const base = time && fetchedAt ? { server: Date.parse(time.now), local: fetchedAt } : undefined;
  const serverNow = base ? base.server + (now - base.local) : undefined;
  const drift = base ? Math.round((base.server - base.local) / 1000) : 0;
  const sel = zone ?? time?.timezone ?? "";
  const bz = browserZone(zones.data ?? []);

  const run = async (path: string, body: unknown, ok: string) => {
    setBusy(true);
    onDone(undefined);
    try {
      await withStepUp(() => api("POST", path, body));
      onDone({ msg: ok, tone: "ok" });
      setZone(undefined);
      refresh();
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">{t("timehost.time")}</h2>
      {!time && <p className="text-muted">{t("common.loading")}</p>}
      {time && (
        <>
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
            <dt className="text-muted">{t("timehost.serverTime")}</dt>
            <dd className="font-mono tabular-nums" aria-live="off">
              {serverNow !== undefined ? inZone(serverNow, time.timezone, i18n.language) : "–"}
            </dd>
            <dt className="text-muted">UTC</dt>
            <dd className="font-mono tabular-nums">{serverNow !== undefined ? inZone(serverNow, "UTC", i18n.language, false) : "–"}</dd>
            <dt className="text-muted">{t("timehost.timezone")}</dt>
            <dd className="font-mono">{time.timezone}</dd>
            <dt className="text-muted">{t("timehost.ntp")}</dt>
            <dd>
              {!time.can_ntp
                ? t("timehost.ntpUnavailable")
                : time.ntp
                  ? time.ntp_synced
                    ? `✓ ${t("timehost.ntpSynced")}`
                    : `⚠ ${t("timehost.ntpNotSynced")}`
                  : `○ ${t("timehost.ntpOff")}`}
              {time.ntp_server && <span className="ml-2 font-mono text-sm text-muted">{time.ntp_server}</span>}
            </dd>
          </dl>
          {Math.abs(drift) >= 30 && <Notice tone="warn">{t("timehost.drift", { s: drift })}</Notice>}
          {time.local_rtc && <Notice tone="warn">{t("timehost.localRtc")}</Notice>}
          <Field label={t("timehost.newTimezone")} help={bz && !sameZone(bz, time.timezone) ? t("timehost.browserZone", { zone: bz }) : undefined}>
            {(p) => (
              <div className="flex flex-nowrap gap-2">
                <select {...p} className="input min-w-0 flex-1 font-mono" value={sel} disabled={!zones.data} onChange={(e) => setZone(e.target.value)}>
                  {!zones.data?.includes(sel) && <option value={sel}>{sel}</option>}
                  {groupZones(zones.data ?? []).map(([g, zs]) => (
                    <optgroup key={g || "-"} label={g || t("timehost.otherZones")}>
                      {zs.map((z) => (
                        <option key={z} value={z}>
                          {z}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                {bz && !sameZone(bz, sel) && (
                  <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("timehost.useBrowserZone")} onClick={() => setZone(bz)}>
                    <Icon name="home" className="h-4 w-4" />
                    <span className="sr-only">{t("timehost.useBrowserZone")}</span>
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-primary min-h-9 shrink-0"
                  disabled={!isAdmin || busy || sel === time.timezone}
                  onClick={() => void run("/timehost/set_timezone", { timezone: sel }, t("timehost.timezoneSet", { zone: sel }))}
                >
                  {t("common.save")}
                </button>
              </div>
            )}
          </Field>
          {zones.isError && <Notice tone="bad">{errorText(t, zones.error)}</Notice>}
          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              role="switch"
              checked={time.ntp}
              disabled={!isAdmin || busy || !time.can_ntp}
              onChange={(e) => void run("/timehost/set_ntp", { on: e.target.checked }, t(e.target.checked ? "timehost.ntpOnDone" : "timehost.ntpOffDone"))}
            />
            <span>{t("timehost.ntpSwitch")}</span>
          </label>
          <Explain>
            <p>{t("timehost.timeExplain")}</p>
          </Explain>
        </>
      )}
    </Panel>
  );
}

function HostPanel({ s, isAdmin, onDone, refresh }: { s?: State; isAdmin: boolean; onDone: Done; refresh: () => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const h = s?.host;
  const [draft, setDraft] = useState<{ hostname: string; pretty: string; hosts: boolean }>();
  const [plan, setPlan] = useState<HostnamePlan>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const d = draft ?? { hostname: confirmName(h), pretty: h?.pretty ?? "", hosts: true };
  const problem = hostnameProblem(d.hostname);
  const changed = !!h && (d.hostname !== confirmName(h) || d.pretty !== h.pretty);
  const set = (x: Partial<typeof d>) => {
    setDraft({ ...d, ...x });
    setPlan(undefined);
  };

  const preview = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      setPlan(await api<HostnamePlan>("POST", "/timehost/hostname_plan", { hostname: d.hostname, pretty: d.pretty }));
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
      const r = await withStepUp(() => api<HostState>("POST", "/timehost/set_hostname", { hostname: d.hostname, pretty: d.pretty, update_hosts: d.hosts }));
      onDone({ msg: t("timehost.hostnameSet", { name: r.static }), tone: "ok" });
      setDraft(undefined);
      setPlan(undefined);
      refresh();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel className="flex flex-col gap-4">
      <h2 className="text-lg font-semibold">{t("timehost.host")}</h2>
      {!h && <p className="text-muted">{t("common.loading")}</p>}
      {h && s && (
        <>
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
            <dt className="text-muted">{t("timehost.static")}</dt>
            <dd className="font-mono">{h.static || "–"}</dd>
            {h.hostname !== h.static && (
              <>
                <dt className="text-muted">{t("timehost.transient")}</dt>
                <dd className="font-mono">{h.hostname}</dd>
              </>
            )}
            <dt className="text-muted">{t("timehost.pretty")}</dt>
            <dd>{h.pretty || "–"}</dd>
            <dt className="text-muted">/etc/hosts</dt>
            <dd className="break-all font-mono text-sm">{s.hosts_line || t("timehost.noHostsLine")}</dd>
            {h.os && (
              <>
                <dt className="text-muted">{t("timehost.os")}</dt>
                <dd>{h.os}</dd>
              </>
            )}
          </dl>
          <Field
            label={t("timehost.newHostname")}
            help={t("timehost.hostnameHelp")}
            error={changed && problem ? t(`timehost.hostnameProblem.${problem}`) : undefined}
          >
            {(p) => (
              <input
                {...p}
                className="input font-mono"
                value={d.hostname}
                autoComplete="off"
                spellCheck={false}
                maxLength={63}
                onChange={(e) => set({ hostname: e.target.value })}
              />
            )}
          </Field>
          <Field label={t("timehost.prettyLabel")}>
            {(p) => <input {...p} className="input" value={d.pretty} maxLength={64} onChange={(e) => set({ pretty: e.target.value })} />}
          </Field>
          <label className="flex items-start gap-2">
            <input type="checkbox" className="mt-1" checked={d.hosts} onChange={(e) => set({ hosts: e.target.checked })} />
            <span>{t("timehost.updateHosts")}</span>
          </label>
          {s.cloud_init_resets && <Notice tone="warn">{t("timehost.cloudInit")}</Notice>}
          {s.cloud_init_hosts && d.hosts && <Notice tone="warn">{t("timehost.cloudInitHosts")}</Notice>}
          {plan && d.hosts && (plan.hosts_changed ? <DiffView diff={plan.diff} /> : <Notice tone="info">{t("timehost.hostsUnchanged")}</Notice>)}
          {err && <Notice tone="bad">{err}</Notice>}
          <div className="flex flex-nowrap justify-end gap-2">
            <button
              type="button"
              className="btn btn-secondary min-h-9 shrink-0"
              disabled={!draft || busy}
              onClick={() => (setDraft(undefined), setPlan(undefined))}
            >
              {t("timehost.discard")}
            </button>
            <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!changed || !!problem || busy} onClick={() => void preview()}>
              <Icon name="eye" className="h-4 w-4" />
              {t("timehost.preview")}
            </button>
            <button
              type="button"
              className="btn btn-primary min-h-9 shrink-0"
              disabled={!isAdmin || !changed || !!problem || busy || !plan}
              onClick={() => void save()}
            >
              {t("common.save")}
            </button>
          </div>
          <Explain>
            <p>{t("timehost.hostExplain")}</p>
          </Explain>
        </>
      )}
    </Panel>
  );
}

function PowerPanel({ s, isAdmin, onAsk }: { s?: State; isAdmin: boolean; onAsk: (a: PowerAction) => void }) {
  const { t } = useTranslation();
  const cols: Column<Inhibitor>[] = [
    { key: "who", label: t("timehost.col.who"), sortValue: (i) => i.who, filter: "text", cell: (i) => i.who },
    { key: "what", label: t("timehost.col.what"), sortValue: (i) => i.what, filter: "text", tdClass: "font-mono text-xs", cell: (i) => i.what },
    { key: "why", label: t("timehost.col.why"), sortValue: (i) => i.why, filter: "text", cell: (i) => i.why },
    { key: "mode", label: t("timehost.col.mode"), sortValue: (i) => i.mode, filter: "text", cell: (i) => i.mode },
    { key: "pid", label: "PID", sortValue: (i) => i.pid, filter: "number", tdClass: "font-mono", cell: (i) => i.pid },
  ];
  return (
    <Panel className="flex flex-col gap-4">
      <div className="flex flex-nowrap items-center gap-2 overflow-x-auto">
        <h2 className="min-w-0 flex-1 text-lg font-semibold">{t("timehost.power")}</h2>
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!isAdmin || !s?.host} onClick={() => onAsk("reboot")}>
          <Icon name="restart" className="h-4 w-4" />
          {t("timehost.reboot")}
        </button>
        <button type="button" className="btn btn-danger min-h-9 shrink-0" disabled={!isAdmin || !s?.host} onClick={() => onAsk("poweroff")}>
          <Icon name="stop" className="h-4 w-4" />
          {t("timehost.poweroff")}
        </button>
      </div>
      <p className="text-muted">{t("timehost.powerIntro")}</p>
      <h3 className="font-medium">{t("timehost.inhibitors")}</h3>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("timehost.inhibitors")}
          columns={cols}
          rows={s?.inhibitors}
          rowKey={(i) => `${i.pid}-${i.what}-${i.who}`}
          empty={t("timehost.noInhibitors")}
        />
      </div>
    </Panel>
  );
}

function PowerModal({
  action,
  host,
  inhibitors,
  onClose,
  onDone,
}: {
  action: PowerAction;
  host: HostState | null;
  inhibitors: Inhibitor[];
  onClose: () => void;
  onDone: (r: PowerResult) => void;
}) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [delay, setDelay] = useState(0);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const name = confirmName(host);
  const blocking = inhibitors.filter((i) => i.mode === "block" && i.what.split(":").includes("shutdown"));
  const go = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      onDone(await withStepUp(() => api<PowerResult>("POST", "/power/schedule", { action, delay_min: delay, confirm: typed.trim() })));
    } catch (e) {
      setErr(e instanceof ApiError && e.code === "confirm_mismatch" ? t("timehost.err.confirm_mismatch") : errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={t(`timehost.${action}Title`)} onClose={onClose}>
      <div className="flex flex-col gap-4">
        <p>{t(`timehost.${action}Explain`)}</p>
        {action === "poweroff" && <Notice tone="warn">{t("timehost.poweroffWarn")}</Notice>}
        {blocking.length > 0 && <Notice tone="warn">{t("timehost.blocked", { who: blocking.map((i) => `${i.who} (${i.why})`).join(", ") })}</Notice>}
        <Field label={t("timehost.when")}>
          {(p) => (
            <select {...p} className="input" value={delay} onChange={(e) => setDelay(Number(e.target.value))}>
              {delays.map((m) => (
                <option key={m} value={m}>
                  {m === 0 ? t("timehost.now") : t("timehost.inMinutes", { count: m })}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label={t("timehost.typeName", { name })}>
          {(p) => <input {...p} className="input font-mono" value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} />}
        </Field>
        {err && <Notice tone="bad">{err}</Notice>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn btn-danger" disabled={busy || !name || typed.trim() !== name} onClick={() => void go()}>
            {t(delay === 0 ? `timehost.${action}Now` : `timehost.${action}Later`)}
          </button>
        </div>
      </div>
    </Modal>
  );
}

const reconnectLimit = { reboot: 10 * 60_000, poweroff: 24 * 3600_000 };

/** Full-screen overlay after a reboot or power-off: polls until the boot id changes. */
function Reconnect({ action, bootId, onBack }: { action: PowerAction; bootId: string; onBack: () => void }) {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>("waiting");
  const [start] = useState(() => Date.now());
  const now = useNow(phase !== "back");
  const back = useRef(onBack);
  useEffect(() => {
    back.current = onBack;
  }, [onBack]);
  useEffect(() => {
    let stop = false;
    let cur: Phase = "waiting";
    const tick = async () => {
      let poll: { ok: true; bootId: string } | { ok: false };
      try {
        const s = await api<State>("GET", "/timehost");
        poll = { ok: true, bootId: s.boot_id };
      } catch (e) {
        // Logged out (sessions end with the reboot): the login page takes over.
        if (e instanceof ApiError && e.status === 401) return;
        poll = { ok: false };
      }
      if (stop) return;
      cur = nextPhase(cur, bootId, poll, Date.now() - start, reconnectLimit[action]);
      setPhase(cur);
      if (cur === "back") {
        setTimeout(() => back.current(), 1500);
        return;
      }
      setTimeout(() => void tick(), 3000);
    };
    const id = setTimeout(() => void tick(), 3000);
    return () => {
      stop = true;
      clearTimeout(id);
    };
  }, [action, bootId, start]);
  const secs = Math.floor((now - start) / 1000);
  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="reconnect-title"
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4"
    >
      <div className="panel panel-edge flex w-[min(94vw,520px)] flex-col gap-4 p-6">
        <h2 id="reconnect-title" className="text-lg font-semibold">
          {t(`timehost.reconnect.title.${action}`)}
        </h2>
        <p role="status" aria-live="polite">
          {phase === "back" ? `✓ ${t("timehost.reconnect.back")}` : t(`timehost.reconnect.${phase}.${action}`)}
        </p>
        {phase !== "back" && (
          <p className="text-muted">
            {t("timehost.reconnect.elapsed")} <span className="font-mono tabular-nums">{countdown(secs)}</span>
          </p>
        )}
        {phase === "timeout" && <Notice tone="warn">{t(`timehost.reconnect.timeoutHint.${action}`)}</Notice>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={() => window.location.reload()}>
            {t("timehost.reconnect.reload")}
          </button>
        </div>
      </div>
    </div>
  );
}
