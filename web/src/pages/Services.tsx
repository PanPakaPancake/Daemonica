import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { Icon } from "../components/icons";
import { Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, relative } from "../lib/format";
import { useSession } from "../lib/session";
import { DataTable } from "../components/DataTable";

interface Unit {
  name: string;
  type: "service" | "timer" | "socket";
  description: string;
  load: string;
  active: string;
  sub: string;
  file_state: string;
  since?: string;
  memory?: number;
  protected: boolean;
}
interface Detail extends Unit {
  fragment_path?: string;
  main_pid?: number;
  requires?: string[];
  wants?: string[];
  after?: string[];
  wanted_by?: string[];
  triggered_by?: string[];
  triggers?: string[];
  unit_file?: string;
}
interface JournalEntry {
  time: string;
  priority: number;
  identifier?: string;
  pid?: number;
  message: string;
}

type Action = "start" | "stop" | "restart" | "reload" | "enable" | "disable" | "mask" | "unmask";

const activeTone: Record<string, string> = { active: "text-ok", failed: "text-bad", activating: "text-warn", deactivating: "text-warn" };
const activeIcon: Record<string, string> = { active: "●", failed: "✖", activating: "◐", deactivating: "◑" };

export function Services() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const qc = useQueryClient();
  const { me, withStepUp } = useSession();
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [type, setType] = useState<string>("service");
  const state = params.get("state") ?? "";
  const [selected, setSelected] = useState<string>();
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState<string>();
  const [confirmSelf, setConfirmSelf] = useState<{ unit: string; action: Action }>();
  const [typed, setTyped] = useState("");

  const q = useQuery({ queryKey: ["services"], queryFn: () => api<Unit[]>("GET", "/services"), refetchInterval: 10_000 });
  const canControl = me?.role === "admin" || me?.role === "operator";
  const isAdmin = me?.role === "admin";

  const rows = useMemo(() => {
    const s = search.trim().toLowerCase();
    return (q.data ?? []).filter(
      (u) =>
        (!type || u.type === type) &&
        (!state || u.active === state || (state === "running" && u.sub === "running")) &&
        (!s || u.name.toLowerCase().includes(s) || u.description.toLowerCase().includes(s)),
    );
  }, [q.data, search, type, state]);

  const counts = useMemo(() => {
    const c = { total: 0, active: 0, failed: 0 };
    for (const u of q.data ?? []) {
      if (type && u.type !== type) continue;
      c.total++;
      if (u.active === "active") c.active++;
      if (u.active === "failed") c.failed++;
    }
    return c;
  }, [q.data, type]);

  const run = async (unit: string, action: Action, confirm = false) => {
    setErr(undefined);
    setBusy(`${unit}:${action}`);
    try {
      await withStepUp(() => api("POST", "/services/action", { unit, action, ...(confirm && { confirm: true }) }));
      await qc.invalidateQueries({ queryKey: ["services"] });
      await qc.invalidateQueries({ queryKey: ["service", unit] });
    } catch (e) {
      setErr(`${unit}: ${errorText(t, e)}`);
    } finally {
      setBusy(undefined);
    }
  };

  const isRunning = (u: Unit) => u.active === "active" || u.active === "activating";

  const request = (u: Unit, action: Action) => {
    const destructive = action === "stop" || action === "disable" || action === "mask";
    if (u.name.startsWith("daemonica-web") && destructive) {
      setTyped("");
      setConfirmSelf({ unit: u.name, action });
      return;
    }
    if (u.protected && !window.confirm(t("services.protectedWarning", { unit: u.name }))) return;
    void run(u.name, action);
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("services.title")}</h1>
        <p className="mt-1 text-muted">{t("services.intro")}</p>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <label className="flex min-w-56 flex-1 flex-col gap-1">
          <span className="text-sm font-medium">{t("services.search")}</span>
          <input className="input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="nginx, ssh …" />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-sm font-medium">{t("services.type")}</span>
          <select className="input header-select" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="service">{t("services.types.service")}</option>
            <option value="timer">{t("services.types.timer")}</option>
            <option value="socket">{t("services.types.socket")}</option>
            <option value="">{t("services.all")}</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-sm font-medium">{t("services.state")}</span>
          <select className="input header-select" value={state} onChange={(e) => setParams(e.target.value ? { state: e.target.value } : {}, { replace: true })}>
            <option value="">{t("services.all")}</option>
            <option value="running">{t("services.running")}</option>
            <option value="active">active</option>
            <option value="inactive">inactive</option>
            <option value="failed">failed</option>
          </select>
        </label>
        <p className="pb-2 text-sm text-muted">
          {t("services.counts", { total: counts.total, active: counts.active })}
          {counts.failed > 0 && <span className="text-bad"> · {t("services.failedCount", { count: counts.failed })}</span>}
        </p>
      </div>

      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}

      <Panel className="p-0">
        <div className="relative overflow-x-auto">
          <DataTable
            rows={q.data ? rows : undefined}
            rowKey={(u) => u.name}
            loading={q.isLoading}
            empty={t("services.empty")}
            label={t("services.title")}
            defaultSort={{ key: "unit", desc: false }}
            rowMenu={(u) => ({
              label: u.name,
              items: [
                { label: t("services.details"), icon: "info", onSelect: () => setSelected(u.name) },
                ...(canControl
                  ? [
                      isRunning(u)
                        ? { label: t("services.stop"), icon: "stop" as const, onSelect: () => request(u, "stop") }
                        : { label: t("services.start"), icon: "play" as const, onSelect: () => request(u, "start") },
                      { label: t("services.restart"), icon: "restart" as const, onSelect: () => request(u, "restart") },
                    ]
                  : []),
              ],
            })}
            columns={[
              {
                key: "unit",
                label: t("services.unit"),
                tdClass: "min-w-[14rem] max-w-[26rem]",
                sortValue: (u) => u.name,
                filterValue: (u) => `${u.name} ${u.description}`,
                filter: "text",
                cell: (u) => (
                  <>
                    <button type="button" className="block max-w-full truncate text-left font-mono text-fg hover:underline" onClick={() => setSelected(u.name)}>
                      {u.name}
                    </button>
                    <span className="block truncate text-xs text-muted" title={u.description}>
                      {u.protected && (
                        <span className="mr-1 inline-flex items-center gap-0.5 text-warn">
                          <Icon name="shield" className="h-3 w-3" />
                          {t("services.protected")} ·
                        </span>
                      )}
                      {u.description}
                    </span>
                  </>
                ),
              },
              {
                key: "state",
                label: t("services.state"),
                tdClass: "whitespace-nowrap",
                sortValue: (u) => u.active,
                filter: { options: ["active", "activating", "deactivating", "inactive", "failed"].map((s) => ({ value: s, label: s })) },
                cell: (u) => (
                  <>
                    <span className={activeTone[u.active] ?? "text-faint"} aria-hidden="true">
                      {activeIcon[u.active] ?? "○"}{" "}
                    </span>
                    {u.active}
                    <span className="text-faint"> ({u.sub})</span>
                  </>
                ),
              },
              {
                key: "enabled",
                label: t("services.enabled"),
                thClass: "hidden md:table-cell",
                tdClass: "hidden md:table-cell",
                sortValue: (u) => u.file_state,
                filter: { options: [...new Set((q.data ?? []).map((x) => x.file_state).filter(Boolean))].sort().map((s) => ({ value: s, label: s })) },
                cell: (u) => <>{u.file_state || "–"}</>,
              },
              {
                key: "since",
                label: t("services.since"),
                thClass: "hidden lg:table-cell",
                tdClass: "hidden whitespace-nowrap lg:table-cell",
                sortValue: (u) => (isRunning(u) ? u.since : undefined),
                tdTitle: (u) => dateTime(u.since, lang),
                cell: (u) => <>{isRunning(u) ? relative(u.since, lang) : "–"}</>,
              },
              {
                key: "mem",
                label: "RAM",
                thClass: "hidden text-right lg:table-cell",
                tdClass: "hidden text-right tabular-nums lg:table-cell",
                sortValue: (u) => u.memory || undefined,
                cell: (u) => <>{u.memory ? bytes(u.memory, lang) : "–"}</>,
              },
              {
                key: "actions",
                label: t("services.actions"),
                thClass: "text-right",
                cell: (u) => (
                  <>
                    {canControl && (
                      <div className="flex justify-end gap-1">
                        {!isRunning(u) ? (
                          <IconButton icon="play" label={t("services.start")} busy={busy === `${u.name}:start`} onClick={() => request(u, "start")} />
                        ) : (
                          <IconButton icon="stop" label={t("services.stop")} busy={busy === `${u.name}:stop`} onClick={() => request(u, "stop")} />
                        )}
                        <IconButton icon="restart" label={t("services.restart")} busy={busy === `${u.name}:restart`} onClick={() => request(u, "restart")} />
                      </div>
                    )}
                  </>
                ),
              },
            ]}
          />
        </div>
      </Panel>

      {selected && (
        <UnitDetail
          name={selected}
          onClose={() => setSelected(undefined)}
          canControl={canControl}
          isAdmin={isAdmin}
          canLogs={canControl}
          onAction={(a) => {
            const u = (q.data ?? []).find((x) => x.name === selected);
            if (u) request(u, a);
          }}
          busy={busy}
        />
      )}

      <Dialog.Root open={!!confirmSelf} onOpenChange={(o) => !o && setConfirmSelf(undefined)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
          <Dialog.Content className="panel panel-edge fixed left-1/2 top-1/2 z-50 w-[min(92vw,480px)] -translate-x-1/2 -translate-y-1/2 p-6">
            <Dialog.Title className="text-lg font-semibold">{t("services.selfTitle")}</Dialog.Title>
            <Dialog.Description className="mt-2 text-muted">{t("services.selfText")}</Dialog.Description>
            <label className="mt-4 flex flex-col gap-1">
              <span className="text-sm font-medium">{t("services.typeToConfirm", { name: confirmSelf?.unit })}</span>
              <input className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
            </label>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" className="btn btn-secondary" onClick={() => setConfirmSelf(undefined)}>
                {t("common.cancel")}
              </button>
              <button
                type="button"
                className="btn btn-danger"
                disabled={typed !== confirmSelf?.unit}
                onClick={() => {
                  const c = confirmSelf;
                  setConfirmSelf(undefined);
                  if (c) void run(c.unit, c.action, true);
                }}
              >
                {t(`services.${confirmSelf?.action ?? "stop"}`)}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}

function IconButton({ icon, label, onClick, busy }: { icon: "play" | "stop" | "restart"; label: string; onClick: () => void; busy?: boolean }) {
  return (
    <button type="button" className="btn btn-secondary min-h-8 px-2" onClick={onClick} disabled={busy} aria-label={label} title={label}>
      <Icon name={icon} className={`h-4 w-4 ${busy ? "animate-pulse" : ""}`} />
    </button>
  );
}

function UnitDetail({
  name,
  onClose,
  canControl,
  isAdmin,
  canLogs,
  onAction,
  busy,
}: {
  name: string;
  onClose: () => void;
  canControl: boolean;
  isAdmin: boolean;
  canLogs: boolean;
  onAction: (a: Action) => void;
  busy?: string;
}) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const [tab, setTab] = useState<"status" | "journal" | "file" | "deps">("status");
  const d = useQuery({ queryKey: ["service", name], queryFn: () => api<Detail>("POST", "/services/get", { unit: name }) });
  const j = useQuery({
    queryKey: ["service-journal", name],
    queryFn: () => api<{ entries: JournalEntry[] }>("POST", "/journal/query", { unit: name, lines: 100 }),
    enabled: canLogs && tab === "journal",
    refetchInterval: tab === "journal" ? 5000 : false,
  });
  const u = d.data;
  const actions: Action[] = ["start", "stop", "restart", "reload"];
  const fileActions: Action[] = ["enable", "disable", "mask", "unmask"];

  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60" />
        <Dialog.Content className="panel fixed inset-y-0 right-0 z-40 flex w-[min(100vw,760px)] flex-col overflow-hidden rounded-none border-l border-line">
          <div className="flex items-start justify-between gap-3 border-b border-line p-5">
            <div className="min-w-0">
              <Dialog.Title className="truncate font-mono text-lg font-semibold">{name}</Dialog.Title>
              <Dialog.Description className="truncate text-sm text-muted">{u?.description ?? t("common.loading")}</Dialog.Description>
            </div>
            <Dialog.Close className="btn btn-secondary min-h-9 px-2.5" aria-label={t("common.close")}>
              <Icon name="close" />
            </Dialog.Close>
          </div>
          {u?.protected && (
            <div className="px-5 pt-4">
              <Notice tone="warn">{t("services.protectedHint")}</Notice>
            </div>
          )}
          {canControl && (
            <div className="flex flex-wrap gap-2 px-5 pt-4">
              {actions.map((a) => (
                <button key={a} type="button" className="btn btn-secondary min-h-9" disabled={busy === `${name}:${a}`} onClick={() => onAction(a)}>
                  {t(`services.${a}`)}
                </button>
              ))}
              {isAdmin &&
                fileActions.map((a) => (
                  <button
                    key={a}
                    type="button"
                    className={`btn min-h-9 ${a === "mask" || a === "disable" ? "btn-danger" : "btn-secondary"}`}
                    disabled={busy === `${name}:${a}`}
                    onClick={() => onAction(a)}
                  >
                    {t(`services.${a}`)}
                  </button>
                ))}
            </div>
          )}
          <div role="tablist" className="mt-4 flex gap-1 border-b border-line px-5">
            {(["status", "journal", "file", "deps"] as const)
              .filter((x) => x !== "journal" || canLogs)
              .map((x) => (
                <button
                  key={x}
                  role="tab"
                  type="button"
                  aria-selected={tab === x}
                  className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
                  onClick={() => setTab(x)}
                >
                  {t(`services.tab.${x}`)}
                </button>
              ))}
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-5 text-sm">
            {d.isError && <Notice tone="bad">{errorText(t, d.error)}</Notice>}
            {u && tab === "status" && (
              <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2">
                <dt className="text-muted">{t("services.state")}</dt>
                <dd>
                  {u.active} ({u.sub})
                </dd>
                <dt className="text-muted">{t("services.enabled")}</dt>
                <dd>{u.file_state || "–"}</dd>
                <dt className="text-muted">{t("services.load")}</dt>
                <dd>{u.load}</dd>
                <dt className="text-muted">{t("services.since")}</dt>
                <dd>{dateTime(u.since, lang)}</dd>
                {u.main_pid ? (
                  <>
                    <dt className="text-muted">Main PID</dt>
                    <dd className="tabular-nums">{u.main_pid}</dd>
                  </>
                ) : null}
                {u.memory ? (
                  <>
                    <dt className="text-muted">RAM</dt>
                    <dd>{bytes(u.memory, lang)}</dd>
                  </>
                ) : null}
                <dt className="text-muted">{t("services.file")}</dt>
                <dd className="break-all font-mono">{u.fragment_path || "–"}</dd>
              </dl>
            )}
            {tab === "journal" && (
              <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed">
                {(j.data?.entries ?? []).map((e, i) => (
                  <span key={i} className={e.priority <= 3 ? "text-bad" : e.priority === 4 ? "text-warn" : ""}>
                    <span className="text-faint">{new Date(e.time).toLocaleString(lang)} </span>
                    {e.identifier && <span className="text-violet">{e.identifier}: </span>}
                    {e.message}
                    {"\n"}
                  </span>
                ))}
                {j.isLoading && t("common.loading")}
                {j.data && j.data.entries.length === 0 && t("logs.empty")}
              </pre>
            )}
            {u && tab === "file" && (
              <pre className="overflow-x-auto rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-xs leading-relaxed">
                {u.unit_file || t("services.noFile")}
              </pre>
            )}
            {u && tab === "deps" && (
              <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3">
                {(["requires", "wants", "after", "wanted_by", "triggered_by", "triggers"] as const).map((k) =>
                  u[k] && u[k].length > 0 ? (
                    <div key={k} className="contents">
                      <dt className="text-muted">{k.replace("_", " ")}</dt>
                      <dd className="break-all font-mono">{u[k].join(", ")}</dd>
                    </div>
                  ) : null,
                )}
              </dl>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
