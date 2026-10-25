import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "../components/icons";
import { Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, pct } from "../lib/format";
import { useSession } from "../lib/session";
import type { ProcessInfo } from "./Overview";
import { DataTable } from "../components/DataTable";

interface ProcessView extends ProcessInfo {
  protected: boolean;
  mine: boolean;
}
const SIGNALS = ["TERM", "HUP", "STOP", "CONT", "KILL"] as const;

export function Processes() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const qc = useQueryClient();
  const { me } = useSession();
  const [filter, setFilter] = useState("");
  const [onlyMine, setOnlyMine] = useState(false);
  const [target, setTarget] = useState<ProcessView>();
  const [sig, setSig] = useState<(typeof SIGNALS)[number]>("TERM");
  const [err, setErr] = useState<string>();
  const [ok, setOk] = useState<string>();

  const q = useQuery({
    queryKey: ["processes"],
    queryFn: () => api<{ processes: ProcessView[]; truncated: boolean }>("GET", "/processes"),
    refetchInterval: 3000,
  });

  const canSignal = (p: ProcessView) => !p.protected && (me?.role === "admin" || (me?.role === "operator" && p.mine));

  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (q.data?.processes ?? []).filter(
      (p) => (!onlyMine || p.mine) && (!f || p.command.toLowerCase().includes(f) || p.user.toLowerCase().includes(f) || String(p.pid) === f),
    );
  }, [q.data, filter, onlyMine]);

  const send = async () => {
    if (!target) return;
    setErr(undefined);
    setOk(undefined);
    try {
      await api("POST", "/processes/signal", { pid: target.pid, start: target.start, signal: sig });
      setOk(t("processes.sent", { signal: sig, pid: target.pid }));
      setTarget(undefined);
      await qc.invalidateQueries({ queryKey: ["processes"] });
    } catch (e) {
      setErr(errorText(t, e));
      setTarget(undefined);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("processes.title")}</h1>
        <p className="mt-1 text-muted">{t("processes.intro")}</p>
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex min-w-56 flex-1 flex-col gap-1">
          <span className="text-sm font-medium">{t("processes.filter")}</span>
          <input className="input" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 pb-2">
          <input type="checkbox" checked={onlyMine} onChange={(e) => setOnlyMine(e.target.checked)} />
          <span>{t("processes.onlyMine", { user: me?.linux_user })}</span>
        </label>
        <p className="pb-2 text-sm text-muted">{t("processes.count", { count: rows.length })}</p>
      </div>
      {ok && <Notice tone="ok">{ok}</Notice>}
      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {q.data?.truncated && <Notice tone="info">{t("processes.truncated")}</Notice>}

      <Panel className="p-0">
        <div className="max-h-[70vh] overflow-auto">
          <DataTable
            rows={q.data ? rows : undefined}
            rowKey={(p) => String(p.pid)}
            stickyHeader
            loading={q.isLoading}
            label={t("processes.title")}
            defaultSort={{ key: "cpu", desc: true }}
            rowMenu={(p) => ({
              label: t("processes.signal", { pid: p.pid }),
              items: canSignal(p)
                ? [
                    {
                      label: t("processes.signal", { pid: p.pid }),
                      icon: "signal",
                      onSelect: () => {
                        setSig("TERM");
                        setTarget(p);
                      },
                    },
                  ]
                : [],
            })}
            columns={[
              {
                key: "pid",
                label: "PID",
                tdClass: "tabular-nums",
                sortValue: (p) => p.pid,
                filterValue: (p) => String(p.pid),
                filter: "text",
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
                key: "start",
                label: t("processes.started"),
                thClass: "hidden lg:table-cell",
                tdClass: "hidden whitespace-nowrap lg:table-cell",
                sortValue: (p) => p.start,
                cell: (p) => <>{dateTime(p.start, lang)}</>,
              },
              {
                key: "cmd",
                label: t("processes.command"),
                tdClass: "max-w-0 truncate font-mono",
                tdTitle: (p) => p.command,
                sortValue: (p) => p.command,
                filter: "text",
                cell: (p) => (
                  <>
                    {p.protected && <Icon name="shield" className="mr-1 inline h-3.5 w-3.5 text-warn" />}
                    {p.command}
                  </>
                ),
              },
              {
                key: "actions",
                label: t("common.actions"),
                tdClass: "text-right",
                srOnly: true,
                cell: (p) => (
                  <>
                    {canSignal(p) && (
                      <button
                        type="button"
                        className="btn btn-secondary min-h-8 px-2"
                        aria-label={t("processes.signal", { pid: p.pid })}
                        title={t("processes.signal", { pid: p.pid })}
                        onClick={() => {
                          setSig("TERM");
                          setTarget(p);
                        }}
                      >
                        <Icon name="signal" className="h-4 w-4" />
                      </button>
                    )}
                  </>
                ),
              },
            ]}
          />
        </div>
      </Panel>

      <Dialog.Root open={!!target} onOpenChange={(o) => !o && setTarget(undefined)}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
          <Dialog.Content className="panel panel-edge fixed left-1/2 top-1/2 z-50 w-[min(92vw,480px)] -translate-x-1/2 -translate-y-1/2 p-6">
            <Dialog.Title className="text-lg font-semibold">{t("processes.signalTitle", { pid: target?.pid })}</Dialog.Title>
            <Dialog.Description className="mt-2 break-all font-mono text-sm text-muted">{target?.command}</Dialog.Description>
            <fieldset className="mt-4 flex flex-col gap-2">
              <legend className="sr-only">Signal</legend>
              {SIGNALS.map((s) => (
                <label key={s} className="flex items-start gap-2">
                  <input type="radio" name="sig" className="mt-1" checked={sig === s} onChange={() => setSig(s)} />
                  <span>
                    <span className="font-mono font-semibold">SIG{s}</span>
                    <span className="block text-sm text-muted">{t(`processes.sig.${s}`)}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" className="btn btn-secondary" onClick={() => setTarget(undefined)}>
                {t("common.cancel")}
              </button>
              <button type="button" className={`btn ${sig === "KILL" ? "btn-danger" : "btn-primary"}`} onClick={() => void send()}>
                {t("processes.send")}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
