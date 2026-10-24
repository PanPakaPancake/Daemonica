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

interface ProcessView extends ProcessInfo {
  protected: boolean;
  mine: boolean;
}
type SortKey = "pid" | "user" | "cpu" | "rss" | "start" | "command";
const SIGNALS = ["TERM", "HUP", "STOP", "CONT", "KILL"] as const;

export function Processes() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const qc = useQueryClient();
  const { me } = useSession();
  const [filter, setFilter] = useState("");
  const [onlyMine, setOnlyMine] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "cpu", desc: true });
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
    const list = (q.data?.processes ?? []).filter(
      (p) => (!onlyMine || p.mine) && (!f || p.command.toLowerCase().includes(f) || p.user.toLowerCase().includes(f) || String(p.pid) === f),
    );
    const dir = sort.desc ? -1 : 1;
    return list.sort((a, b) => {
      const k = sort.key;
      const av = a[k];
      const bv = b[k];
      return (av < bv ? -1 : av > bv ? 1 : 0) * dir;
    });
  }, [q.data, filter, onlyMine, sort]);

  const header = (key: SortKey, label: string, right = false) => (
    <th className={`px-2 py-2 font-medium ${right ? "text-right" : ""}`} aria-sort={sort.key === key ? (sort.desc ? "descending" : "ascending") : "none"}>
      <button type="button" className="hover:text-fg" onClick={() => setSort((s) => ({ key, desc: s.key === key ? !s.desc : key !== "user" && key !== "command" }))}>
        {label}
        {sort.key === key && <span aria-hidden="true">{sort.desc ? " ↓" : " ↑"}</span>}
      </button>
    </th>
  );

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
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-bg-1 text-faint">
              <tr>
                {header("pid", "PID")}
                {header("user", t("processes.user"))}
                {header("cpu", "CPU", true)}
                {header("rss", "RAM", true)}
                <th className="hidden px-2 py-2 font-medium lg:table-cell">{t("processes.started")}</th>
                {header("command", t("processes.command"))}
                <th className="px-2 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.pid} className="border-t border-line hover:bg-bg-2">
                  <td className="px-2 py-1.5 tabular-nums">{p.pid}</td>
                  <td className="px-2 py-1.5">{p.user}</td>
                  <td className="px-2 py-1.5 text-right tabular-nums">{pct(p.cpu, lang, 1)}</td>
                  <td className="px-2 py-1.5 text-right tabular-nums">{bytes(p.rss, lang)}</td>
                  <td className="hidden whitespace-nowrap px-2 py-1.5 lg:table-cell">{dateTime(p.start, lang)}</td>
                  <td className="max-w-0 truncate px-2 py-1.5 font-mono" title={p.command}>
                    {p.protected && <Icon name="shield" className="mr-1 inline h-3.5 w-3.5 text-warn" />}
                    {p.command}
                  </td>
                  <td className="px-2 py-1.5 text-right">
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
