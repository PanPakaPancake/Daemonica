import { useQuery } from "@tanstack/react-query";
import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "../components/icons";
import { Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { useFollow, followEndText } from "../lib/follow";
import { saveText } from "../lib/format";

interface Entry {
  time: string;
  priority: number;
  unit?: string;
  identifier?: string;
  pid?: number;
  message: string;
}
interface Result {
  entries: Entry[];
  cursor?: string;
  truncated: boolean;
}
interface Filter {
  unit: string;
  priority: string;
  boot: string;
  grep: string;
  since: string;
  lines: number;
}

const prioLabel = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
const prioClass = (p: number) => (p <= 3 ? "text-bad" : p === 4 ? "text-warn" : p === 5 ? "text-info" : "");
const MAX_BUFFER = 5000;

export function Logs() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const [draft, setDraft] = useState<Filter>({ unit: "", priority: "", boot: "0", grep: "", since: "", lines: 500 });
  const [filter, setFilter] = useState<Filter>(draft);
  const [follow, setFollow] = useState(false);
  const [extra, setExtra] = useState<Entry[]>([]);
  const [err, setErr] = useState<string>();
  const [skipped, setSkipped] = useState(0);
  const bottom = useRef<HTMLDivElement>(null);

  // Filter fields shared by the initial query and follow polling.
  const where = (f: Filter) => ({
    ...(f.unit && { unit: f.unit.includes(".") ? f.unit : `${f.unit}.service` }),
    ...(f.priority && { priority: Number(f.priority) }),
    ...(f.boot && { boot: f.boot }),
    ...(f.grep && { grep: f.grep }),
    ...(f.since && { since: new Date(f.since).toISOString() }),
  });

  const q = useQuery({
    queryKey: ["journal", filter],
    queryFn: async () => {
      const r = await api<Result>("POST", "/journal/query", { ...where(filter), lines: filter.lines });
      setExtra([]);
      setSkipped(0);
      return r;
    },
  });

  // Follow: the server pushes entries after the last cursor over WebSocket (DEC-017, DEC-026).
  const followParams = useMemo(
    () => (follow && q.data?.cursor ? { ...where(filter), after: q.data.cursor } : undefined),
    [follow, filter, q.data?.cursor],
  );
  useFollow<Entry>(
    "journal.query",
    followParams,
    (es, sk) => {
      setExtra((x) => [...x, ...es].slice(-MAX_BUFFER));
      if (sk) setSkipped((n) => n + sk);
      window.requestAnimationFrame(() => bottom.current?.scrollIntoView({ block: "end" }));
    },
    (reason) => {
      setErr(followEndText(t, reason));
      setFollow(false);
    },
  );

  const entries = [...(q.data?.entries ?? []), ...extra];
  const fmtTime = (s: string) => new Date(s).toLocaleString(lang);

  const exportAs = (kind: "txt" | "json") => {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    if (kind === "json") {
      saveText(`journal-${stamp}.json`, JSON.stringify(entries, null, 2), "application/json");
    } else {
      saveText(
        `journal-${stamp}.txt`,
        entries.map((e) => `${e.time} ${prioLabel[e.priority] ?? e.priority} ${e.identifier ?? ""}[${e.pid ?? ""}]: ${e.message}`).join("\n"),
      );
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("logs.title")}</h1>
        <p className="mt-1 text-muted">{t("logs.intro")}</p>
      </div>
      <Panel>
        <form
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6"
          onSubmit={(e) => {
            e.preventDefault();
            setErr(undefined);
            setFilter({ ...draft });
          }}
        >
          <label className="flex flex-col gap-1 lg:col-span-2">
            <span className="text-sm font-medium">{t("logs.unit")}</span>
            <input
              className="input font-mono"
              value={draft.unit}
              onChange={(e) => setDraft({ ...draft, unit: e.target.value.trim() })}
              placeholder="ssh.service"
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium">{t("logs.priority")}</span>
            <select className="input" value={draft.priority} onChange={(e) => setDraft({ ...draft, priority: e.target.value })}>
              <option value="">{t("services.all")}</option>
              {prioLabel.map((p, i) => (
                <option key={p} value={i}>
                  ≤ {p}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium">{t("logs.boot")}</span>
            <select className="input" value={draft.boot} onChange={(e) => setDraft({ ...draft, boot: e.target.value })}>
              <option value="0">{t("logs.currentBoot")}</option>
              <option value="-1">{t("logs.previousBoot")}</option>
              <option value="">{t("services.all")}</option>
            </select>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium">{t("logs.since")}</span>
            <input type="datetime-local" className="input" value={draft.since} onChange={(e) => setDraft({ ...draft, since: e.target.value })} />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium">{t("logs.lines")}</span>
            <select className="input" value={draft.lines} onChange={(e) => setDraft({ ...draft, lines: Number(e.target.value) })}>
              {[100, 500, 1000, 2000, 5000].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 sm:col-span-2 lg:col-span-4">
            <span className="text-sm font-medium">{t("logs.search")}</span>
            <input className="input" value={draft.grep} onChange={(e) => setDraft({ ...draft, grep: e.target.value })} maxLength={200} />
          </label>
          <div className="flex items-end gap-2 sm:col-span-2">
            <button className="btn btn-primary flex-1">
              <Icon name="search" className="h-4 w-4" />
              {t("logs.apply")}
            </button>
          </div>
        </form>
      </Panel>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          <span>{t("logs.follow")}</span>
          {follow && <span className="h-2 w-2 animate-pulse rounded-full bg-ok" aria-hidden="true" />}
          {skipped > 0 && <span className="text-sm text-warn">{t("common.skipped", { count: skipped })}</span>}
        </label>
        <div className="flex gap-2">
          <button type="button" className="btn btn-secondary min-h-9" onClick={() => exportAs("txt")} disabled={!entries.length}>
            <Icon name="download" className="h-4 w-4" /> TXT
          </button>
          <button type="button" className="btn btn-secondary min-h-9" onClick={() => exportAs("json")} disabled={!entries.length}>
            <Icon name="download" className="h-4 w-4" /> JSON
          </button>
        </div>
      </div>

      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {q.data?.truncated && <Notice tone="info">{t("logs.truncated")}</Notice>}

      <Panel className="p-0">
        <div className="max-h-[65vh] overflow-auto p-3 font-mono text-xs leading-relaxed" role="log" aria-live={follow ? "polite" : "off"}>
          {q.isLoading && <p className="p-2 text-muted">{t("common.loading")}</p>}
          {!q.isLoading && entries.length === 0 && <p className="p-2 text-muted">{t("logs.empty")}</p>}
          {entries.map((e, i) => (
            <div key={i} className={`flex gap-3 whitespace-pre-wrap break-words px-1 hover:bg-bg-2 ${prioClass(e.priority)}`}>
              <span className="shrink-0 text-faint tabular-nums">{fmtTime(e.time)}</span>
              <span className="w-14 shrink-0 text-faint">{prioLabel[e.priority]}</span>
              <span className="min-w-0">
                {e.identifier && (
                  <span className="text-violet">
                    {e.identifier}
                    {e.pid ? `[${e.pid}]` : ""}:{" "}
                  </span>
                )}
                {e.message}
              </span>
            </div>
          ))}
          <div ref={bottom} />
        </div>
      </Panel>
    </div>
  );
}
