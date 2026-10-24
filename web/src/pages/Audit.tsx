import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "../components/icons";
import { Field, Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";

interface AuditEvent {
  ts: string;
  event_id: string;
  actor: { account_id?: string; name?: string; role?: string; linux_user?: string };
  source_ip?: string;
  action: string;
  target?: string;
  params?: Record<string, string>;
  step_up: boolean;
  result: "ok" | "denied" | "error";
  reason?: string;
}
interface AuditPage {
  events: AuditEvent[];
  next?: string;
}
interface VerifyResult {
  records: number;
  ok: boolean;
  bad_line?: number;
  problem?: string;
}
interface Filter {
  action: string;
  result: string;
  text: string;
}

const resultClass = { ok: "text-ok", denied: "text-warn", error: "text-bad" } as const;

export function Audit() {
  const { t, i18n } = useTranslation();
  const [draft, setDraft] = useState<Filter>({ action: "", result: "", text: "" });
  const [filter, setFilter] = useState<Filter>(draft);
  const [verifying, setVerifying] = useState(false);
  const [verify, setVerify] = useState<VerifyResult>();
  const [err, setErr] = useState<string>();

  const accounts = useQuery({ queryKey: ["accounts"], queryFn: () => api<{ id: string; name: string }[]>("GET", "/accounts") });
  const names = new Map((accounts.data ?? []).map((a) => [a.id, a.name]));

  const q = useInfiniteQuery({
    queryKey: ["audit", filter],
    initialPageParam: "",
    queryFn: ({ pageParam }) =>
      api<AuditPage>("POST", "/audit/query", {
        ...(filter.action && { action: filter.action }),
        ...(filter.result && { result: filter.result }),
        ...(filter.text && { text: filter.text }),
        ...(pageParam && { before: pageParam }),
        limit: 100,
      }),
    getNextPageParam: (p) => p.next || undefined,
  });
  const events = q.data?.pages.flatMap((p) => p.events) ?? [];

  const runVerify = async () => {
    setVerifying(true);
    setErr(undefined);
    try {
      setVerify(await api<VerifyResult>("POST", "/audit/verify"));
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setVerifying(false);
    }
  };

  // Export the loaded, filtered events as JSON Lines (client-side, no extra endpoint).
  const exportJSONL = () => {
    const blob = new Blob([events.map((e) => JSON.stringify(e)).join("\n") + "\n"], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `daemonica-audit-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const actor = (e: AuditEvent) => {
    if (e.actor.name) return e.actor.name;
    if (e.actor.account_id) return names.get(e.actor.account_id) ?? e.actor.account_id;
    return "—";
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("audit.title")}</h1>
        <p className="mt-1 text-muted">{t("audit.intro")}</p>
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {verify && (
        <Notice tone={verify.ok ? "ok" : "bad"} live>
          {verify.ok
            ? t("audit.chainOk", { count: verify.records })
            : t("audit.chainBad", { line: verify.bad_line ?? 0, problem: verify.problem ?? "" })}
        </Notice>
      )}

      <Panel>
        <form
          className="grid gap-4 md:grid-cols-[1fr_auto_1fr_auto] md:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            setFilter(draft);
          }}
        >
          <Field label={t("audit.action")} help={t("audit.actionHelp")}>
            {(p) => <input {...p} className="input font-mono" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value.trim() })} maxLength={64} />}
          </Field>
          <Field label={t("audit.result")}>
            {(p) => (
              <select {...p} className="input" value={draft.result} onChange={(e) => setDraft({ ...draft, result: e.target.value })}>
                <option value="">{t("audit.any")}</option>
                <option value="ok">{t("audit.results.ok")}</option>
                <option value="denied">{t("audit.results.denied")}</option>
                <option value="error">{t("audit.results.error")}</option>
              </select>
            )}
          </Field>
          <Field label={t("audit.text")}>
            {(p) => <input {...p} className="input" value={draft.text} onChange={(e) => setDraft({ ...draft, text: e.target.value })} maxLength={64} />}
          </Field>
          <button className="btn btn-primary">{t("audit.apply")}</button>
        </form>
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" className="btn btn-secondary" onClick={() => void runVerify()} disabled={verifying}>
            <Icon name="shield" />
            {verifying ? t("common.loading") : t("audit.verify")}
          </button>
          <button type="button" className="btn btn-secondary" onClick={exportJSONL} disabled={events.length === 0}>
            <Icon name="logs" />
            {t("audit.export", { count: events.length })}
          </button>
        </div>
      </Panel>

      <Panel>
        {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
        {q.isLoading ? (
          <p className="text-muted">{t("common.loading")}</p>
        ) : events.length === 0 ? (
          <p className="text-muted">{t("audit.empty")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-faint">
                <tr>
                  <th className="py-2 pr-4 font-medium">{t("audit.time")}</th>
                  <th className="py-2 pr-4 font-medium">{t("audit.actor")}</th>
                  <th className="py-2 pr-4 font-medium">{t("audit.action")}</th>
                  <th className="py-2 pr-4 font-medium">{t("audit.target")}</th>
                  <th className="py-2 pr-4 font-medium">{t("audit.result")}</th>
                  <th className="py-2 font-medium">{t("audit.source")}</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id} className="border-t border-line align-top">
                    <td className="whitespace-nowrap py-2 pr-4">{new Date(e.ts).toLocaleString(i18n.language)}</td>
                    <td className="py-2 pr-4">
                      {actor(e)}
                      {e.step_up && <span className="ml-2 text-xs text-cyan">{t("header.stepUpActive")}</span>}
                    </td>
                    <td className="py-2 pr-4 font-mono">{e.action}</td>
                    <td className="max-w-xs break-all py-2 pr-4 font-mono text-muted">{e.target ?? ""}</td>
                    <td className={`py-2 pr-4 ${resultClass[e.result]}`}>
                      {t(`audit.results.${e.result}`)}
                      {e.reason && <span className="block text-xs text-faint">{e.reason}</span>}
                    </td>
                    <td className="py-2 font-mono text-muted">{e.source_ip ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {q.hasNextPage && (
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
            {t("audit.more")}
          </button>
        )}
      </Panel>
    </div>
  );
}
