import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";

interface SessionInfo {
  id: string;
  account_name?: string;
  role: string;
  linux_user: string;
  created: string;
  last_used: string;
  source_ip?: string;
  step_up: boolean;
  current: boolean;
}

export function Sessions() {
  const { t, i18n } = useTranslation();
  const { me, logout } = useSession();
  const qc = useQueryClient();
  const [all, setAll] = useState(false);
  const [err, setErr] = useState<string>();
  const q = useQuery({
    queryKey: ["sessions", all],
    queryFn: () => api<SessionInfo[]>("POST", "/sessions/list", all ? { all: true } : undefined),
    refetchInterval: 30_000,
  });
  const fmt = (s: string) => new Date(s).toLocaleString(i18n.language);

  const revoke = async (s: SessionInfo) => {
    if (!window.confirm(t("sessions.confirmEnd"))) return;
    setErr(undefined);
    try {
      if (s.current) {
        await logout();
        return;
      }
      await api("DELETE", `/sessions/${encodeURIComponent(s.id)}`);
      await qc.invalidateQueries({ queryKey: ["sessions"] });
    } catch (e) {
      setErr(errorText(t, e));
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("sessions.title")}</h1>
        <p className="mt-1 text-muted">{t("sessions.intro")}</p>
      </div>
      {me?.role === "admin" && (
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
          <span>{t("sessions.showAll")}</span>
        </label>
      )}
      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      <Panel>
        {q.isLoading ? (
          <p className="text-muted">{t("common.loading")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-faint">
                <tr>
                  {all && <th className="py-2 pr-4 font-medium">{t("sessions.account")}</th>}
                  <th className="py-2 pr-4 font-medium">{t("sessions.ip")}</th>
                  <th className="py-2 pr-4 font-medium">{t("sessions.created")}</th>
                  <th className="py-2 pr-4 font-medium">{t("sessions.lastUsed")}</th>
                  <th className="py-2 pr-4 font-medium">{t("sessions.state")}</th>
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((s) => (
                  <tr key={s.id} className="border-t border-line">
                    {all && (
                      <td className="py-2 pr-4">
                        {s.account_name} <span className="text-faint">({s.linux_user})</span>
                      </td>
                    )}
                    <td className="py-2 pr-4 font-mono">{s.source_ip || "—"}</td>
                    <td className="py-2 pr-4">{fmt(s.created)}</td>
                    <td className="py-2 pr-4">{fmt(s.last_used)}</td>
                    <td className="py-2 pr-4">
                      {s.current && (
                        <span className="mr-2 rounded-full border border-cyan px-2 py-0.5 text-xs text-cyan">{t("sessions.current")}</span>
                      )}
                      {s.step_up && <span className="rounded-full border border-line-strong px-2 py-0.5 text-xs">{t("header.stepUpActive")}</span>}
                    </td>
                    <td className="py-2 text-right">
                      <button type="button" className="btn btn-secondary min-h-9" onClick={() => void revoke(s)}>
                        {t("sessions.end")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
