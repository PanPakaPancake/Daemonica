import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "../components/icons";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";

interface SettingsView {
  domain: string;
  port: number;
  allowlist: string[];
  public: boolean;
  tls_source?: string;
  language: string;
  idle_minutes: number;
  absolute_hours: number;
  upload_limit_mib: number;
  client_ip: string;
  client_allowed: boolean;
}
interface Change {
  id: string;
  summary: string;
  diff: string;
  risk: "low" | "medium" | "high";
  state: "planned" | "applied" | "confirmed" | "rolled_back" | "failed" | "discarded";
  deadline?: string;
}

const loopback = new Set(["127.0.0.0/8", "::1/128"]);

function useCountdown(deadline?: string) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!deadline) return;
    const id = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(id);
  }, [deadline]);
  return deadline ? Math.max(0, Math.ceil((Date.parse(deadline) - now) / 1000)) : 0;
}

export function Settings() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { withStepUp } = useSession();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<SettingsView>("GET", "/settings") });

  const [text, setText] = useState<string>();
  const [change, setChange] = useState<Change>();
  const [needLockout, setNeedLockout] = useState(false);
  const [needPublic, setNeedPublic] = useState(false);
  const [ackLockout, setAckLockout] = useState(false);
  const [ackPublic, setAckPublic] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [done, setDone] = useState<string>();
  const left = useCountdown(change?.state === "applied" ? change.deadline : undefined);

  const s = q.data;
  const current = s ? s.allowlist.filter((x) => !loopback.has(x)).join("\n") : "";
  const value = text ?? current;
  const entries = value
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

  // The change rolled back on the server when the timer ran out.
  useEffect(() => {
    if (change?.state === "applied" && left === 0) {
      setChange({ ...change, state: "rolled_back" });
      setDone(t("settings.rolledBackTimeout"));
      void qc.invalidateQueries({ queryKey: ["settings"] });
    }
  }, [left, change, qc, t]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(undefined);
    setDone(undefined);
    try {
      await fn();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const plan = () =>
    run(async () => {
      try {
        const c = await withStepUp(() =>
          api<Change>("POST", "/settings/allowlist/plan", { allowlist: entries, confirm_lockout: ackLockout, confirm_public: ackPublic }),
        );
        setChange(c);
        setNeedLockout(false);
        setNeedPublic(false);
      } catch (e) {
        if (e instanceof ApiError && e.code === "lockout_protection") {
          setNeedLockout(true);
          return;
        }
        if (e instanceof ApiError && e.code === "validation_failed" && entries.some((x) => x.endsWith("/0"))) {
          setNeedPublic(true);
          return;
        }
        throw e;
      }
    });

  const apply = () =>
    run(async () => {
      if (!change) return;
      const c = await withStepUp(() => api<Change>("POST", `/changes/${encodeURIComponent(change.id)}/apply`));
      setChange(c);
    });

  // Confirmation travels over a NEW connection (the apply response closed the
  // old one), which proves the new allowlist still admits this browser.
  const confirm = () =>
    run(async () => {
      if (!change) return;
      const c = await api<Change>("POST", `/changes/${encodeURIComponent(change.id)}/confirm`);
      setChange(undefined);
      setText(undefined);
      setDone(c.state === "confirmed" ? t("settings.confirmed") : "");
      await qc.invalidateQueries({ queryKey: ["settings"] });
    });

  const rollback = () =>
    run(async () => {
      if (!change) return;
      await api<Change>("POST", `/changes/${encodeURIComponent(change.id)}/rollback`);
      setChange(undefined);
      setDone(t("settings.rolledBack"));
      await qc.invalidateQueries({ queryKey: ["settings"] });
    });

  const discard = () => {
    setChange(undefined);
    setNeedLockout(false);
    setNeedPublic(false);
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("settings.title")}</h1>
        <p className="mt-1 text-muted">{t("settings.intro")}</p>
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {done && (
        <Notice tone="ok" live>
          {done}
        </Notice>
      )}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}

      {s && (
        <Panel>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Icon name="network" />
            {t("settings.access")}
          </h2>
          <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-faint">{t("settings.domain")}</dt>
            <dd className="font-mono">
              {s.domain}:{s.port}
            </dd>
            <dt className="text-faint">{t("settings.yourIp")}</dt>
            <dd className="font-mono">
              {s.client_ip}{" "}
              {s.client_allowed ? <span className="text-ok">({t("settings.allowed")})</span> : <span className="text-bad">({t("settings.notAllowed")})</span>}
            </dd>
            <dt className="text-faint">{t("settings.current")}</dt>
            <dd className="font-mono">{s.allowlist.join(", ")}</dd>
          </dl>
          {s.public && (
            <div className="mt-4">
              <Notice tone="warn">{t("settings.publicWarn")}</Notice>
            </div>
          )}

          {!change && (
            <form
              className="mt-6 flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                void plan();
              }}
            >
              <Field label={t("settings.newList")} help={t("settings.newListHelp")}>
                {(p) => (
                  <textarea
                    {...p}
                    className="input min-h-28 py-2 font-mono"
                    value={value}
                    onChange={(e) => setText(e.target.value)}
                    spellCheck={false}
                    rows={4}
                  />
                )}
              </Field>
              {needLockout && (
                <Notice tone="bad">
                  <label className="flex items-start gap-2">
                    <input type="checkbox" checked={ackLockout} onChange={(e) => setAckLockout(e.target.checked)} />
                    <span>{t("settings.lockoutAck", { ip: s.client_ip })}</span>
                  </label>
                </Notice>
              )}
              {needPublic && (
                <Notice tone="warn">
                  <label className="flex items-start gap-2">
                    <input type="checkbox" checked={ackPublic} onChange={(e) => setAckPublic(e.target.checked)} />
                    <span>{t("settings.publicAck")}</span>
                  </label>
                </Notice>
              )}
              <div>
                <button className="btn btn-primary" disabled={busy || entries.length === 0}>
                  {t("settings.plan")}
                </button>
              </div>
              <Explain>{t("settings.explain")}</Explain>
            </form>
          )}

          {change && (
            <div className="mt-6 flex flex-col gap-4">
              <h3 className="font-semibold">{t("settings.preview")}</h3>
              <pre className="overflow-x-auto rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-sm">
                {change.diff.split("\n").map((l, i) => (
                  <span key={i} className={l.startsWith("+") ? "text-ok" : l.startsWith("-") ? "text-bad" : "text-muted"}>
                    {l + "\n"}
                  </span>
                ))}
              </pre>
              <p className={change.risk === "high" ? "text-bad" : "text-warn"}>{t(`settings.risk.${change.risk}`)}</p>
              {change.state === "planned" && (
                <div className="flex flex-wrap gap-2">
                  <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void apply()}>
                    {t("settings.apply")}
                  </button>
                  <button type="button" className="btn btn-secondary" disabled={busy} onClick={discard}>
                    {t("common.cancel")}
                  </button>
                </div>
              )}
              {change.state === "applied" && (
                <>
                  <Notice tone="warn" live>
                    {t("settings.confirmPrompt", { seconds: left })}
                  </Notice>
                  <div className="flex flex-wrap gap-2">
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void confirm()}>
                      <Icon name="check" />
                      {t("settings.keep")}
                    </button>
                    <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void rollback()}>
                      {t("settings.undo")}
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </Panel>
      )}

      {s && (
        <Panel>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Icon name="settings" />
            {t("settings.general")}
          </h2>
          <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-faint">{t("settings.tls")}</dt>
            <dd>{s.tls_source ?? "—"}</dd>
            <dt className="text-faint">{t("settings.sessionTimes")}</dt>
            <dd>{t("settings.sessionTimesValue", { idle: s.idle_minutes, abs: s.absolute_hours })}</dd>
            <dt className="text-faint">{t("settings.upload")}</dt>
            <dd>{s.upload_limit_mib} MiB</dd>
          </dl>
          <p className="mt-4 text-sm text-faint">{t("settings.moreLater")}</p>
        </Panel>
      )}
    </div>
  );
}
