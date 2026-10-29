import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { CertificateForm, useCertView } from "../components/CertificateForm";
import { ChangeFlow, type Change } from "../components/ChangeFlow";
import { Icon } from "../components/icons";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { certTone, isStaging, running } from "../lib/cert";
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
const loopback = new Set(["127.0.0.0/8", "::1/128"]);

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
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "warn" }>();

  const s = q.data;
  const current = s ? s.allowlist.filter((x) => !loopback.has(x)).join("\n") : "";
  const value = text ?? current;
  const entries = value
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

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

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("settings.title")}</h1>
        <p className="mt-1 text-muted">{t("settings.intro")}</p>
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {done?.msg && (
        <Notice tone={done.tone} live>
          {done.msg}
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
            <div className="mt-6">
              <ChangeFlow
                change={change}
                ns="settings"
                onChange={(c) => {
                  setChange(c);
                  if (!c) {
                    setText(undefined);
                    setNeedLockout(false);
                    setNeedPublic(false);
                  }
                }}
                onDone={(msg, tone) => {
                  setDone({ msg, tone });
                  void qc.invalidateQueries({ queryKey: ["settings"] });
                }}
              />
            </div>
          )}
        </Panel>
      )}

      {s && <CertificatePanel />}

      {s && (
        <Panel>
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Icon name="settings" />
            {t("settings.general")}
          </h2>
          <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
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

function CertificatePanel() {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const q = useCertView("/certificate");
  const [open, setOpen] = useState(false);
  const [done, setDone] = useState<string>();
  const v = q.data;
  const c = v?.cert;
  const tone = certTone(c, v?.renew_days ?? 30);
  const showForm = open || running(v?.issuance);
  return (
    <Panel>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Icon name="lock" />
          {t("cert.title")}
        </h2>
        {!showForm && v && (
          <button type="button" className="btn btn-secondary ml-auto" onClick={() => setOpen(true)}>
            <Icon name="edit" />
            {t("cert.change")}
          </button>
        )}
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {done && (
        <div className="mt-4">
          <Notice tone="ok" live>
            {done}
          </Notice>
        </div>
      )}
      {v && (
        <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
          <dt className="text-faint">{t("cert.names")}</dt>
          <dd className="font-mono break-all">{c?.names?.join(", ") || v.domain}</dd>
          <dt className="text-faint">{t("cert.issuer")}</dt>
          <dd>{c?.issuer || "—"}</dd>
          <dt className="text-faint">{t("cert.validUntil")}</dt>
          <dd className={tone === "ok" ? "" : tone === "warn" ? "text-warn" : "text-bad"}>
            {c ? t("cert.validValue", { date: new Date(c.not_after).toLocaleString(), days: c.days_left }) : "—"}
          </dd>
          <dt className="text-faint">{t("cert.sourceLabel")}</dt>
          <dd>{v.source ? t(`cert.sourceName.${v.source}`, { defaultValue: v.source }) : "—"}</dd>
          {v.method && (
            <>
              <dt className="text-faint">{t("cert.method")}</dt>
              <dd className="font-mono">{v.method}</dd>
            </>
          )}
          <dt className="text-faint">{t("cert.renewal")}</dt>
          <dd>{v.auto_renew ? t("cert.renewAuto", { days: v.renew_days }) : v.source === "own" ? t("cert.renewOwn") : t("cert.renewManual")}</dd>
        </dl>
      )}
      {c && tone !== "ok" && (
        <div className="mt-4">
          <Notice tone={tone}>{tone === "bad" ? t("cert.expired") : t("cert.expiring", { days: c.days_left })}</Notice>
        </div>
      )}
      {isStaging(c) && (
        <div className="mt-4">
          <Notice tone="warn">{t("cert.stagingWarn")}</Notice>
        </div>
      )}
      {v?.issuance?.renewal && v.issuance.state === "failed" && !showForm && (
        <div className="mt-4">
          <Notice tone="bad">
            {t("cert.renewFailed")}
            {v.issuance.error && <span className="block text-sm break-all text-muted">{v.issuance.error}</span>}
          </Notice>
        </div>
      )}
      {showForm && v && (
        <div className="mt-6 flex flex-col gap-4">
          <CertificateForm
            base="/certificate"
            wrap={withStepUp}
            defaultCa={v.source === "acme-staging" ? "staging" : "production"}
            onClose={() => setOpen(false)}
            onInstalled={(ci) => {
              setOpen(false);
              setDone(t("cert.installed", { date: new Date(ci.not_after).toLocaleDateString() }));
            }}
          />
        </div>
      )}
    </Panel>
  );
}
