import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";
import { methods, relativeName, running, zoneGuess, type CA, type CertInfo, type CertMode, type CertView, type Issuance } from "../lib/cert";
import { errorText } from "../lib/errors";
import { Icon } from "./icons";
import { Explain, Field, Notice } from "./ui";

interface Props {
  /** "/setup/certificate" (bootstrap token) or "/certificate" (settings). */
  base: "/setup/certificate" | "/certificate";
  token?: string;
  /** Wraps changing calls (step-up in the settings). */
  wrap?: <T>(fn: () => Promise<T>) => Promise<T>;
  defaultCa?: CA;
  canWrite?: boolean;
  /** A certificate was installed by this form. */
  onInstalled?: (c: CertInfo) => void;
  /** Shows a cancel button next to the submit button (settings). */
  onClose?: () => void;
  /** The status could not be read while an issuance ran (setup: the web service switched to the domain). */
  onLost?: () => void;
}

/** The view of the certificate and the current issuance (shared query key per base). */
export function useCertView(base: Props["base"], token?: string) {
  return useQuery({
    queryKey: ["certificate", base],
    queryFn: () => (base === "/certificate" ? api<CertView>("GET", "/certificate") : api<CertView>("POST", "/setup/certificate/status", { token })),
    refetchInterval: (q) => (running(q.state.data?.issuance) ? 3000 : false),
    retry: false,
  });
}

function Copy({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-ghost min-h-0 shrink-0 px-2 py-1"
      title={label}
      aria-label={label}
      onClick={() =>
        void navigator.clipboard
          ?.writeText(text)
          .then(() => {
            setDone(true);
            setTimeout(() => setDone(false), 1500);
          })
          .catch(() => undefined)
      }
    >
      <Icon name={done ? "check" : "copy"} />
    </button>
  );
}

function Progress({ i, domain, busy, onConfirm, onCancel }: { i: Issuance; domain: string; busy: boolean; onConfirm: () => void; onCancel: () => void }) {
  const { t } = useTranslation();
  const rec = i.record;
  return (
    <div className="flex flex-col gap-4">
      {i.state === "running" && (
        <Notice tone="info" live>
          {t(i.method === "dns-01" ? "cert.preparing" : "cert.working", { method: i.method })}
        </Notice>
      )}
      {rec && (i.state === "dns_wait" || i.state === "dns_check") && (
        <>
          <p>{t("cert.dnsIntro")}</p>
          <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-faint">{t("cert.dnsType")}</dt>
            <dd className="font-mono">TXT</dd>
            <dt className="text-faint">{t("cert.dnsName")}</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <code className="min-w-0 break-all">{rec.name}</code>
              <Copy text={rec.name} label={t("cert.copy")} />
            </dd>
            <dt className="text-faint">{t("cert.dnsValue")}</dt>
            <dd className="flex min-w-0 items-center gap-1">
              <code className="min-w-0 break-all">{rec.value}</code>
              <Copy text={rec.value} label={t("cert.copy")} />
            </dd>
            <dt className="text-faint">TTL</dt>
            <dd>{t("cert.dnsTtl")}</dd>
          </dl>
          <p className="text-sm text-muted">{t("cert.dnsShort", { name: relativeName(rec.name, zoneGuess(domain)) })}</p>
        </>
      )}
      {i.state === "dns_check" && (
        <Notice tone={i.check && i.check !== "ok" ? "warn" : "info"} live>
          {t("cert.checking", { n: i.checks ?? 0 })}
          {i.check && i.check !== "ok" && <span className="block text-sm break-all text-muted">{i.check === "pending" ? t("cert.notVisible") : i.check}</span>}
        </Notice>
      )}
      <div className="flex flex-wrap gap-2">
        {i.state === "dns_wait" && (
          <button type="button" className="btn btn-primary" disabled={busy} onClick={onConfirm}>
            <Icon name="check" />
            {t("cert.dnsConfirm")}
          </button>
        )}
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>
          <Icon name="close" />
          {t("cert.cancel")}
        </button>
      </div>
    </div>
  );
}

/** Choose and install the dashboard certificate: Let's Encrypt (HTTP-01, TLS-ALPN-01, guided DNS-01) or own PEM. */
export function CertificateForm({ base, token, wrap = (fn) => fn(), defaultCa = "production", canWrite = true, onInstalled, onClose, onLost }: Props) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [mode, setMode] = useState<CertMode>("http-01");
  const [ca, setCa] = useState<CA>(defaultCa);
  const [tos, setTos] = useState(false);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const view = useCertView(base, token);
  const i = view.data?.issuance;
  // Set while an issuance started here has not been seen to end.
  const watching = useRef(false);

  useEffect(() => {
    if (!watching.current || !i || running(i)) return;
    watching.current = false;
    if (i.state === "done" && i.cert) onInstalled?.(i.cert);
  }, [i, onInstalled]);
  useEffect(() => {
    if (watching.current && view.isError) {
      watching.current = false;
      onLost?.();
    }
  }, [view.isError, onLost]);

  const body = (extra: Record<string, unknown>) => (token !== undefined ? { token, ...extra } : extra);
  const call = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(undefined);
    try {
      await wrap(fn);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
      await qc.invalidateQueries({ queryKey: ["certificate", base] });
    }
  };

  const submit = () =>
    call(async () => {
      if (mode === "own") {
        const c = await api<CertInfo>("POST", `${base}/upload`, body({ cert_pem: certPem, key_pem: keyPem }));
        setCertPem("");
        setKeyPem("");
        onInstalled?.(c);
        return;
      }
      await api<Issuance>("POST", `${base}/acme`, body({ method: mode, ca, agree_tos: tos }));
      watching.current = true;
    });

  if (i && running(i)) {
    return (
      <div className="flex flex-col gap-4">
        {err && <Notice tone="bad">{err}</Notice>}
        <Progress
          i={i}
          domain={view.data?.domain ?? ""}
          busy={busy || !canWrite}
          onConfirm={() => void call(() => api("POST", `${base}/dns_confirm`, body({})))}
          onCancel={() => void call(() => api("POST", `${base}/cancel`, body({})))}
        />
      </div>
    );
  }

  return (
    <form
      className="flex flex-col gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      {err && <Notice tone="bad">{err}</Notice>}
      {i?.state === "failed" && (
        <Notice tone="bad">
          {t("cert.failed", { method: i.method })}
          {i.error && <span className="block text-sm break-all text-muted">{i.error}</span>}
        </Notice>
      )}
      {i?.state === "canceled" && <Notice tone="warn">{t("cert.canceled")}</Notice>}
      <fieldset className="flex flex-col gap-3" disabled={!canWrite}>
        <legend className="sr-only">{t("cert.source")}</legend>
        {methods.map((m) => (
          <label key={m} className="flex items-start gap-2">
            <input type="radio" name="cert-mode" checked={mode === m} onChange={() => setMode(m)} className="mt-1" />
            <span>
              <span className="font-medium">{t(`cert.mode.${m}`)}</span>
              <span className="block text-sm text-muted">{t(`cert.modeHelp.${m}`)}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {mode !== "own" ? (
        <>
          <Field label={t("cert.ca")}>
            {(p) => (
              <select {...p} className="input" value={ca} disabled={!canWrite} onChange={(e) => setCa(e.target.value === "staging" ? "staging" : "production")}>
                <option value="production">{t("cert.production")}</option>
                <option value="staging">{t("cert.staging")}</option>
              </select>
            )}
          </Field>
          <label className="flex items-start gap-2">
            <input type="checkbox" checked={tos} disabled={!canWrite} onChange={(e) => setTos(e.target.checked)} className="mt-1" />
            <span>{t("cert.tos")}</span>
          </label>
        </>
      ) : (
        <>
          <Field label={t("cert.certPem")}>
            {(p) => <textarea {...p} className="input" value={certPem} onChange={(e) => setCertPem(e.target.value)} spellCheck={false} />}
          </Field>
          <Field label={t("cert.keyPem")}>
            {(p) => <textarea {...p} className="input" value={keyPem} onChange={(e) => setKeyPem(e.target.value)} spellCheck={false} autoComplete="off" />}
          </Field>
        </>
      )}
      <Explain>{t(`cert.explain.${mode}`)}</Explain>
      <div className="flex flex-wrap gap-2">
        <button className="btn btn-primary" disabled={!canWrite || busy || (mode === "own" ? !certPem || !keyPem : !tos)}>
          <Icon name={mode === "own" ? "upload" : "lock"} />
          {mode === "own" ? t("cert.upload") : t("cert.issue")}
        </button>
        {onClose && (
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
        )}
      </div>
    </form>
  );
}
