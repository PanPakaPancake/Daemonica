import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { Explain, Field, Notice, Panel, Steps, Wordmark } from "../components/ui";
import { api, type CeremonyStart, type LinuxUser, type SetupState } from "../lib/api";
import { errorText } from "../lib/errors";
import { createPasskey, supported } from "../lib/webauthn";

type Step = "token" | "domain" | "allowlist" | "certificate" | "switch" | "passkey" | "done";
const order: Step[] = ["token", "domain", "allowlist", "certificate", "switch", "passkey", "done"];

const isLoopback = () => ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname);

function targetURL(s: SetupState | undefined): string {
  if (!s?.domain) return "";
  return s.port && s.port !== 443 ? `https://${s.domain}:${s.port}/setup` : `https://${s.domain}/setup`;
}

export function Setup() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const nav = useNavigate();
  const state = useQuery({ queryKey: ["setup-state"], queryFn: () => api<SetupState>("GET", "/setup/state") });
  const [step, setStep] = useState<Step>("token");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();

  // Form state
  const [domain, setDomain] = useState("");
  const [port, setPort] = useState("8443");
  const [allow, setAllow] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [publicOk, setPublicOk] = useState(false);
  const [certMode, setCertMode] = useState<"acme" | "own">("acme");
  const [ca, setCa] = useState<"production" | "staging">("production");
  const [tos, setTos] = useState(false);
  const [certPem, setCertPem] = useState("");
  const [keyPem, setKeyPem] = useState("");
  const [certInfo, setCertInfo] = useState<string>();
  const [account, setAccount] = useState("");
  const [linuxUser, setLinuxUser] = useState("");
  const [pkName, setPkName] = useState("");
  const [users, setUsers] = useState<LinuxUser[]>();

  useEffect(() => {
    if (state.data?.setup_done) void nav("/login", { replace: true });
  }, [state.data, nav]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(undefined);
    try {
      await fn();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  // After the token: on the final domain go straight to the passkey step.
  const afterToken = async () => {
    await api("POST", "/setup/token", { token });
    const s = await qc.fetchQuery({ queryKey: ["setup-state"], queryFn: () => api<SetupState>("GET", "/setup/state") });
    if (s.domain) setDomain(s.domain);
    if (s.port) setPort(String(s.port));
    if (!isLoopback() && s.domain && s.has_certificate) {
      setUsers(await api<LinuxUser[]>("POST", "/setup/linux-users", { token }));
      setStep("passkey");
    } else {
      setStep("domain");
    }
  };

  const saveDomain = async () => {
    await api("POST", "/setup/domain", { token, domain: domain.trim().toLowerCase(), port: Number(port) });
    setStep("allowlist");
  };

  const saveAllowlist = async () => {
    const list = isPublic ? ["0.0.0.0/0", "::/0"] : allow.split(/\s+/).filter(Boolean);
    await api("POST", "/setup/allowlist", { token, allowlist: list, confirm_public: isPublic && publicOk });
    setStep("certificate");
  };

  const installCert = async () => {
    const info =
      certMode === "acme"
        ? await api<{ not_after: string }>("POST", "/setup/certificate/acme", { token, method: "http-01", ca, agree_tos: tos })
        : await api<{ not_after: string }>("POST", "/setup/certificate/upload", { token, cert_pem: certPem, key_pem: keyPem });
    setCertInfo(new Date(info.not_after).toLocaleDateString());
    await qc.invalidateQueries({ queryKey: ["setup-state"] });
    setStep("switch");
  };

  const register = async () => {
    const start = await api<CeremonyStart>("POST", "/setup/register/begin", { token, account_name: account.trim(), linux_user: linuxUser });
    const response = await createPasskey(start.options);
    await api("POST", "/setup/register/finish", { token, ceremony_id: start.ceremony_id, response, passkey_name: pkName.trim() });
    await qc.invalidateQueries({ queryKey: ["session"] });
    setStep("done");
  };

  const url = targetURL(state.data);
  const stepIndex = order.indexOf(step);

  return (
    <main className="grid min-h-screen place-items-start justify-center p-4 md:place-items-center">
      <Panel edge className="w-full max-w-2xl">
        <Wordmark />
        <h1 className="mt-4 text-2xl font-semibold">{t("setup.title")}</h1>
        <div className="mt-4">
          <Steps steps={order.map((s) => t(`setup.steps.${s}`))} current={stepIndex} />
        </div>
        <div className="mt-6 flex flex-col gap-5">
          {err && <Notice tone="bad">{err}</Notice>}

          {step === "token" && (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                void run(afterToken);
              }}
            >
              <Field label={t("setup.token.label")} help={t("setup.token.help")}>
                {(p) => (
                  <input {...p} className="input font-mono" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value.trim())} required />
                )}
              </Field>
              <Explain>{t("setup.token.explain")}</Explain>
              <div className="flex justify-end">
                <button className="btn btn-primary" disabled={busy || !token}>
                  {t("common.next")}
                </button>
              </div>
            </form>
          )}

          {step === "domain" && (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                void run(saveDomain);
              }}
            >
              <div className="grid gap-4 md:grid-cols-[1fr_8rem]">
                <Field label={t("setup.domain.label")} help={t("setup.domain.help")}>
                  {(p) => <input {...p} className="input" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="dash.example.org" required />}
                </Field>
                <Field label={t("setup.domain.port")}>
                  {(p) => <input {...p} className="input" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} required />}
                </Field>
              </div>
              <Explain>{t("setup.domain.explain")}</Explain>
              <Nav onBack={() => setStep("token")} busy={busy} />
            </form>
          )}

          {step === "allowlist" && (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                void run(saveAllowlist);
              }}
            >
              <Field label={t("setup.allowlist.label")} help={t("setup.allowlist.help")}>
                {(p) => <textarea {...p} className="input" value={allow} onChange={(e) => setAllow(e.target.value)} disabled={isPublic} placeholder="203.0.113.7/32" />}
              </Field>
              <label className="flex items-start gap-2">
                <input type="checkbox" checked={isPublic} onChange={(e) => setIsPublic(e.target.checked)} className="mt-1" />
                <span>{t("setup.allowlist.public")}</span>
              </label>
              {isPublic && (
                <>
                  <Notice tone="warn">{t("setup.allowlist.publicWarning")}</Notice>
                  <label className="flex items-start gap-2">
                    <input type="checkbox" checked={publicOk} onChange={(e) => setPublicOk(e.target.checked)} className="mt-1" />
                    <span>{t("setup.allowlist.publicConfirm")}</span>
                  </label>
                </>
              )}
              <Explain>{t("setup.allowlist.explain")}</Explain>
              <Nav onBack={() => setStep("domain")} busy={busy} disabled={isPublic ? !publicOk : !allow.trim()} />
            </form>
          )}

          {step === "certificate" && (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                void run(installCert);
              }}
            >
              <fieldset className="flex flex-col gap-3">
                <legend className="sr-only">{t("setup.steps.certificate")}</legend>
                <label className="flex items-start gap-2">
                  <input type="radio" name="cert" checked={certMode === "acme"} onChange={() => setCertMode("acme")} className="mt-1" />
                  <span>
                    <span className="font-medium">{t("setup.certificate.acme")}</span>
                    <span className="block text-sm text-muted">{t("setup.certificate.acmeHelp")}</span>
                  </span>
                </label>
                <label className="flex items-start gap-2">
                  <input type="radio" name="cert" checked={certMode === "own"} onChange={() => setCertMode("own")} className="mt-1" />
                  <span className="font-medium">{t("setup.certificate.own")}</span>
                </label>
              </fieldset>
              {certMode === "acme" ? (
                <>
                  <Field label={t("setup.certificate.ca")}>
                    {(p) => (
                      <select {...p} className="input" value={ca} onChange={(e) => setCa(e.target.value === "staging" ? "staging" : "production")}>
                        <option value="production">{t("setup.certificate.production")}</option>
                        <option value="staging">{t("setup.certificate.staging")}</option>
                      </select>
                    )}
                  </Field>
                  <label className="flex items-start gap-2">
                    <input type="checkbox" checked={tos} onChange={(e) => setTos(e.target.checked)} className="mt-1" />
                    <span>{t("setup.certificate.tos")}</span>
                  </label>
                </>
              ) : (
                <>
                  <Field label={t("setup.certificate.certPem")}>
                    {(p) => <textarea {...p} className="input" value={certPem} onChange={(e) => setCertPem(e.target.value)} spellCheck={false} />}
                  </Field>
                  <Field label={t("setup.certificate.keyPem")}>
                    {(p) => <textarea {...p} className="input" value={keyPem} onChange={(e) => setKeyPem(e.target.value)} spellCheck={false} autoComplete="off" />}
                  </Field>
                </>
              )}
              {busy && <Notice tone="info" live>{t("setup.certificate.working")}</Notice>}
              <Explain>{t("setup.certificate.explain")}</Explain>
              <Nav
                onBack={() => setStep("allowlist")}
                busy={busy}
                label={certMode === "acme" ? t("setup.certificate.issue") : t("setup.certificate.upload")}
                disabled={certMode === "acme" ? !tos : !certPem || !keyPem}
              />
            </form>
          )}

          {step === "switch" && (
            <div className="flex flex-col gap-4">
              {certInfo && <Notice tone="ok">{t("setup.certificate.ok", { date: certInfo })}</Notice>}
              <h2 className="text-lg font-semibold">{t("setup.switch.title")}</h2>
              <p>{t("setup.switch.text", { url })}</p>
              {url && (
                <a className="btn btn-primary self-start" href={url} rel="noreferrer">
                  {t("setup.switch.open", { url })}
                </a>
              )}
            </div>
          )}

          {step === "passkey" && (
            <form
              className="flex flex-col gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                void run(register);
              }}
            >
              {isLoopback() && url && <Notice tone="warn">{t("setup.wrongOrigin", { url })}</Notice>}
              {!supported() && <Notice tone="bad">{t("errors.webauthn_unsupported")}</Notice>}
              <Field label={t("setup.passkey.account")}>
                {(p) => <input {...p} className="input" value={account} onChange={(e) => setAccount(e.target.value)} maxLength={64} required />}
              </Field>
              <Field label={t("setup.passkey.linuxUser")} help={t("setup.passkey.linuxUserHelp")}>
                {(p) =>
                  users && users.length === 0 ? (
                    <Notice tone="warn">{t("setup.passkey.noUsers")}</Notice>
                  ) : (
                    <select {...p} className="input" value={linuxUser} onChange={(e) => setLinuxUser(e.target.value)} required>
                      <option value="" disabled>
                        —
                      </option>
                      {(users ?? []).map((u) => (
                        <option key={u.name} value={u.name}>
                          {u.name} (UID {u.uid})
                        </option>
                      ))}
                    </select>
                  )
                }
              </Field>
              <Field label={t("setup.passkey.name")}>
                {(p) => <input {...p} className="input" value={pkName} onChange={(e) => setPkName(e.target.value)} maxLength={64} />}
              </Field>
              <Explain>{t("setup.passkey.explain")}</Explain>
              <div className="flex justify-end">
                <button className="btn btn-primary" disabled={busy || !account || !linuxUser || !supported()}>
                  {t("setup.passkey.register")}
                </button>
              </div>
            </form>
          )}

          {step === "done" && (
            <div className="flex flex-col gap-4">
              <Notice tone="ok">{t("setup.done.title")}</Notice>
              <p>{t("setup.done.text")}</p>
              <button type="button" className="btn btn-primary self-start" onClick={() => void nav("/security/passkeys")}>
                {t("setup.done.go")}
              </button>
            </div>
          )}
        </div>
      </Panel>
    </main>
  );
}

function Nav({ onBack, busy, disabled = false, label }: { onBack: () => void; busy: boolean; disabled?: boolean; label?: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex justify-between">
      <button type="button" className="btn btn-secondary" onClick={onBack} disabled={busy}>
        {t("common.back")}
      </button>
      <button className="btn btn-primary" disabled={busy || disabled}>
        {label ?? t("common.next")}
      </button>
    </div>
  );
}
