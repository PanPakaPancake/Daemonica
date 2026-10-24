import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { Field, Notice, Panel, Wordmark } from "../components/ui";
import { api, type CeremonyStart } from "../lib/api";
import { errorText } from "../lib/errors";
import { createPasskey, supported } from "../lib/webauthn";

export function Recovery() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const nav = useNavigate();
  const [token, setToken] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();

  const submit = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const start = await api<CeremonyStart>("POST", "/recovery/begin", { token });
      const response = await createPasskey(start.options);
      await api("POST", "/recovery/finish", { token, ceremony_id: start.ceremony_id, response, passkey_name: name.trim() });
      await qc.invalidateQueries({ queryKey: ["session"] });
      void nav("/security/passkeys", { replace: true });
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="grid min-h-screen place-items-center p-4">
      <Panel edge className="w-full max-w-md">
        <Wordmark />
        <h1 className="mt-6 text-xl font-semibold">{t("recovery.title")}</h1>
        <p className="mt-1 text-muted">{t("recovery.intro")}</p>
        <form
          className="mt-6 flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {err && <Notice tone="bad">{err}</Notice>}
          <Field label={t("recovery.token")}>
            {(p) => <input {...p} className="input font-mono" autoComplete="off" spellCheck={false} value={token} onChange={(e) => setToken(e.target.value.trim())} required />}
          </Field>
          <Field label={t("setup.passkey.name")}>
            {(p) => <input {...p} className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />}
          </Field>
          <button className="btn btn-primary" disabled={busy || !token || !supported()}>
            {t("recovery.register")}
          </button>
        </form>
      </Panel>
    </main>
  );
}
