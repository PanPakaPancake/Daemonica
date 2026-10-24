import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { Notice, Panel, Wordmark } from "../components/ui";
import { api, type CeremonyStart } from "../lib/api";
import { errorText } from "../lib/errors";
import { getPasskey, supported } from "../lib/webauthn";

export function Login() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const nav = useNavigate();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();

  const login = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const start = await api<CeremonyStart>("POST", "/auth/login/begin");
      const response = await getPasskey(start.options);
      await api("POST", "/auth/login/finish", { ceremony_id: start.ceremony_id, response });
      await qc.invalidateQueries({ queryKey: ["session"] });
      void nav("/", { replace: true });
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="grid min-h-screen place-items-center p-4">
      <Panel edge className="w-full max-w-md">
        <div className="flex flex-col items-center gap-2 text-center">
          <Wordmark size="lg" />
          <p className="text-muted">{t("app.tagline")}</p>
        </div>
        <h1 className="mt-8 text-xl font-semibold">{t("login.title")}</h1>
        <p className="mt-1 text-muted">{t("login.intro")}</p>
        <div className="mt-6 flex flex-col gap-4">
          {!supported() && <Notice tone="bad">{t("errors.webauthn_unsupported")}</Notice>}
          {err && <Notice tone="bad">{err}</Notice>}
          <button type="button" className="btn btn-primary w-full" onClick={() => void login()} disabled={busy || !supported()}>
            {t("login.button")}
          </button>
          <p className="text-sm text-faint">{t("login.recovery")}</p>
          <Link to="/recovery" className="text-sm text-violet underline">
            {t("login.recoveryLink")}
          </Link>
        </div>
      </Panel>
    </main>
  );
}
