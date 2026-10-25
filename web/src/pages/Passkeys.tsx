import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Field, Notice, Panel } from "../components/ui";
import { api, type CeremonyStart, type Passkey } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import { createPasskey } from "../lib/webauthn";

export function Passkeys() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const { withStepUp } = useSession();
  const q = useQuery({ queryKey: ["passkeys"], queryFn: () => api<Passkey[]>("GET", "/passkeys") });
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [renaming, setRenaming] = useState<string>();
  const [newName, setNewName] = useState("");

  const fmt = (s?: string) => (s ? new Date(s).toLocaleString(i18n.language) : t("passkeys.never"));

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(undefined);
    try {
      await fn();
      await qc.invalidateQueries({ queryKey: ["passkeys"] });
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const add = () =>
    act(() =>
      withStepUp(async () => {
        const start = await api<CeremonyStart>("POST", "/passkeys/begin");
        const response = await createPasskey(start.options);
        await api("POST", "/passkeys/finish", { ceremony_id: start.ceremony_id, response, passkey_name: name.trim() });
        setName("");
      }),
    );

  const remove = (p: Passkey) => {
    if (!window.confirm(t("passkeys.confirmRemove", { name: p.name }))) return;
    void act(() => withStepUp(() => api("DELETE", `/passkeys/${encodeURIComponent(p.id)}`)));
  };

  const list = q.data ?? [];
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("passkeys.title")}</h1>
        <p className="mt-1 text-muted">{t("passkeys.intro")}</p>
      </div>
      {q.isSuccess && list.length < 2 && <Notice tone="warn">{t("passkeys.secondHint")}</Notice>}
      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}

      <Panel>
        {q.isLoading ? (
          <p className="text-muted">{t("common.loading")}</p>
        ) : (
          <ul className="divide-y divide-[var(--border-subtle)]">
            {list.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                <div className="min-w-0">
                  {renaming === p.id ? (
                    <form
                      className="flex gap-2"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void act(async () => {
                          await api("PATCH", `/passkeys/${encodeURIComponent(p.id)}`, { name: newName });
                          setRenaming(undefined);
                        });
                      }}
                    >
                      <label className="sr-only" htmlFor={`rn-${p.id}`}>
                        {t("passkeys.newName")}
                      </label>
                      <input id={`rn-${p.id}`} className="input" value={newName} onChange={(e) => setNewName(e.target.value)} maxLength={64} autoFocus />
                      <button className="btn btn-primary" disabled={busy}>
                        {t("common.save")}
                      </button>
                    </form>
                  ) : (
                    <p className="font-semibold">{p.name}</p>
                  )}
                  <p className="text-sm text-muted">
                    {p.backup_state ? t("passkeys.synced") : t("passkeys.deviceBound")} · {t("passkeys.created")} {fmt(p.created_at)} · {t("passkeys.lastUsed")}{" "}
                    {fmt(p.last_used_at)}
                  </p>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => {
                      setRenaming(p.id);
                      setNewName(p.name);
                    }}
                  >
                    {t("common.rename")}
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy || list.length < 2}
                    title={list.length < 2 ? t("passkeys.lastOne") : undefined}
                    onClick={() => remove(p)}
                  >
                    {t("common.remove")}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel>
        <form
          className="flex flex-col gap-4 md:flex-row md:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            void add();
          }}
        >
          <div className="flex-1">
            <Field label={t("setup.passkey.name")}>
              {(p) => <input {...p} className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />}
            </Field>
          </div>
          <button className="btn btn-primary" disabled={busy}>
            {t("passkeys.add")}
          </button>
        </form>
      </Panel>
    </div>
  );
}
