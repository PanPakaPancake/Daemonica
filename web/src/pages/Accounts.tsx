import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Icon } from "../components/icons";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, type Account } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import { DataTable } from "../components/DataTable";
import type { MenuItem } from "../components/Modal";

interface AccountView extends Account {
  disabled: boolean;
  created_at: string;
  sessions: number;
  self: boolean;
  invited: boolean;
}
interface LinuxUser {
  name: string;
  uid: number;
}
interface InviteResult {
  account: Account;
  token: string;
  expires_at: string;
}

const roles: Account["role"][] = ["admin", "operator", "readonly"];

export function Accounts() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const { withStepUp } = useSession();
  const list = useQuery({ queryKey: ["accounts"], queryFn: () => api<AccountView[]>("GET", "/accounts") });
  const users = useQuery({ queryKey: ["accounts-linux-users"], queryFn: () => api<LinuxUser[]>("GET", "/accounts/linux-users") });

  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [invite, setInvite] = useState<InviteResult>();
  const [copied, setCopied] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<Account["role"]>("operator");
  const [linuxUser, setLinuxUser] = useState("");
  const [deleting, setDeleting] = useState<string>();
  const [confirm, setConfirm] = useState("");

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setErr(undefined);
    try {
      await fn();
      await qc.invalidateQueries({ queryKey: ["accounts"] });
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  // Same actions as the row buttons, for the right-click menu.
  const accountItems = (a: AccountView): MenuItem[] => [
    ...(a.invited && !a.disabled
      ? [
          {
            label: t("accounts.reinvite"),
            icon: "passkey" as const,
            disabled: busy,
            onSelect: () => void act(async () => showInvite(await withStepUp(() => api<InviteResult>("POST", `/accounts/${id(a)}/reinvite`)))),
          },
        ]
      : []),
    {
      label: a.disabled ? t("accounts.enable") : t("accounts.disable"),
      icon: "lock",
      disabled: busy,
      onSelect: () => void act(() => withStepUp(() => api("PATCH", `/accounts/${id(a)}/disabled`, { disabled: !a.disabled }))),
    },
    {
      label: t("common.remove"),
      icon: "trash",
      danger: true,
      disabled: busy,
      onSelect: () => {
        setDeleting(a.id);
        setConfirm("");
      },
    },
  ];

  const showInvite = (r: InviteResult) => {
    setInvite(r);
    setCopied(false);
  };

  const submitInvite = () =>
    act(async () => {
      const r = await withStepUp(() => api<InviteResult>("POST", "/accounts", { name: name.trim(), role, linux_user: linuxUser }));
      showInvite(r);
      setName("");
    });

  const inviteLink = invite ? `${window.location.origin}/invite#token=${invite.token}` : "";
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(inviteLink);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  const fmt = (s: string) => new Date(s).toLocaleString(i18n.language);
  const id = (a: AccountView) => encodeURIComponent(a.id);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("accounts.title")}</h1>
        <p className="mt-1 text-muted">{t("accounts.intro")}</p>
      </div>
      {err && <Notice tone="bad">{err}</Notice>}
      {list.isError && <Notice tone="bad">{errorText(t, list.error)}</Notice>}

      {invite && (
        <Panel edge>
          <h2 className="text-lg font-semibold">{t("accounts.inviteReady", { name: invite.account.name })}</h2>
          <p className="mt-1 text-muted">{t("accounts.inviteOnce", { time: fmt(invite.expires_at) })}</p>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <code className="min-w-0 flex-1 break-all rounded-[8px] border border-line bg-bg-0 px-3 py-2 font-mono text-sm">{inviteLink}</code>
            <button type="button" className="btn btn-secondary" onClick={() => void copy()}>
              <Icon name={copied ? "check" : "files"} />
              {copied ? t("accounts.copied") : t("accounts.copy")}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => setInvite(undefined)}>
              {t("common.close")}
            </button>
          </div>
        </Panel>
      )}

      <Panel>
        <h2 className="text-lg font-semibold">{t("accounts.inviteTitle")}</h2>
        <form
          className="mt-4 grid gap-4 md:grid-cols-[2fr_1fr_1fr_auto] md:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            void submitInvite();
          }}
        >
          <Field label={t("accounts.name")}>
            {(p) => <input {...p} className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required />}
          </Field>
          <Field label={t("accounts.role")}>
            {(p) => (
              <select {...p} className="input" value={role} onChange={(e) => setRole(e.target.value as Account["role"])}>
                {roles.map((r) => (
                  <option key={r} value={r}>
                    {t(`header.role.${r}`)}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label={t("accounts.linuxUser")}>
            {(p) => (
              <select {...p} className="input" value={linuxUser} onChange={(e) => setLinuxUser(e.target.value)} required>
                <option value="">—</option>
                {(users.data ?? []).map((u) => (
                  <option key={u.name} value={u.name}>
                    {u.name} ({u.uid})
                  </option>
                ))}
              </select>
            )}
          </Field>
          <button className="btn btn-primary" disabled={busy || !name.trim() || !linuxUser}>
            <Icon name="users" />
            {t("accounts.invite")}
          </button>
        </form>
        <div className="mt-4">
          <Explain>{t("accounts.inviteExplain")}</Explain>
        </div>
      </Panel>

      <Panel>
        {list.isLoading ? (
          <p className="text-muted">{t("common.loading")}</p>
        ) : (
          <div className="overflow-x-auto">
            <DataTable
              rows={list.data}
              rowKey={(a) => a.id}
              label={t("accounts.title")}
              defaultSort={{ key: "name", desc: false }}
              rowMenu={(a) => ({ label: a.name, items: a.self ? [] : accountItems(a) })}
              columns={[
                {
                  key: "name",
                  label: t("accounts.name"),
                  sortValue: (a) => a.name,
                  filter: "text",
                  cell: (a) => (
                    <>
                      <span className="font-medium">{a.name}</span>
                      {a.self && <span className="ml-2 rounded-full border border-cyan px-2 py-0.5 text-xs text-cyan">{t("accounts.you")}</span>}
                    </>
                  ),
                },
                {
                  key: "role",
                  label: t("accounts.role"),
                  sortValue: (a) => a.role,
                  filter: { options: roles.map((r) => ({ value: r, label: t(`header.role.${r}`) })) },
                  cell: (a) => (
                    <>
                      {a.self ? (
                        t(`header.role.${a.role}`)
                      ) : (
                        <select
                          aria-label={t("accounts.roleOf", { name: a.name })}
                          className="input min-h-9 py-1 header-select"
                          value={a.role}
                          disabled={busy}
                          onChange={(e) => {
                            const r = e.target.value;
                            if (!window.confirm(t("accounts.confirmRole", { name: a.name }))) return;
                            void act(() => withStepUp(() => api("PATCH", `/accounts/${id(a)}/role`, { role: r })));
                          }}
                        >
                          {roles.map((r) => (
                            <option key={r} value={r}>
                              {t(`header.role.${r}`)}
                            </option>
                          ))}
                        </select>
                      )}
                    </>
                  ),
                },
                {
                  key: "linux",
                  label: t("accounts.linuxUser"),
                  tdClass: "font-mono",
                  sortValue: (a) => a.linux_user,
                  filter: "text",
                  cell: (a) => <>{a.linux_user}</>,
                },
                {
                  key: "passkeys",
                  label: t("accounts.passkeys"),
                  sortValue: (a) => a.passkeys,
                  cell: (a) => <>{a.passkeys}</>,
                },
                {
                  key: "sessions",
                  label: t("accounts.sessions"),
                  sortValue: (a) => a.sessions,
                  cell: (a) => <>{a.sessions}</>,
                },
                {
                  key: "status",
                  label: t("accounts.status"),
                  sortValue: (a) => (a.disabled ? "disabled" : a.invited ? "invited" : "active"),
                  filter: { options: ["active", "invited", "disabled"].map((s) => ({ value: s, label: t(`accounts.${s}`) })) },
                  cell: (a) => (
                    <>
                      {a.disabled ? (
                        <span className="text-bad">{t("accounts.disabled")}</span>
                      ) : a.invited ? (
                        <span className="text-warn">{t("accounts.invited")}</span>
                      ) : (
                        <span className="text-ok">{t("accounts.active")}</span>
                      )}
                    </>
                  ),
                },
                {
                  key: "actions",
                  label: t("common.actions"),
                  tdClass: "text-right align-top",
                  srOnly: true,
                  cell: (a) => (
                    <>
                      {!a.self && (
                        <div className="flex flex-wrap justify-end gap-2">
                          {a.invited && !a.disabled && (
                            <button
                              type="button"
                              className="btn btn-secondary min-h-9"
                              disabled={busy}
                              onClick={() => void act(async () => showInvite(await withStepUp(() => api<InviteResult>("POST", `/accounts/${id(a)}/reinvite`))))}
                            >
                              {t("accounts.reinvite")}
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-secondary min-h-9"
                            disabled={busy}
                            onClick={() => void act(() => withStepUp(() => api("PATCH", `/accounts/${id(a)}/disabled`, { disabled: !a.disabled })))}
                          >
                            {a.disabled ? t("accounts.enable") : t("accounts.disable")}
                          </button>
                          <button
                            type="button"
                            className="btn btn-danger min-h-9"
                            disabled={busy}
                            onClick={() => {
                              setDeleting(a.id);
                              setConfirm("");
                            }}
                          >
                            {t("common.remove")}
                          </button>
                        </div>
                      )}
                      {deleting === a.id && (
                        <form
                          className="mt-3 flex flex-col items-end gap-2"
                          onSubmit={(e) => {
                            e.preventDefault();
                            void act(async () => {
                              await withStepUp(() => api("DELETE", `/accounts/${id(a)}`, { confirm_name: confirm }));
                              setDeleting(undefined);
                            });
                          }}
                        >
                          <label className="text-left text-muted">
                            {t("accounts.confirmDelete", { name: a.name })}
                            <input className="input mt-1" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
                          </label>
                          <div className="flex gap-2">
                            <button type="button" className="btn btn-secondary min-h-9" onClick={() => setDeleting(undefined)}>
                              {t("common.cancel")}
                            </button>
                            <button className="btn btn-danger min-h-9" disabled={busy || confirm !== a.name}>
                              {t("accounts.deleteNow")}
                            </button>
                          </div>
                        </form>
                      )}
                    </>
                  ),
                },
              ]}
            />
          </div>
        )}
      </Panel>
    </div>
  );
}
