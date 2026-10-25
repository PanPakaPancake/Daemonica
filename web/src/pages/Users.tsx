import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Link } from "react-router";
import { Icon } from "../components/icons";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import { DataTable } from "../components/DataTable";

interface LinuxUser {
  name: string;
  uid: number;
  gid: number;
  gecos: string;
  home: string;
  shell: string;
  groups: string[];
  system: boolean;
  locked: boolean;
  no_password: boolean;
  expired: boolean;
  expires_on?: string;
  pw_changed?: string;
  pw_max_days?: number;
  must_change: boolean;
  sudo: boolean;
  key_count: number;
  dashboard_accounts?: string[];
  admin_mapped: boolean;
}
interface Group {
  name: string;
  gid: number;
  members: string[];
  system: boolean;
}
interface Listing {
  users: LinuxUser[];
  groups: Group[];
  shells: string[];
}

type Dlg =
  | { kind: "create" }
  | { kind: "edit"; user: LinuxUser }
  | { kind: "password"; user: LinuxUser }
  | { kind: "delete"; user: LinuxUser }
  | { kind: "group"; group?: Group }
  | undefined;

export function Users() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { me, withStepUp } = useSession();
  const isAdmin = me?.role === "admin";
  const [advanced, setAdvanced] = useState(false);
  const [tab, setTab] = useState<"users" | "groups">("users");
  const [dlg, setDlg] = useState<Dlg>();
  const [err, setErr] = useState<string>();
  const [ok, setOk] = useState<string>();
  const q = useQuery({ queryKey: ["linux-users"], queryFn: () => api<Listing>("POST", "/users/list") });

  const users = useMemo(() => (q.data?.users ?? []).filter((u) => advanced || !u.system), [q.data, advanced]);
  const groups = useMemo(() => (q.data?.groups ?? []).filter((g) => advanced || !g.system || g.name === "sudo"), [q.data, advanced]);

  // Runs a change with step-up; mapped-admin protection asks for an extra confirmation.
  const change = async (op: string, body: Record<string, unknown>, done?: string) => {
    setErr(undefined);
    setOk(undefined);
    try {
      await withStepUp(() => api("POST", `/users/${op}`, { ...body, ...(advanced && { advanced: true }) }));
      await qc.invalidateQueries({ queryKey: ["linux-users"] });
      if (done) setOk(done);
      return true;
    } catch (e) {
      setErr(errorText(t, e));
      return false;
    }
  };

  const guarded = (u: LinuxUser, op: string, body: Record<string, unknown>, done: string) => {
    if (u.admin_mapped && !window.confirm(t("users.adminMappedWarning", { name: u.name }))) return;
    void change(op, { name: u.name, ...body, ...(u.admin_mapped && { confirm_mapped: true }) }, done);
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{t("users.title")}</h1>
          <p className="mt-1 text-muted">{t("users.intro")}</p>
        </div>
        {isAdmin && (
          <div className="flex gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setDlg({ kind: "group" })}>
              {t("users.newGroup")}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setDlg({ kind: "create" })}>
              <Icon name="users" className="h-4 w-4" />
              {t("users.newUser")}
            </button>
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="tablist" className="flex gap-1 border-b border-line">
          {(["users", "groups"] as const).map((x) => (
            <button
              key={x}
              role="tab"
              type="button"
              aria-selected={tab === x}
              className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
              onClick={() => setTab(x)}
            >
              {t(`users.tab.${x}`)}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={advanced} onChange={(e) => setAdvanced(e.target.checked)} />
          <span>{t("users.advanced")}</span>
        </label>
      </div>

      {ok && <Notice tone="ok">{ok}</Notice>}
      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}

      {tab === "users" && (
        <Panel className="p-0">
          <div className="overflow-x-auto">
            <DataTable
              rows={q.data ? users : undefined}
              rowKey={(u) => u.name}
              loading={q.isLoading}
              label={t("users.title")}
              defaultSort={{ key: "uid", desc: false }}
              columns={[
                {
                  key: "name",
                  label: t("users.name"),
                  tdClass: "align-top",
                  sortValue: (u) => u.name,
                  filterValue: (u) => `${u.name} ${u.gecos ?? ""} ${u.home} ${u.shell}`,
                  filter: "text",
                  cell: (u) => (
                    <>
                      <span className="font-mono font-semibold">{u.name}</span>
                      {u.gecos && <span className="block text-xs text-muted">{u.gecos}</span>}
                      <span className="block text-xs text-faint">
                        {u.home} · {u.shell}
                      </span>
                      {u.dashboard_accounts && u.dashboard_accounts.length > 0 && (
                        <span className="mt-1 inline-flex items-center gap-1 rounded-full border border-cyan px-2 text-xs text-cyan">
                          <Icon name="shield" className="h-3 w-3" />
                          {t("users.mapped", { accounts: u.dashboard_accounts.join(", ") })}
                        </span>
                      )}
                    </>
                  ),
                },
                {
                  key: "uid",
                  label: "UID",
                  tdClass: "tabular-nums align-top",
                  sortValue: (u) => u.uid,
                  filterValue: (u) => String(u.uid),
                  filter: "text",
                  cell: (u) => <>{u.uid}</>,
                },
                {
                  key: "groups",
                  label: t("users.groups"),
                  thClass: "hidden md:table-cell",
                  tdClass: "hidden md:table-cell align-top",
                  sortValue: (u) => u.groups.join(", "),
                  filter: "text",
                  cell: (u) => (
                    <>
                      <span className="flex flex-wrap gap-1">
                        {u.groups.map((g) => (
                          <span
                            key={g}
                            className={`rounded-full border px-1.5 text-xs ${g === "sudo" || g === "admin" ? "border-warn text-warn" : "border-line text-muted"}`}
                          >
                            {g}
                          </span>
                        ))}
                      </span>
                    </>
                  ),
                },
                {
                  key: "status",
                  label: t("users.status"),
                  tdClass: "align-top",
                  sortValue: (u) =>
                    statusList(u, t)
                      .map((x) => x.text)
                      .join(", "),
                  filter: "text",
                  cell: (u) => (
                    <>
                      <StatusBadges u={u} />
                    </>
                  ),
                },
                {
                  key: "keys",
                  label: t("users.keys"),
                  thClass: "hidden lg:table-cell",
                  tdClass: "hidden lg:table-cell align-top",
                  sortValue: (u) => (u.key_count >= 0 ? u.key_count : undefined),
                  cell: (u) => (
                    <>
                      {u.key_count >= 0 ? (
                        <Link to={`/ssh-keys?user=${encodeURIComponent(u.name)}`} className="text-violet underline">
                          {t("users.keyCount", { count: u.key_count })}
                        </Link>
                      ) : (
                        "–"
                      )}
                    </>
                  ),
                },
                {
                  key: "actions",
                  label: t("services.actions"),
                  thClass: "text-right",
                  tdClass: "align-top",
                  cell: (u) => (
                    <>
                      {isAdmin && (
                        <div className="flex flex-wrap justify-end gap-1">
                          <SmallBtn label={t("users.edit")} onClick={() => setDlg({ kind: "edit", user: u })} />
                          {u.uid !== 0 && (
                            <SmallBtn
                              label={u.sudo ? t("users.revokeSudo") : t("users.grantSudo")}
                              warn
                              onClick={() => {
                                if (!window.confirm(u.sudo ? t("users.revokeSudoConfirm", { name: u.name }) : t("users.grantSudoConfirm", { name: u.name })))
                                  return;
                                guarded(u, "set_sudo", { sudo: !u.sudo }, t("users.done"));
                              }}
                            />
                          )}
                          {u.uid !== 0 && (
                            <SmallBtn
                              label={isLocked(u) ? t("users.unlock") : t("users.lock")}
                              onClick={() => guarded(u, "set_locked", { locked: !isLocked(u) }, t("users.done"))}
                            />
                          )}
                          <SmallBtn label={t("users.password")} onClick={() => setDlg({ kind: "password", user: u })} />
                          {u.uid !== 0 && <SmallBtn label={t("common.remove")} danger onClick={() => setDlg({ kind: "delete", user: u })} />}
                        </div>
                      )}
                    </>
                  ),
                },
              ]}
            />
          </div>
        </Panel>
      )}

      {tab === "groups" && (
        <Panel className="p-0">
          <DataTable
            rows={q.data ? groups : undefined}
            rowKey={(g) => g.name}
            label={t("users.group")}
            defaultSort={{ key: "name", desc: false }}
            columns={[
              {
                key: "name",
                label: t("users.group"),
                tdClass: "font-mono",
                sortValue: (g) => g.name,
                filter: "text",
                cell: (g) => <>{g.name}</>,
              },
              {
                key: "gid",
                label: "GID",
                tdClass: "tabular-nums",
                sortValue: (g) => g.gid,
                cell: (g) => <>{g.gid}</>,
              },
              {
                key: "members",
                label: t("users.members"),
                tdClass: "text-muted",
                sortValue: (g) => g.members.join(", "),
                filter: "text",
                cell: (g) => <>{g.members.join(", ") || "–"}</>,
              },
              {
                key: "actions",
                label: t("common.actions"),
                tdClass: "text-right",
                srOnly: true,
                cell: (g) => (
                  <>
                    {isAdmin && g.name !== "sudo" && g.name !== "admin" && (
                      <SmallBtn label={t("users.edit")} onClick={() => setDlg({ kind: "group", group: g })} />
                    )}
                  </>
                ),
              },
            ]}
          />
        </Panel>
      )}

      {dlg?.kind === "create" && q.data && (
        <CreateDialog
          shells={q.data.shells}
          groups={q.data.groups.filter((g) => !g.system && g.name !== "sudo")}
          onClose={() => setDlg(undefined)}
          onSubmit={async (body) => {
            const ok2 = await change("create", body, t("users.created", { name: body.name }));
            if (ok2) setDlg(undefined);
          }}
        />
      )}
      {dlg?.kind === "edit" && q.data && (
        <EditDialog
          user={dlg.user}
          shells={q.data.shells}
          groups={q.data.groups.filter((g) => g.name !== "sudo" && g.name !== "admin" && (advanced || !g.system))}
          onClose={() => setDlg(undefined)}
          onSubmit={async (body) => {
            const keepSudo = dlg.user.groups.filter((g) => g === "sudo" || g === "admin");
            const groups = Array.isArray(body.groups) ? { groups: [...(body.groups as string[]), ...keepSudo] } : {};
            const ok2 = await change("update", { name: dlg.user.name, ...body, ...groups }, t("users.done"));
            if (ok2) setDlg(undefined);
          }}
        />
      )}
      {dlg?.kind === "password" && (
        <PasswordDialog
          user={dlg.user}
          onClose={() => setDlg(undefined)}
          onSubmit={async (password, force) => {
            const ok2 = await change("set_password", { name: dlg.user.name, password, force_change: force }, t("users.passwordSet"));
            if (ok2) setDlg(undefined);
          }}
        />
      )}
      {dlg?.kind === "delete" && (
        <DeleteDialog
          user={dlg.user}
          onClose={() => setDlg(undefined)}
          onSubmit={async (removeHome) => {
            const ok2 = await change(
              "delete",
              { name: dlg.user.name, confirm_name: dlg.user.name, remove_home: removeHome, ...(dlg.user.admin_mapped && { confirm_mapped: true }) },
              t("users.deleted", { name: dlg.user.name }),
            );
            if (ok2) setDlg(undefined);
          }}
        />
      )}
      {dlg?.kind === "group" && q.data && (
        <GroupDialog
          group={dlg.group}
          users={q.data.users.filter((u) => !u.system)}
          onClose={() => setDlg(undefined)}
          onCreate={async (name) => {
            const ok2 = await change("groups/create", { name }, t("users.done"));
            if (ok2) setDlg(undefined);
          }}
          onMembers={async (members) => {
            const ok2 = await change("groups/set_members", { name: dlg.group?.name, members }, t("users.done"));
            if (ok2) setDlg(undefined);
          }}
          onDelete={async () => {
            const g = dlg.group;
            if (!g || window.prompt(t("users.typeToConfirm", { name: g.name })) !== g.name) return;
            const ok2 = await change("groups/delete", { name: g.name, confirm_name: g.name }, t("users.done"));
            if (ok2) setDlg(undefined);
          }}
        />
      )}
    </div>
  );
}

/** An account counts as locked when it is expired or has a locked (but existing) password. */
const isLocked = (u: LinuxUser) => u.expired || (u.locked && !u.no_password);

function statusList(u: LinuxUser, t: TFunction) {
  const b: { tone: string; icon: string; text: string }[] = [];
  if (u.expired) b.push({ tone: "text-bad", icon: "✖", text: t("users.st.expired") });
  else if (u.locked && !u.no_password) b.push({ tone: "text-warn", icon: "⚠", text: t("users.st.pwLocked") });
  if (u.no_password && !u.expired) b.push({ tone: "text-muted", icon: "○", text: t("users.st.keyOnly") });
  if (u.must_change) b.push({ tone: "text-warn", icon: "⚠", text: t("users.st.mustChange") });
  if (u.sudo || u.uid === 0) b.push({ tone: "text-warn", icon: "★", text: u.uid === 0 ? "root" : "sudo" });
  if (!b.length) b.push({ tone: "text-ok", icon: "✓", text: t("users.st.active") });
  return b;
}

function StatusBadges({ u }: { u: LinuxUser }) {
  const { t } = useTranslation();
  const b = statusList(u, t);
  return (
    <span className="flex flex-col gap-0.5 text-xs">
      {b.map((x) => (
        <span key={x.text} className={x.tone}>
          <span aria-hidden="true">{x.icon} </span>
          {x.text}
        </span>
      ))}
    </span>
  );
}

function SmallBtn({ label, onClick, danger, warn }: { label: string; onClick: () => void; danger?: boolean; warn?: boolean }) {
  return (
    <button type="button" className={`btn min-h-8 px-2 text-xs ${danger ? "btn-danger" : "btn-secondary"} ${warn ? "text-warn" : ""}`} onClick={onClick}>
      {label}
    </button>
  );
}

function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  const { t } = useTranslation();
  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
        <Dialog.Content
          className={`panel panel-edge fixed left-1/2 top-1/2 z-50 max-h-[90vh] -translate-x-1/2 -translate-y-1/2 overflow-auto p-6 ${wide ? "w-[min(94vw,640px)]" : "w-[min(94vw,480px)]"}`}
          aria-describedby={undefined}
        >
          <div className="mb-4 flex items-start justify-between gap-3">
            <Dialog.Title className="text-lg font-semibold">{title}</Dialog.Title>
            <Dialog.Close className="btn btn-secondary min-h-8 px-2" aria-label={t("common.close")}>
              <Icon name="close" className="h-4 w-4" />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

const nameRE = /^[a-z_][a-z0-9_-]{0,31}$/;

function CreateDialog({
  shells,
  groups,
  onClose,
  onSubmit,
}: {
  shells: string[];
  groups: Group[];
  onClose: () => void;
  onSubmit: (b: { name: string; gecos?: string; shell: string; groups: string[]; create_home: boolean }) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [gecos, setGecos] = useState("");
  const [shell, setShell] = useState(shells.includes("/bin/bash") ? "/bin/bash" : (shells[0] ?? ""));
  const [sel, setSel] = useState<string[]>([]);
  const [home, setHome] = useState(true);
  const valid = nameRE.test(name);
  return (
    <Modal title={t("users.newUser")} onClose={onClose}>
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit({ name, ...(gecos && { gecos }), shell, groups: sel, create_home: home });
        }}
      >
        <Field label={t("users.name")} help={t("users.nameHelp")} error={name && !valid ? t("users.nameInvalid") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" required />}
        </Field>
        <Field label={t("users.description")}>
          {(p) => <input {...p} className="input" value={gecos} onChange={(e) => setGecos(e.target.value.replace(/[:,]/g, ""))} maxLength={128} />}
        </Field>
        <Field label={t("users.shell")}>
          {(p) => (
            <select {...p} className="input" value={shell} onChange={(e) => setShell(e.target.value)}>
              {shells.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          )}
        </Field>
        <GroupPicker groups={groups} selected={sel} onChange={setSel} />
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={home} onChange={(e) => setHome(e.target.checked)} />
          <span>{t("users.createHome")}</span>
        </label>
        <Explain>{t("users.createExplain")}</Explain>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button className="btn btn-primary" disabled={!valid}>
            {t("users.create")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function GroupPicker({ groups, selected, onChange }: { groups: Group[]; selected: string[]; onChange: (g: string[]) => void }) {
  const { t } = useTranslation();
  return (
    <fieldset className="flex flex-col gap-1">
      <legend className="mb-1 font-medium">{t("users.groups")}</legend>
      {groups.length === 0 && <p className="text-sm text-muted">{t("users.noGroups")}</p>}
      <div className="flex flex-wrap gap-2">
        {groups.map((g) => (
          <label key={g.name} className="flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 text-sm">
            <input
              type="checkbox"
              checked={selected.includes(g.name)}
              onChange={(e) => onChange(e.target.checked ? [...selected, g.name] : selected.filter((x) => x !== g.name))}
            />
            {g.name}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function EditDialog({
  user,
  shells,
  groups,
  onClose,
  onSubmit,
}: {
  user: LinuxUser;
  shells: string[];
  groups: Group[];
  onClose: () => void;
  onSubmit: (b: Record<string, unknown>) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [gecos, setGecos] = useState(user.gecos);
  const [shell, setShell] = useState(user.shell);
  const initial = user.groups.filter((g) => groups.some((x) => x.name === g) && g !== user.name);
  const [sel, setSel] = useState<string[]>(initial);
  // Locked accounts carry the expiry date 1970-01-02 (usermod --expiredate 1); that is not an editable date.
  const initialExpires = user.expires_on && user.expires_on !== "1970-01-02" ? user.expires_on : "";
  const [expires, setExpires] = useState(initialExpires);
  const body: Record<string, unknown> = {};
  if (gecos !== user.gecos) body.gecos = gecos;
  if (shell !== user.shell) body.shell = shell;
  if (sel.slice().sort().join() !== initial.slice().sort().join()) {
    body.set_groups = true;
    body.groups = sel;
  }
  if (expires !== initialExpires) body.expires = expires;
  return (
    <Modal title={t("users.editTitle", { name: user.name })} onClose={onClose}>
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit(body);
        }}
      >
        <Field label={t("users.description")}>
          {(p) => <input {...p} className="input" value={gecos} onChange={(e) => setGecos(e.target.value.replace(/[:,]/g, ""))} maxLength={128} />}
        </Field>
        <Field label={t("users.shell")}>
          {(p) => (
            <select {...p} className="input" value={shell} onChange={(e) => setShell(e.target.value)}>
              {!shells.includes(user.shell) && <option>{user.shell}</option>}
              {shells.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          )}
        </Field>
        <GroupPicker groups={groups.filter((g) => g.name !== user.name)} selected={sel} onChange={setSel} />
        <Field label={t("users.expires")} help={t("users.expiresHelp")}>
          {(p) => <input {...p} type="date" className="input" value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </Field>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button className="btn btn-primary" disabled={Object.keys(body).length === 0}>
            {t("common.save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function strength(pw: string): number {
  let s = 0;
  if (pw.length >= 12) s++;
  if (pw.length >= 16) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s);
}

function PasswordDialog({ user, onClose, onSubmit }: { user: LinuxUser; onClose: () => void; onSubmit: (pw: string, force: boolean) => Promise<void> }) {
  const { t } = useTranslation();
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [force, setForce] = useState(true);
  const s = strength(pw);
  const valid = [...pw].length >= 12 && pw === pw2 && !/[\n:]/.test(pw);
  return (
    <Modal title={t("users.passwordTitle", { name: user.name })} onClose={onClose}>
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void onSubmit(pw, force);
        }}
      >
        <Notice tone="info">{t("users.passwordHint")}</Notice>
        <Field label={t("users.newPassword")} help={t("users.strength", { level: t(`users.strengthLevel.${s}`) })}>
          {(p) => <input {...p} type="password" className="input" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />}
        </Field>
        <Field label={t("users.repeatPassword")} error={pw2 && pw !== pw2 ? t("users.mismatch") : undefined}>
          {(p) => <input {...p} type="password" className="input" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />}
        </Field>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
          <span>{t("users.forceChange")}</span>
        </label>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button className="btn btn-primary" disabled={!valid}>
            {t("common.save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteDialog({ user, onClose, onSubmit }: { user: LinuxUser; onClose: () => void; onSubmit: (removeHome: boolean) => Promise<void> }) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState("");
  const [removeHome, setRemoveHome] = useState(false);
  return (
    <Modal title={t("users.deleteTitle", { name: user.name })} onClose={onClose}>
      <div className="flex flex-col gap-4">
        <Notice tone="bad">{t("users.deleteWarning")}</Notice>
        {user.admin_mapped && <Notice tone="bad">{t("users.adminMappedWarning", { name: user.name })}</Notice>}
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={removeHome} onChange={(e) => setRemoveHome(e.target.checked)} />
          <span>{t("users.removeHome", { home: user.home })}</span>
        </label>
        <Field label={t("users.typeToConfirm", { name: user.name })}>
          {(p) => <input {...p} className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />}
        </Field>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn btn-danger" disabled={typed !== user.name} onClick={() => void onSubmit(removeHome)}>
            {t("common.remove")}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function GroupDialog({
  group,
  users,
  onClose,
  onCreate,
  onMembers,
  onDelete,
}: {
  group?: Group;
  users: LinuxUser[];
  onClose: () => void;
  onCreate: (name: string) => Promise<void>;
  onMembers: (m: string[]) => Promise<void>;
  onDelete: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [members, setMembers] = useState<string[]>(group?.members ?? []);
  if (!group) {
    return (
      <Modal title={t("users.newGroup")} onClose={onClose}>
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void onCreate(name);
          }}
        >
          <Field label={t("users.group")} error={name && !nameRE.test(name) ? t("users.nameInvalid") : undefined}>
            {(p) => <input {...p} className="input font-mono" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />}
          </Field>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              {t("common.cancel")}
            </button>
            <button className="btn btn-primary" disabled={!nameRE.test(name)}>
              {t("users.create")}
            </button>
          </div>
        </form>
      </Modal>
    );
  }
  return (
    <Modal title={t("users.groupTitle", { name: group.name })} onClose={onClose}>
      <div className="flex flex-col gap-4">
        <fieldset className="flex flex-wrap gap-2">
          <legend className="mb-1 font-medium">{t("users.members")}</legend>
          {users.map((u) => (
            <label key={u.name} className="flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 text-sm">
              <input
                type="checkbox"
                checked={members.includes(u.name)}
                onChange={(e) => setMembers(e.target.checked ? [...members, u.name] : members.filter((x) => x !== u.name))}
              />
              {u.name}
            </label>
          ))}
        </fieldset>
        <div className="flex justify-between gap-2">
          <button type="button" className="btn btn-danger" onClick={() => void onDelete()}>
            {t("users.deleteGroup")}
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void onMembers(members)}>
            {t("common.save")}
          </button>
        </div>
      </div>
    </Modal>
  );
}
