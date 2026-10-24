import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { Icon } from "../components/icons";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";

interface Key {
  type: string;
  bits: number;
  fingerprint: string;
  comment: string;
  options?: string[];
  line: number;
}
interface Listing {
  user: string;
  keys: Key[];
  invalid_lines?: number[];
  write_path?: string;
  read_only: boolean;
  problems?: string[];
}
interface ServerInfo {
  host_keys: { file: string; type: string; fingerprint: string }[];
  sshd: { key: string; value: string }[] | null;
}

// Options offered by the guided "restrict access" form (authorized_keys(5)).
const flagOpts = ["restrict", "no-port-forwarding", "no-agent-forwarding", "no-X11-forwarding", "no-pty"] as const;

export function SSHKeys() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { me, withStepUp } = useSession();
  const [params, setParams] = useSearchParams();
  const user = params.get("user") ?? me?.linux_user ?? "";
  const [line, setLine] = useState("");
  const [from, setFrom] = useState("");
  const [flags, setFlags] = useState<string[]>([]);
  const [command, setCommand] = useState("");
  const [err, setErr] = useState<string>();
  const [ok, setOk] = useState<string>();
  const [busy, setBusy] = useState(false);

  const users = useQuery({
    queryKey: ["linux-users-names"],
    queryFn: () => api<{ users: { name: string; system: boolean; uid: number }[] }>("POST", "/users/list"),
    enabled: me?.role === "admin",
  });
  const q = useQuery({ queryKey: ["sshkeys", user], queryFn: () => api<Listing>("POST", "/ssh-keys/list", { user }), enabled: !!user });
  const srv = useQuery({ queryKey: ["sshd"], queryFn: () => api<ServerInfo>("GET", "/ssh-keys/server") });

  const options = () => {
    const o: string[] = [...flags];
    const f = from.trim();
    if (f) o.push(`from="${f.replace(/\s+/g, "")}"`);
    if (command.trim()) o.push(`command="${command.trim().replace(/"/g, '\\"')}"`);
    return o;
  };

  const act = async (op: string, body: Record<string, unknown>, done: string) => {
    setBusy(true);
    setErr(undefined);
    setOk(undefined);
    try {
      const l = await withStepUp(() => api<Listing>("POST", `/ssh-keys/${op}`, { user, ...body }));
      qc.setQueryData(["sshkeys", user], l);
      setOk(done);
      return true;
    } catch (e) {
      setErr(errorText(t, e));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const l = q.data;
  const canEdit = !!l && !l.read_only;
  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{t("sshkeys.title")}</h1>
          <p className="mt-1 text-muted">{t("sshkeys.intro")}</p>
        </div>
        {me?.role === "admin" && (
          <label className="flex flex-col gap-1">
            <span className="text-sm font-medium">{t("sshkeys.user")}</span>
            <select className="input header-select font-mono" value={user} onChange={(e) => setParams({ user: e.target.value })}>
              {(users.data?.users ?? [])
                .filter((u) => !u.system)
                .map((u) => (
                  <option key={u.name} value={u.name}>
                    {u.name}
                  </option>
                ))}
            </select>
          </label>
        )}
      </div>

      {ok && <Notice tone="ok">{ok}</Notice>}
      {err && <Notice tone="bad">{err}</Notice>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {l?.read_only && <Notice tone="warn">{t("sshkeys.readOnly")}</Notice>}
      {l && (l.problems?.length ?? 0) > 0 && (
        <Notice tone="warn">
          <p>{t("sshkeys.problems")}</p>
          <ul className="mt-1 list-inside list-disc text-sm text-muted">
            {l.problems?.map((p) => (
              <li key={p} className="font-mono">
                {t(`sshkeys.problem.${p.split(":")[0]}`, { path: p.split(":").slice(1).join(":") })}
              </li>
            ))}
          </ul>
          <button
            type="button"
            className="btn btn-secondary mt-2 min-h-8"
            disabled={busy}
            onClick={() => void act("fix_permissions", {}, t("sshkeys.fixed"))}
          >
            {t("sshkeys.fix")}
          </button>
        </Notice>
      )}
      {l && (l.invalid_lines?.length ?? 0) > 0 && <Notice tone="info">{t("sshkeys.invalidLines", { lines: l.invalid_lines?.join(", ") })}</Notice>}

      <Panel className="p-0">
        <div className="flex items-center justify-between px-4 py-3">
          <h2 className="flex items-center gap-2 font-semibold">
            <Icon name="key" className="h-4 w-4 text-cyan" />
            {t("sshkeys.authorized", { user })}
          </h2>
          {l?.write_path && <span className="font-mono text-xs text-faint">~/{l.write_path}</span>}
        </div>
        {q.isLoading && <p className="px-4 pb-4 text-muted">{t("common.loading")}</p>}
        {l && l.keys.length === 0 && <p className="px-4 pb-4 text-muted">{t("sshkeys.none")}</p>}
        <ul>
          {l?.keys.map((k) => (
            <li key={k.fingerprint} className="flex flex-wrap items-start justify-between gap-3 border-t border-line px-4 py-3">
              <div className="min-w-0">
                <p className="font-semibold">{k.comment || t("sshkeys.noComment")}</p>
                <p className="text-sm text-muted">
                  {k.type} · {k.bits} Bit
                </p>
                <p className="break-all font-mono text-xs text-faint">{k.fingerprint}</p>
                {k.options && k.options.length > 0 && (
                  <p className="mt-1 flex flex-wrap gap-1">
                    {k.options.map((o) => (
                      <span key={o} className="break-all rounded-full border border-line px-1.5 font-mono text-xs text-muted">
                        {o}
                      </span>
                    ))}
                  </p>
                )}
              </div>
              {canEdit && (
                <button
                  type="button"
                  className="btn btn-danger min-h-8 px-2 text-xs"
                  disabled={busy}
                  onClick={() => {
                    if (window.confirm(t("sshkeys.confirmRemove", { name: k.comment || k.fingerprint }))) void act("remove", { fingerprint: k.fingerprint }, t("sshkeys.removed"));
                  }}
                >
                  {t("common.remove")}
                </button>
              )}
            </li>
          ))}
        </ul>
      </Panel>

      {canEdit && (
        <Panel>
          <h2 className="mb-3 font-semibold">{t("sshkeys.add")}</h2>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void act("add", { key: line.trim(), ...(options().length && { options: options() }) }, t("sshkeys.added")).then((d) => {
                if (d) {
                  setLine("");
                  setFrom("");
                  setFlags([]);
                  setCommand("");
                }
              });
            }}
          >
            <Field label={t("sshkeys.publicKey")} help={t("sshkeys.publicKeyHelp")}>
              {(p) => <textarea {...p} className="input" rows={3} value={line} onChange={(e) => setLine(e.target.value)} spellCheck={false} placeholder="ssh-ed25519 AAAA… user@laptop" />}
            </Field>
            <details className="rounded-[8px] border border-line px-4 py-2">
              <summary className="cursor-pointer font-medium">{t("sshkeys.restrict")}</summary>
              <div className="flex flex-col gap-3 pt-3">
                <Field label={t("sshkeys.from")} help={t("sshkeys.fromHelp")}>
                  {(p) => <input {...p} className="input font-mono" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="203.0.113.7,10.0.0.0/8" />}
                </Field>
                <div className="flex flex-wrap gap-2">
                  {flagOpts.map((f) => (
                    <label key={f} className="flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 text-sm">
                      <input type="checkbox" checked={flags.includes(f)} onChange={(e) => setFlags(e.target.checked ? [...flags, f] : flags.filter((x) => x !== f))} />
                      <span className="font-mono">{f}</span>
                    </label>
                  ))}
                </div>
                <Field label={t("sshkeys.command")}>
                  {(p) => <input {...p} className="input font-mono" value={command} onChange={(e) => setCommand(e.target.value)} />}
                </Field>
                {command && <Notice tone="warn">{t("sshkeys.commandWarning")}</Notice>}
              </div>
            </details>
            <Explain>{t("sshkeys.explain")}</Explain>
            <div className="flex justify-end">
              <button className="btn btn-primary" disabled={busy || !line.trim()}>
                {t("sshkeys.add")}
              </button>
            </div>
          </form>
        </Panel>
      )}

      <Panel>
        <h2 className="mb-2 flex items-center gap-2 font-semibold">
          <Icon name="shield" className="h-4 w-4 text-cyan" />
          {t("sshkeys.hostKeys")}
        </h2>
        <p className="mb-3 text-sm text-muted">{t("sshkeys.hostKeysHelp")}</p>
        <table className="w-full text-left text-sm">
          <tbody>
            {(srv.data?.host_keys ?? []).map((h) => (
              <tr key={h.file} className="border-t border-line">
                <td className="py-1.5 pr-3 font-mono">{h.type}</td>
                <td className="break-all py-1.5 font-mono text-xs">{h.fingerprint}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <details className="mt-4">
          <summary className="cursor-pointer font-medium">{t("sshkeys.sshdConfig")}</summary>
          <p className="mt-2 text-sm text-muted">{t("sshkeys.sshdReadOnly")}</p>
          <div className="mt-2 max-h-80 overflow-auto rounded-[8px] border border-line">
            <table className="w-full text-left font-mono text-xs">
              <tbody>
                {(srv.data?.sshd ?? []).map((s, i) => (
                  <tr key={`${s.key}-${i}`} className="border-t border-line first:border-t-0">
                    <td className="px-3 py-1 text-violet">{s.key}</td>
                    <td className="break-all px-3 py-1">{s.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      </Panel>
    </div>
  );
}
