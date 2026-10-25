// Script library tab of the jobs page (DEC-030): local scripts and GitHub
// collections pinned to a commit; updates show the diff and need a passkey.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { DiffView } from "../components/ChangeFlow";
import type { CodeEditorHandle } from "../components/CodeEditor";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Field, Notice } from "../components/ui";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { bytes, dateTime, relative } from "../lib/format";
import type { Job } from "../lib/jobs";
import {
  interpreterFor,
  LOCAL,
  nameRE,
  normalizeRepo,
  shortSha,
  sourceIdRE,
  terminalCommand,
  type Candidate,
  type CandidateResult,
  type Content,
  type Library,
  type ScriptFile,
  type Source,
  type Spec,
} from "../lib/scripts";
import { useSession } from "../lib/session";

const CodeEditor = lazy(() => import("../components/CodeEditor").then((m) => ({ default: m.CodeEditor })));

type Done = (d: { msg: string; tone: "ok" | "bad" } | undefined) => void;

export function useLibrary(enabled = true) {
  return useQuery({ queryKey: ["scripts"], queryFn: () => api<Library>("GET", "/scripts"), enabled, staleTime: 10_000 });
}

/** A new job (script mode) for a library file. */
export function jobFor(f: ScriptFile, user: string): Job {
  const base = f.path.replace(/^.*\//, "").replace(/\.[^.]*$/, "");
  return {
    id: base
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48),
    description: f.path,
    mode: "script",
    script: f.abs,
    interpreter: interpreterFor(f),
    user,
    schedule: { kind: "daily", time: "03:00" },
    hardening: "safe",
    enabled: false,
  };
}

export function Scripts({ isAdmin, onDone, onSchedule }: { isAdmin: boolean; onDone: Done; onSchedule: (j: Job) => void }) {
  const { t, i18n } = useTranslation();
  const { me, withStepUp } = useSession();
  const qc = useQueryClient();
  const nav = useNavigate();
  const q = useLibrary();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["scripts"] });
  const [view, setView] = useState<ScriptFile>();
  const [edit, setEdit] = useState<{ file?: ScriptFile }>();
  const [delFile, setDelFile] = useState<ScriptFile>();
  const [adding, setAdding] = useState(false);
  const [check, setCheck] = useState<Source>();
  const [delSrc, setDelSrc] = useState<Source>();
  const files = q.data?.files ?? [];
  const sources = q.data?.sources ?? [];
  const canTerminal = me?.role === "admin" || me?.role === "operator";

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    onDone(undefined);
    try {
      await fn();
      onDone({ msg: ok, tone: "ok" });
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      refresh();
    }
  };
  const srcLabel = (id: string) => (id === LOCAL ? t("scripts.local") : id);

  const fileItems = (f: ScriptFile): MenuItem[] => {
    const local = f.source === LOCAL;
    const used = (f.used_by ?? []).length > 0;
    return [
      { label: t("scripts.view"), icon: "eye", onSelect: () => setView(f) },
      ...(local ? [{ label: t("common.edit"), icon: "edit" as const, disabled: !isAdmin, onSelect: () => setEdit({ file: f }) }] : []),
      { label: t("scripts.schedule"), icon: "clock", disabled: !isAdmin, onSelect: () => onSchedule(jobFor(f, me?.linux_user || "root")) },
      {
        label: t("scripts.runInTerminal"),
        icon: "terminal",
        disabled: !canTerminal,
        onSelect: () => void nav("/terminal", { state: { input: terminalCommand(f) } }),
      },
      { label: t("scripts.copyPath"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(f.abs).catch(() => undefined) },
      ...(local
        ? [
            {
              label: used ? t("scripts.inUse", { jobs: (f.used_by ?? []).join(", ") }) : t("common.delete"),
              icon: "trash" as const,
              danger: true,
              disabled: !isAdmin || used,
              onSelect: () => setDelFile(f),
            },
          ]
        : []),
    ];
  };

  const fileCols: Column<ScriptFile>[] = [
    {
      key: "path",
      label: t("scripts.col.file"),
      sortValue: (f) => f.path,
      filter: "text",
      cell: (f) => (
        <button type="button" className="text-left" onClick={() => setView(f)}>
          <span className="block font-mono">{f.path}</span>
          <span className="block font-mono text-xs text-faint">{f.abs}</span>
        </button>
      ),
    },
    {
      key: "source",
      label: t("scripts.col.source"),
      sortValue: (f) => srcLabel(f.source),
      filter: { options: [{ value: t("scripts.local"), label: t("scripts.local") }, ...sources.map((s) => ({ value: s.id, label: s.id }))] },
      cell: (f) => srcLabel(f.source),
    },
    {
      key: "shebang",
      label: t("scripts.col.interpreter"),
      sortValue: (f) => f.shebang ?? "",
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (f) => f.shebang ?? "–",
    },
    {
      key: "exec",
      label: t("scripts.col.exec"),
      sortValue: (f) => (f.exec ? "yes" : "no"),
      filter: {
        options: [
          { value: "yes", label: t("common.yes") },
          { value: "no", label: t("common.no") },
        ],
      },
      cell: (f) => (f.exec ? t("common.yes") : t("common.no")),
    },
    {
      key: "size",
      label: t("scripts.col.size"),
      sortValue: (f) => f.size,
      filter: "bytes",
      tdClass: "whitespace-nowrap",
      cell: (f) => bytes(f.size, i18n.language),
    },
    {
      key: "used",
      label: t("scripts.col.usedBy"),
      sortValue: (f) => (f.used_by ?? []).join(", "),
      filter: "text",
      cell: (f) => (f.used_by?.length ? <span className="font-mono text-xs">{f.used_by.join(", ")}</span> : "–"),
    },
    {
      key: "modified",
      label: t("scripts.col.modified"),
      sortValue: (f) => f.modified,
      filter: "date",
      tdClass: "whitespace-nowrap",
      tdTitle: (f) => dateTime(f.modified, i18n.language),
      cell: (f) => relative(f.modified, i18n.language),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (f) => <Menu label={t("scripts.actionsFor", { path: f.path })} items={fileItems(f)} />,
    },
  ];

  const srcItems = (s: Source): MenuItem[] => {
    const users = files.filter((f) => f.source === s.id).flatMap((f) => f.used_by ?? []);
    return [
      { label: t("scripts.checkUpdates"), icon: "download", disabled: !isAdmin, onSelect: () => setCheck(s) },
      {
        label: users.length ? t("scripts.inUse", { jobs: [...new Set(users)].join(", ") }) : t("scripts.removeSource"),
        icon: "trash",
        danger: true,
        disabled: !isAdmin || users.length > 0,
        onSelect: () => setDelSrc(s),
      },
    ];
  };

  const srcCols: Column<Source>[] = [
    {
      key: "id",
      label: t("scripts.col.source"),
      sortValue: (s) => s.id,
      filterValue: (s) => `${s.id} ${s.repo}`,
      filter: "text",
      cell: (s) => (
        <span>
          <span className="block font-medium">{s.id}</span>
          <a className="block font-mono text-xs text-faint underline" href={`https://github.com/${s.repo}`} target="_blank" rel="noreferrer noopener">
            github.com/{s.repo}
          </a>
        </span>
      ),
    },
    {
      key: "ref",
      label: t("scripts.col.ref"),
      sortValue: (s) => s.ref || "",
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (s) => s.ref || t("scripts.defaultBranch"),
    },
    {
      key: "subdir",
      label: t("scripts.col.subdir"),
      sortValue: (s) => s.subdir ?? "",
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (s) => s.subdir || "/",
    },
    {
      key: "commit",
      label: t("scripts.col.commit"),
      sortValue: (s) => s.commit.sha,
      filterValue: (s) => `${s.commit.sha} ${s.commit.message ?? ""}`,
      filter: "text",
      tdClass: "max-w-[22rem] truncate",
      tdTitle: (s) => `${s.commit.sha}\n${s.commit.message ?? ""}`,
      cell: (s) => (
        <span>
          <span className="font-mono text-xs">{shortSha(s.commit.sha)}</span> <span className="text-muted">{s.commit.message}</span>
        </span>
      ),
    },
    {
      key: "updated",
      label: t("scripts.col.updated"),
      sortValue: (s) => s.updated,
      filter: "date",
      tdClass: "whitespace-nowrap",
      tdTitle: (s) => dateTime(s.updated, i18n.language),
      cell: (s) => relative(s.updated, i18n.language),
    },
    {
      key: "token",
      label: t("scripts.col.access"),
      sortValue: (s) => (s.has_token ? "token" : "public"),
      filter: {
        options: [
          { value: "public", label: t("scripts.public") },
          { value: "token", label: t("scripts.withToken") },
        ],
      },
      cell: (s) => (s.has_token ? t("scripts.withToken") : t("scripts.public")),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (s) => <Menu label={t("scripts.actionsForSource", { id: s.id })} items={srcItems(s)} />,
    },
  ];

  return (
    <section className="flex flex-col gap-3 pt-4">
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted" title={t("scripts.intro", { root: q.data?.root ?? "" })}>
          {t("scripts.intro", { root: q.data?.root ?? "" })}
        </p>
        {isAdmin && (
          <>
            <button type="button" className="btn btn-primary min-h-9 shrink-0" onClick={() => setEdit({})}>
              <Icon name="filePlus" className="h-4 w-4" />
              {t("scripts.new")}
            </button>
            <button type="button" className="btn btn-secondary min-h-9 shrink-0" onClick={() => setAdding(true)}>
              <Icon name="link" className="h-4 w-4" />
              {t("scripts.addSource")}
            </button>
          </>
        )}
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" title={t("common.refresh")} onClick={refresh}>
          <Icon name="restart" className="h-4 w-4" />
          <span className="sr-only">{t("common.refresh")}</span>
        </button>
      </div>
      {sources.length > 0 && (
        <div className="relative overflow-x-auto">
          <DataTable
            label={t("scripts.sources")}
            columns={srcCols}
            rows={sources}
            rowKey={(s) => s.id}
            loading={q.isLoading}
            defaultSort={{ key: "id", desc: false }}
            className="min-w-[900px]"
            rowMenu={(s) => ({ label: t("scripts.actionsForSource", { id: s.id }), items: srcItems(s) })}
          />
        </div>
      )}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("scripts.files")}
          columns={fileCols}
          rows={files}
          rowKey={(f) => `${f.source}/${f.path}`}
          loading={q.isLoading}
          defaultSort={{ key: "path", desc: false }}
          className="min-w-[1000px]"
          rowMenu={(f) => ({ label: t("scripts.actionsFor", { path: f.path }), items: fileItems(f) })}
          empty={t("scripts.empty")}
        />
      </div>

      {view && <Viewer file={view} onClose={() => setView(undefined)} />}
      {edit && (
        <LocalEditor
          file={edit.file}
          taken={files.filter((f) => f.source === LOCAL).map((f) => f.path)}
          onClose={() => setEdit(undefined)}
          onSaved={(name, created) => {
            setEdit(undefined);
            onDone({ msg: t(created ? "scripts.created" : "scripts.saved", { name }), tone: "ok" });
            refresh();
          }}
        />
      )}
      {adding && (
        <AddSource
          onClose={() => setAdding(false)}
          onAdded={(s) => {
            setAdding(false);
            onDone({ msg: t("scripts.sourceAdded", { id: s.id, sha: shortSha(s.commit.sha) }), tone: "ok" });
            refresh();
          }}
        />
      )}
      {check && (
        <UpdateCheck
          source={check}
          onClose={() => setCheck(undefined)}
          onUpdated={(s) => {
            setCheck(undefined);
            onDone({ msg: t("scripts.sourceUpdated", { id: s.id, sha: shortSha(s.commit.sha) }), tone: "ok" });
            refresh();
          }}
        />
      )}
      {delFile && (
        <Confirm
          title={t("scripts.deleteTitle")}
          text={t("scripts.deleteConfirm", { path: delFile.abs })}
          onClose={() => setDelFile(undefined)}
          onConfirm={() => {
            const f = delFile;
            setDelFile(undefined);
            void act(() => withStepUp(() => api("POST", "/scripts/delete", { name: f.path })), t("scripts.deleted", { name: f.path }));
          }}
        />
      )}
      {delSrc && (
        <Confirm
          title={t("scripts.removeSource")}
          text={t("scripts.removeConfirm", { id: delSrc.id, dir: `${q.data?.root ?? ""}/${delSrc.id}` })}
          onClose={() => setDelSrc(undefined)}
          onConfirm={() => {
            const s = delSrc;
            setDelSrc(undefined);
            void act(() => withStepUp(() => api("POST", "/scripts/remove", { id: s.id })), t("scripts.removed", { id: s.id }));
          }}
        />
      )}
    </section>
  );
}

function Confirm({ title, text, onClose, onConfirm }: { title: string; text: string; onClose: () => void; onConfirm: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal title={title} onClose={onClose}>
      <p className="break-words">{text}</p>
      <div className="mt-6 flex justify-end gap-2">
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          {t("common.cancel")}
        </button>
        <button type="button" className="btn btn-danger" onClick={onConfirm}>
          <Icon name="trash" className="h-4 w-4" />
          {t("common.delete")}
        </button>
      </div>
    </Modal>
  );
}

function Viewer({ file, onClose }: { file: ScriptFile; onClose: () => void }) {
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["script", file.source, file.path, file.sha256],
    queryFn: () => api<Content>("POST", "/scripts/read", { source: file.source, path: file.path }),
  });
  return (
    <Modal title={file.path} onClose={onClose} wide>
      <p className="mb-3 font-mono text-xs text-faint break-all">
        {file.abs} · sha256 {file.sha256.slice(0, 16)}…
      </p>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {q.isLoading && <p className="text-muted">{t("common.loading")}</p>}
      {q.data && !q.data.text && <Notice tone="info">{q.data.size < 0 ? t("scripts.tooLarge") : t("scripts.binary")}</Notice>}
      {q.data?.text && (
        <div className="h-[60vh] overflow-hidden rounded-[8px] border border-line">
          <Suspense fallback={<p className="text-muted">{t("common.loading")}</p>}>
            <CodeEditor
              initial={q.data.content ?? ""}
              path={file.path}
              wrap={false}
              tabSize={4}
              readOnly
              label={file.path}
              onDirty={() => undefined}
              onSave={() => undefined}
              onCursor={() => undefined}
            />
          </Suspense>
        </div>
      )}
    </Modal>
  );
}

const template = "#!/bin/bash\nset -euo pipefail\n\n";

function LocalEditor({
  file,
  taken,
  onClose,
  onSaved,
}: {
  file?: ScriptFile;
  taken: string[];
  onClose: () => void;
  onSaved: (name: string, created: boolean) => void;
}) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const create = !file;
  const [name, setName] = useState(file?.path ?? "");
  const [exec, setExec] = useState(file?.exec ?? true);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [touched, setTouched] = useState(false);
  const editor = useRef<CodeEditorHandle>(null);
  const q = useQuery({
    queryKey: ["script", LOCAL, file?.path, file?.sha256],
    queryFn: () => api<Content>("POST", "/scripts/read", { source: LOCAL, path: file?.path }),
    enabled: !create,
  });
  const nameErr = !nameRE.test(name) ? t("scripts.err.name") : create && taken.includes(name) ? t("scripts.err.taken") : undefined;

  const save = async () => {
    setTouched(true);
    if (nameErr) return;
    const content = editor.current?.getText() ?? "";
    if (new TextEncoder().encode(content).length > 128 * 1024) {
      setErr(t("scripts.err.size"));
      return;
    }
    setBusy(true);
    setErr(undefined);
    try {
      await withStepUp(() => api("POST", "/scripts/save", { name, content, exec, hash: create ? "" : q.data?.hash }));
      onSaved(name, create);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const ready = create || q.data?.text;
  return (
    <Modal title={create ? t("scripts.new") : t("scripts.editTitle", { name: file.path })} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        {create && (
          <Field label={t("scripts.name")} help={t("scripts.nameHelp")} error={touched ? nameErr : undefined}>
            {(p) => <input {...p} className="input font-mono" value={name} maxLength={128} placeholder="backup.sh" onChange={(e) => setName(e.target.value)} />}
          </Field>
        )}
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={exec} onChange={(e) => setExec(e.target.checked)} />
          {t("scripts.execLabel")}
        </label>
        {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
        {ready && (
          <div className="h-[50vh] overflow-hidden rounded-[8px] border border-line">
            <Suspense fallback={<p className="text-muted">{t("common.loading")}</p>}>
              <CodeEditor
                ref={editor}
                initial={create ? template : (q.data?.content ?? "")}
                path={name || "script.sh"}
                wrap={false}
                tabSize={4}
                readOnly={false}
                label={t("scripts.content")}
                onDirty={() => undefined}
                onSave={() => void save()}
                onCursor={() => undefined}
              />
            </Suspense>
          </div>
        )}
        <Notice tone="info">{t("scripts.rootNote")}</Notice>
        {err && (
          <Notice tone="bad" live>
            {err}
          </Notice>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="btn btn-primary" disabled={busy || !ready} onClick={() => void save()}>
            <Icon name="passkey" className="h-4 w-4" />
            {t("scripts.saveWithPasskey")}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function fetchError(t: (k: string, o?: Record<string, unknown>) => string, field: string, code: string): string {
  if (field === "fetch") return t(`scripts.fetch.${code}`, { defaultValue: t("scripts.fetch.network") });
  return t(`scripts.err.${field}`, { defaultValue: t("scripts.err.invalid") });
}

function AddSource({ onClose, onAdded }: { onClose: () => void; onAdded: (s: Source) => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [spec, setSpec] = useState<Spec>({ repo: "", ref: "", subdir: "", token: "" });
  const [res, setRes] = useState<CandidateResult>();
  const [id, setId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const repoOk = normalizeRepo(spec.repo) !== undefined;
  const set = (p: Partial<Spec>) => {
    setSpec((s) => ({ ...s, ...p }));
    setRes(undefined);
  };

  const preview = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const r = await api<CandidateResult>("POST", "/scripts/preview", { spec });
      setRes(r);
      if (r.spec?.id) setId(r.spec.id);
      if (r.error) setErr(fetchError(t, r.error.field, r.error.code));
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  const add = async () => {
    if (!res?.candidate) return;
    setBusy(true);
    setErr(undefined);
    try {
      const s = await withStepUp(() => api<Source>("POST", "/scripts/add", { spec: { ...spec, id }, commit: res.candidate?.commit.sha }));
      onAdded(s);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={t("scripts.addSource")} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        <p className="text-muted">{t("scripts.addIntro")}</p>
        <Field label={t("scripts.repo")} help={t("scripts.repoHelp")} error={spec.repo && !repoOk ? t("scripts.err.repo") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={spec.repo} placeholder="owner/repository" onChange={(e) => set({ repo: e.target.value })} />}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("scripts.ref")} help={t("scripts.refHelp")}>
            {(p) => <input {...p} className="input font-mono" value={spec.ref} placeholder="main" onChange={(e) => set({ ref: e.target.value })} />}
          </Field>
          <Field label={t("scripts.subdir")} help={t("scripts.subdirHelp")}>
            {(p) => <input {...p} className="input font-mono" value={spec.subdir} placeholder="scripts" onChange={(e) => set({ subdir: e.target.value })} />}
          </Field>
        </div>
        <Field label={t("scripts.token")} help={t("scripts.tokenHelp")}>
          {(p) => (
            <input {...p} type="password" autoComplete="off" className="input font-mono" value={spec.token} onChange={(e) => set({ token: e.target.value })} />
          )}
        </Field>
        {res?.candidate && (
          <>
            <Field label={t("scripts.sourceId")} help={t("scripts.sourceIdHelp")} error={sourceIdRE.test(id) && id !== LOCAL ? undefined : t("scripts.err.id")}>
              {(p) => <input {...p} className="input font-mono" value={id} maxLength={40} onChange={(e) => setId(e.target.value)} />}
            </Field>
            <CandidateView c={res.candidate} />
          </>
        )}
        {err && (
          <Notice tone="bad" live>
            {err}
          </Notice>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          {!res?.candidate ? (
            <button type="button" className="btn btn-primary" disabled={busy || !repoOk} onClick={() => void preview()}>
              <Icon name="download" className="h-4 w-4" />
              {busy ? t("scripts.loadingRepo") : t("scripts.preview")}
            </button>
          ) : (
            <button type="button" className="btn btn-primary" disabled={busy || !sourceIdRE.test(id) || id === LOCAL} onClick={() => void add()}>
              <Icon name="passkey" className="h-4 w-4" />
              {t("scripts.takeOver", { sha: shortSha(res.candidate.commit.sha) })}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function UpdateCheck({ source, onClose, onUpdated }: { source: Source; onClose: () => void; onUpdated: (s: Source) => void }) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const q = useQuery({
    queryKey: ["scripts-check", source.id],
    queryFn: () => api<CandidateResult>("POST", "/scripts/check", { id: source.id }),
    gcTime: 0,
    retry: false,
  });
  const c = q.data?.candidate;
  const update = async () => {
    if (!c) return;
    setBusy(true);
    setErr(undefined);
    try {
      onUpdated(await withStepUp(() => api<Source>("POST", "/scripts/update", { id: source.id, commit: c.commit.sha })));
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={t("scripts.updateTitle", { id: source.id })} onClose={onClose} wide>
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted">
          {t("scripts.installed")}: <span className="font-mono">{shortSha(source.commit.sha)}</span> {source.commit.message}
        </p>
        {q.isLoading && <p className="text-muted">{t("scripts.loadingRepo")}</p>}
        {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
        {q.data?.error && <Notice tone="bad">{fetchError(t, q.data.error.field, q.data.error.code)}</Notice>}
        {c?.current && <Notice tone="ok">{t("scripts.upToDate")}</Notice>}
        {c && !c.current && <CandidateView c={c} />}
        {err && (
          <Notice tone="bad" live>
            {err}
          </Notice>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {c && !c.current ? t("common.cancel") : t("common.close")}
          </button>
          {c && !c.current && (
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void update()}>
              <Icon name="passkey" className="h-4 w-4" />
              {t("scripts.updateTo", { sha: shortSha(c.commit.sha) })}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

const statusTone: Record<string, string> = { added: "text-ok", removed: "text-bad", modified: "text-warn", mode: "text-muted" };

/** Commit, file list and per-file diffs of a candidate. */
export function CandidateView({ c }: { c: Candidate }) {
  const { t, i18n } = useTranslation();
  const used = c.changes.filter((x) => x.used_by?.length && x.status !== "added");
  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-[8px] border border-line p-3 text-sm">
        <p>
          <span className="font-mono">{c.commit.sha}</span>
        </p>
        <p className="font-medium">{c.commit.message}</p>
        <p className="text-muted">
          {c.commit.author} · {dateTime(c.commit.date, i18n.language)} · {t("scripts.fileCount", { count: c.files })} · {bytes(c.size, i18n.language)}
        </p>
      </div>
      {used.length > 0 && (
        <Notice tone="warn">{t("scripts.usedChanged", { files: used.map((x) => `${x.path} (${(x.used_by ?? []).join(", ")})`).join("; ") })}</Notice>
      )}
      <p className="text-sm text-muted">{t("scripts.reviewNote")}</p>
      <ul className="flex flex-col gap-2">
        {c.changes.map((x) => (
          <li key={x.path}>
            <details className="rounded-[8px] border border-line" open={c.changes.length <= 3}>
              <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2">
                <span className={`text-xs font-semibold uppercase ${statusTone[x.status] ?? ""}`}>{t(`scripts.status.${x.status}`)}</span>
                <span className="font-mono text-sm">{x.path}</span>
                {x.exec && <span className="text-xs text-faint">{t("scripts.col.exec")}</span>}
                {x.used_by?.length ? <span className="text-xs text-warn">{t("scripts.usedBy", { jobs: x.used_by.join(", ") })}</span> : null}
              </summary>
              <div className="px-3 pb-3">
                {x.binary ? (
                  <p className="text-sm text-muted">{t("scripts.binary")}</p>
                ) : x.omitted ? (
                  <p className="text-sm text-muted">{t("scripts.diffOmitted")}</p>
                ) : x.diff ? (
                  <DiffView diff={x.diff} />
                ) : (
                  <p className="text-sm text-muted">{t("scripts.modeOnly")}</p>
                )}
              </div>
            </details>
          </li>
        ))}
      </ul>
      {c.skipped.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">{t("scripts.skipped", { count: c.skipped.length })}</summary>
          <ul className="mt-2 flex flex-col gap-1">
            {c.skipped.map((s) => (
              <li key={s.path} className="font-mono text-xs">
                {s.path} <span className="text-faint">– {t(`scripts.skip.${s.reason}`)}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
