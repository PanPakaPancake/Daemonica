import { useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useSearchParams } from "react-router";
import type { CodeEditorHandle } from "../components/CodeEditor";
import { Icon } from "../components/icons";
import { Modal } from "../components/Modal";
import { Notice } from "../components/ui";
import { ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import { downloadFile, modeString, octal, readFile, writeFile, type FileContent, type Target } from "../lib/files";
import { bytes, dateTime } from "../lib/format";
import { useSession } from "../lib/session";
import { useFsRunner } from "../lib/useFs";

const CodeEditor = lazy(() => import("../components/CodeEditor").then((m) => ({ default: m.CodeEditor })));

type Eol = "\n" | "\r\n";

/** Line diff (LCS) for the conflict dialog; bounded to keep it cheap. */
export function lineDiff(a: string, b: string, max = 2000): { op: " " | "-" | "+"; text: string }[] | null {
  const x = a.split("\n");
  const y = b.split("\n");
  if (x.length > max || y.length > max) return null;
  const n = x.length;
  const m = y.length;
  const dp = new Uint32Array((n + 1) * (m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i * (m + 1) + j] = x[i] === y[j] ? (dp[(i + 1) * (m + 1) + j + 1] ?? 0) + 1 : Math.max(dp[(i + 1) * (m + 1) + j] ?? 0, dp[i * (m + 1) + j + 1] ?? 0);
  const out: { op: " " | "-" | "+"; text: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: " ", text: x[i] ?? "" });
      i++;
      j++;
    } else if ((dp[(i + 1) * (m + 1) + j] ?? 0) >= (dp[i * (m + 1) + j + 1] ?? 0)) out.push({ op: "-", text: x[i++] ?? "" });
    else out.push({ op: "+", text: y[j++] ?? "" });
  }
  while (i < n) out.push({ op: "-", text: x[i++] ?? "" });
  while (j < m) out.push({ op: "+", text: y[j++] ?? "" });
  return out;
}

export function FileEditor() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const nav = useNavigate();
  const qc = useQueryClient();
  const { me } = useSession();
  const { run, asRoot, dialog } = useFsRunner();
  const [params] = useSearchParams();
  const target: Target = { dir: params.get("dir") ?? "", name: params.get("name") ?? undefined, raw: params.get("raw") ?? undefined };
  const shown = target.name ?? "…";
  const editor = useRef<CodeEditorHandle>(null);
  const [file, setFile] = useState<FileContent>();
  const [loadErr, setLoadErr] = useState<string>();
  const [eol, setEol] = useState<Eol>("\n");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "bad" | "warn"; text: string }>();
  const [wrap, setWrap] = useState(false);
  const [tabSize, setTabSize] = useState(4);
  const [cursor, setCursor] = useState({ line: 1, col: 1 });
  const [conflict, setConflict] = useState<{ server: FileContent; mine: string } | null>(null);
  const [leave, setLeave] = useState<string | null>(null);
  const [gen, setGen] = useState(0); // remounts the editor with new content
  const loadedFor = useRef("");
  const key = `${target.dir}|${target.name ?? ""}|${target.raw ?? ""}|${asRoot}`;

  const load = useCallback(async () => {
    setLoadErr(undefined);
    try {
      const f = await run((fl) => readFile(target, fl), `${target.dir}/${shown}`);
      setFile(f);
      setEol(f.content?.includes("\r\n") ? "\r\n" : "\n");
      setDirty(false);
      setGen((g) => g + 1);
    } catch (e) {
      setLoadErr(errorText(t, e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, run]);

  useEffect(() => {
    if (loadedFor.current === key) return;
    loadedFor.current = key;
    void load();
  }, [key, load]);

  // Warn before leaving with unsaved changes (tab close and in-app links).
  useEffect(() => {
    if (!dirty) return;
    const before = (e: BeforeUnloadEvent) => e.preventDefault();
    const click = (e: MouseEvent) => {
      const a = (e.target as HTMLElement).closest?.("a[href]");
      if (!a || e.defaultPrevented || a.getAttribute("target") || a.hasAttribute("download")) return;
      const href = a.getAttribute("href") ?? "";
      if (!href.startsWith("/")) return;
      e.preventDefault();
      e.stopPropagation();
      setLeave(href);
    };
    window.addEventListener("beforeunload", before);
    document.addEventListener("click", click, true);
    return () => {
      window.removeEventListener("beforeunload", before);
      document.removeEventListener("click", click, true);
    };
  }, [dirty]);

  // Non-UTF-8 names cannot round-trip through the canonical path: keep the raw target.
  const saveTarget = (f: FileContent): Target => (target.raw ? target : { dir: f.dir, name: f.name });
  const text = (doc: string) => (eol === "\r\n" ? doc.replace(/\r?\n/g, "\r\n") : doc);

  const save = async (expected?: string) => {
    if (!file || saving || !editor.current) return;
    setSaving(true);
    setMsg(undefined);
    const mine = editor.current.getText();
    try {
      const res = await run((fl) => writeFile(saveTarget(file), text(mine), expected ?? file.hash, fl), file.path);
      setFile({ ...file, hash: res.hash, size: res.size, mtime: res.mtime });
      setDirty(false);
      setMsg({ tone: "ok", text: t(res.atomic ? "files.editor.saved" : "files.editor.savedInPlace") });
      void qc.invalidateQueries({ queryKey: ["fs-list"] });
    } catch (e) {
      if (e instanceof ApiError && e.code === "conflict") {
        try {
          const server = await run((fl) => readFile(saveTarget(file), fl), file.path);
          setConflict({ server, mine });
        } catch (e2) {
          setMsg({ tone: "bad", text: errorText(t, e2) });
        }
      } else setMsg({ tone: "bad", text: errorText(t, e) });
    } finally {
      setSaving(false);
    }
  };

  const back = `/files?path=${encodeURIComponent(file?.dir ?? target.dir)}`;
  const readOnly = !file?.writable;

  return (
    <div className="flex h-[calc(100vh-8.5rem)] min-h-[480px] flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Link to={back} className="btn btn-secondary min-h-9 px-2" title={t("files.editor.back")}>
          <Icon name="chevronLeft" className="h-4 w-4" />
          <span className="sr-only">{t("files.editor.back")}</span>
        </Link>
        <div className="min-w-0 flex-1">
          <h1 className="break-all font-mono text-lg font-semibold">
            {file?.path ?? `${target.dir}/${shown}`}
            {dirty && (
              <span className="ml-2 text-magenta" title={t("files.editor.unsaved")}>
                ●<span className="sr-only">{t("files.editor.unsaved")}</span>
              </span>
            )}
          </h1>
          {file && (
            <p className="text-xs text-muted">
              {bytes(file.size, lang)} · <span className="font-mono">{modeString(file.mode)}</span> ({octal(file.mode)}) · {file.user}:{file.group} ·{" "}
              {dateTime(file.mtime, lang)}
            </p>
          )}
        </div>
        {file?.content !== undefined && (
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={wrap} onChange={(e) => setWrap(e.target.checked)} />
              {t("files.editor.wrap")}
            </label>
            <select className="input header-select min-h-9 py-1 text-sm" value={tabSize} onChange={(e) => setTabSize(Number(e.target.value))} aria-label={t("files.editor.indent")}>
              {[2, 4, 8].map((n) => (
                <option key={n} value={n}>
                  {t("files.editor.spaces", { count: n })}
                </option>
              ))}
              <option value={0}>{t("files.editor.tabs")}</option>
            </select>
            <select
              className="input header-select min-h-9 py-1 font-mono text-sm"
              value={eol === "\r\n" ? "crlf" : "lf"}
              onChange={(e) => {
                setEol(e.target.value === "crlf" ? "\r\n" : "\n");
                setDirty(true);
              }}
              aria-label={t("files.editor.eol")}
            >
              <option value="lf">LF</option>
              <option value="crlf">CRLF</option>
            </select>
            <button type="button" className="btn btn-primary min-h-9 px-3" disabled={readOnly || saving || !dirty} onClick={() => void save()}>
              <Icon name="save" className="h-4 w-4" />
              {t("common.save")}
            </button>
          </div>
        )}
      </div>

      {msg && (
        <Notice tone={msg.tone} live>
          {msg.text}
        </Notice>
      )}
      {loadErr && (
        <Notice tone="bad">
          {loadErr}{" "}
          <button type="button" className="underline" onClick={() => void load()}>
            {t("common.retry")}
          </button>
        </Notice>
      )}
      {file && readOnly && file.content !== undefined && (
        <Notice tone="info">{t(me?.role === "admin" && !asRoot ? "files.editor.readOnlyAdmin" : "files.editor.readOnly", { owner: file.user })}</Notice>
      )}
      {file && (file.binary || file.too_large) && (
        <Notice tone="info">
          {t(file.binary ? "files.editor.binary" : "files.editor.tooLarge")}{" "}
          <button type="button" className="underline" onClick={() => void run((fl) => downloadFile({ dir: file.dir, name: file.name }, fl), file.path)}>
            {t("files.download")}
          </button>
        </Notice>
      )}

      {file?.content !== undefined && (
        <div className="min-h-0 flex-1">
          <Suspense fallback={<p className="text-muted">{t("common.loading")}</p>}>
            <CodeEditor
              key={gen}
              ref={editor}
              initial={file.content.replace(/\r\n/g, "\n")}
              path={file.path}
              wrap={wrap}
              tabSize={tabSize}
              readOnly={readOnly}
              label={t("files.editor.label", { name: file.name })}
              onDirty={() => setDirty(true)}
              onSave={() => void save()}
              onCursor={(line, col) => setCursor({ line, col })}
            />
          </Suspense>
        </div>
      )}
      {file?.content !== undefined && (
        <p className="flex flex-wrap justify-between gap-2 text-xs text-faint">
          <span>{t("files.editor.position", { line: cursor.line, col: cursor.col })}</span>
          <span>{t("files.editor.keys")}</span>
        </p>
      )}

      {dialog}
      {conflict && (
        <ConflictDialog
          mine={conflict.mine}
          server={conflict.server}
          onClose={() => setConflict(null)}
          onOverwrite={() => {
            const h = conflict.server.hash;
            setConflict(null);
            void save(h);
          }}
          onReload={() => {
            setFile(conflict.server);
            setEol(conflict.server.content?.includes("\r\n") ? "\r\n" : "\n");
            setDirty(false);
            setGen((g) => g + 1);
            setConflict(null);
          }}
        />
      )}
      {leave && (
        <Modal title={t("files.editor.leaveTitle")} onClose={() => setLeave(null)}>
          <p>{t("files.editor.leaveText")}</p>
          <div className="mt-5 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setLeave(null)}>
              {t("files.editor.stay")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                const to = leave;
                setDirty(false);
                setLeave(null);
                void nav(to);
              }}
            >
              {t("files.editor.discard")}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function ConflictDialog({
  mine,
  server,
  onClose,
  onOverwrite,
  onReload,
}: {
  mine: string;
  server: FileContent;
  onClose: () => void;
  onOverwrite: () => void;
  onReload: () => void;
}) {
  const { t, i18n } = useTranslation();
  const diff = server.content !== undefined ? lineDiff(server.content.replace(/\r\n/g, "\n"), mine) : null;
  return (
    <Modal title={t("files.editor.conflictTitle")} onClose={onClose} wide>
      <Notice tone="warn">{t("files.editor.conflictText", { time: dateTime(server.mtime, i18n.language), user: server.user })}</Notice>
      <p className="mt-3 text-sm text-muted">{t("files.editor.diffLegend")}</p>
      <div className="mt-2 max-h-[45vh] overflow-auto rounded-[8px] border border-line bg-bg-0 p-2 font-mono text-xs">
        {diff === null ? (
          <p className="text-muted">{t("files.editor.diffTooLarge")}</p>
        ) : (
          diff
            .filter((d, i, all) => d.op !== " " || all.slice(Math.max(0, i - 2), i + 3).some((x) => x.op !== " "))
            .map((d, i) => (
              <div key={i} className={`whitespace-pre-wrap break-all ${d.op === "-" ? "text-bad" : d.op === "+" ? "text-ok" : "text-faint"}`}>
                <span aria-hidden="true">{d.op} </span>
                <span className="sr-only">{d.op === "-" ? t("files.editor.serverLine") : d.op === "+" ? t("files.editor.myLine") : ""}</span>
                {d.text}
              </div>
            ))
        )}
      </div>
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          {t("common.cancel")}
        </button>
        <button type="button" className="btn btn-secondary" onClick={onReload}>
          {t("files.editor.loadServer")}
        </button>
        <button type="button" className="btn btn-danger" onClick={onOverwrite}>
          {t("files.editor.overwrite")}
        </button>
      </div>
    </Modal>
  );
}
