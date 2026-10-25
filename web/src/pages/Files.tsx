import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useSearchParams } from "react-router";
import { Icon, type IconName } from "../components/icons";
import { DataTable } from "../components/DataTable";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Notice, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";
import { errorText } from "../lib/errors";
import {
  downloadFile,
  fsCall,
  isDir,
  joinPath,
  modeString,
  octal,
  parentOf,
  shownName,
  targetOf,
  uploadFile,
  type FsEntry,
  type FsListing,
  type FsStat,
  type Target,
} from "../lib/files";
import { bytes, dateTime } from "../lib/format";
import { useSession } from "../lib/session";
import { useFsRunner } from "../lib/useFs";

const PAGE = 200;

/** Client-side mirror of files.ValidName (the server decides). */
export function validName(n: string): boolean {
  if (!n || n === "." || n === ".." || n.includes("/") || new TextEncoder().encode(n).length > 255) return false;
  return !/[\p{Cc}\p{Cf}]/u.test(n);
}

function iconFor(e: FsEntry): IconName {
  if (e.type === "symlink") return e.target_type === "dir" ? "folder" : "link";
  return e.type === "dir" ? "folder" : "file";
}

type SortKey = "name" | "type" | "size" | "mode" | "owner" | "mtime";
const sortKeys: SortKey[] = ["name", "type", "size", "mode", "owner", "mtime"];

type Kind = "" | "dir" | "file" | "symlink" | "other";
const kinds = ["dir", "file", "symlink", "other"] as const;

function kindOf(e: FsEntry): Exclude<Kind, ""> {
  return e.type === "dir" || e.type === "file" || e.type === "symlink" ? e.type : "other";
}

type View = "details" | "compact" | "grid";
const views: { v: View; icon: IconName }[] = [
  { v: "details", icon: "viewList" },
  { v: "compact", icon: "viewCompact" },
  { v: "grid", icon: "viewGrid" },
];

function loadView(): View {
  try {
    const v = localStorage.getItem("daemonica.files.view");
    if (v === "details" || v === "compact" || v === "grid") return v;
  } catch {
    // storage unavailable: default view
  }
  return "details";
}

type Dlg =
  | { kind: "new"; dirKind: "file" | "dir" }
  | { kind: "rename"; e: FsEntry }
  | { kind: "transfer"; e: FsEntry; copy: boolean }
  | { kind: "chmod"; e: FsEntry }
  | { kind: "chown"; e: FsEntry }
  | { kind: "props"; e: FsEntry }
  | { kind: "delete"; e: FsEntry }
  | { kind: "root" }
  | undefined;

export function Files() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const qc = useQueryClient();
  const nav = useNavigate();
  const { me, withStepUp } = useSession();
  const isAdmin = me?.role === "admin";
  const { run, asRoot, info, dialog } = useFsRunner();
  const [params, setParams] = useSearchParams();
  const path = params.get("path") ?? info.data?.home ?? "";
  const [hidden, setHidden] = useState(false);
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const [ownerInput, setOwnerInput] = useState("");
  const [owner, setOwner] = useState("");
  const [kind, setKind] = useState<Kind>("");
  const [view, setViewState] = useState<View>(loadView);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "name", desc: false });
  const [offset, setOffset] = useState(0);
  const [dlg, setDlg] = useState<Dlg>();
  const [msg, setMsg] = useState<{ tone: "ok" | "bad" | "info"; text: string }>();
  const [drag, setDrag] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const uploads = useUploads(asRoot, () => void qc.invalidateQueries({ queryKey: ["fs-list"] }));

  useEffect(() => {
    const id = setTimeout(() => setFilter(filterInput.trim()), 300);
    return () => clearTimeout(id);
  }, [filterInput]);
  useEffect(() => {
    const id = setTimeout(() => setOwner(ownerInput.trim()), 300);
    return () => clearTimeout(id);
  }, [ownerInput]);

  const setView = (v: View) => {
    setViewState(v);
    try {
      localStorage.setItem("daemonica.files.view", v);
    } catch {
      // per-browser convenience only
    }
  };

  const list = useQuery({
    queryKey: ["fs-list", path, hidden, filter, owner, kind, sort, offset, asRoot],
    queryFn: () =>
      fsCall<FsListing>(
        "list",
        { path, hidden, filter, owner, ...(kind && { kind }), sort: sort.key, desc: sort.desc, offset, limit: PAGE },
        { as_root: asRoot },
      ),
    enabled: !!path,
    retry: false,
  });
  const data = list.data;
  const dir = data?.path ?? path;

  // Symlinked directories: continue with the canonical path (writes never follow symlinks).
  useEffect(() => {
    if (data && data.path !== path) setParams({ path: data.path }, { replace: true });
  }, [data, path, setParams]);

  const go = (p: string) => {
    setOffset(0);
    setFilterInput("");
    setFilter("");
    setOwnerInput("");
    setOwner("");
    setKind("");
    setMsg(undefined);
    setParams({ path: p });
  };

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["fs-list"] });
    void qc.invalidateQueries({ queryKey: ["fs-tree"] });
  };

  /** Runs a change, reports the outcome and refreshes the listing. */
  const act = async (fn: () => Promise<unknown>, done: string): Promise<boolean> => {
    setMsg(undefined);
    try {
      await fn();
      setMsg({ tone: "ok", text: done });
      refresh();
      return true;
    } catch (e) {
      setMsg({ tone: "bad", text: errorText(t, e) });
      return false;
    }
  };

  const open = (e: FsEntry) => {
    if (isDir(e)) {
      if (e.raw) {
        setMsg({ tone: "info", text: t("files.rawName") });
        return;
      }
      go(joinPath(dir, e.name));
      return;
    }
    if (e.type === "file" || e.type === "symlink") {
      const q = new URLSearchParams({ dir });
      if (e.raw) q.set("raw", e.raw);
      else q.set("name", e.name);
      void nav(`/files/edit?${q.toString()}`);
      return;
    }
    setDlg({ kind: "props", e });
  };

  const download = (e: FsEntry) => void act(() => run((f) => downloadFile(targetOf(dir, e), f), joinPath(dir, shownName(e))), t("files.downloadStarted"));

  const items = (e: FsEntry): MenuItem[] => {
    const file = e.type === "file" || (e.type === "symlink" && e.target_type === "file");
    const out: MenuItem[] = [];
    if (isDir(e)) out.push({ label: t("files.open"), icon: "folder", onSelect: () => open(e) });
    if (file) {
      out.push({ label: t("files.edit"), icon: "edit", onSelect: () => open(e) });
      out.push({ label: t("files.download"), icon: "download", onSelect: () => download(e) });
    }
    out.push(
      { label: t("files.rename"), icon: "edit", onSelect: () => setDlg({ kind: "rename", e }) },
      { label: t("files.move"), icon: "move", onSelect: () => setDlg({ kind: "transfer", e, copy: false }) },
      { label: t("files.copy"), icon: "copy", onSelect: () => setDlg({ kind: "transfer", e, copy: true }) },
    );
    if (e.type !== "symlink") out.push({ label: t("files.permissions"), icon: "lock", onSelect: () => setDlg({ kind: "chmod", e }) });
    if (isAdmin && e.type !== "symlink") out.push({ label: t("files.owner"), icon: "users", disabled: !asRoot, onSelect: () => setDlg({ kind: "chown", e }) });
    out.push(
      { label: t("files.properties"), icon: "info", onSelect: () => setDlg({ kind: "props", e }) },
      { label: t("common.delete"), icon: "trash", danger: true, onSelect: () => setDlg({ kind: "delete", e }) },
    );
    return out;
  };

  const addFiles = (fl: FileList | File[]) => {
    const arr = Array.from(fl);
    const limit = (info.data?.upload_limit_mib ?? 1024) * 1024 * 1024;
    uploads.add(arr, dir, limit);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDrag(false);
    const dirs = Array.from(e.dataTransfer.items ?? []).filter((it) => it.webkitGetAsEntry?.()?.isDirectory);
    if (dirs.length) setMsg({ tone: "info", text: t("files.upload.noFolders") });
    const fl = Array.from(e.dataTransfer.files).filter((f) => !dirs.some((d) => d.getAsFile()?.name === f.name));
    if (fl.length) addFiles(fl);
  };

  if (me?.role === "readonly") return <Notice tone="info">{t("files.readonly")}</Notice>;

  const filtered = !!(filter || owner || kind);
  const listErr = list.error instanceof ApiError ? list.error.code : undefined;
  const crumbs = dir.split("/").filter(Boolean);
  const from = data && data.total > 0 ? offset + 1 : 0;
  const to = data ? Math.min(offset + PAGE, data.total) : 0;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{t("files.title")}</h1>
          <p className="mt-1 text-muted">{t(asRoot ? "files.introRoot" : "files.intro", { user: me?.linux_user })}</p>
        </div>
        {isAdmin && (
          <RootButton
            active={asRoot}
            until={info.data?.root.until}
            onEnable={() => setDlg({ kind: "root" })}
            onDisable={() =>
              void act(async () => {
                await api("POST", "/files/root/disable");
                await qc.invalidateQueries({ queryKey: ["fs-info"] });
              }, t("files.root.ended"))
            }
          />
        )}
      </div>

      {msg && (
        <Notice tone={msg.tone} live>
          {msg.text}
        </Notice>
      )}

      <div className="flex gap-4">
        <Panel className="hidden w-64 shrink-0 self-start overflow-auto p-2 lg:block lg:max-h-[calc(100vh-12rem)]">
          <nav aria-label={t("files.tree")}>
            {info.data?.home && info.data.home !== "/" && (
              <button type="button" className={treeBtn(dir === info.data.home)} onClick={() => go(info.data.home)}>
                <Icon name="home" className="h-4 w-4 text-cyan" />
                {t("files.home")}
              </button>
            )}
            <TreeNode path="/" name="/" depth={0} current={dir} asRoot={asRoot} hidden={hidden} onGo={go} />
          </nav>
        </Panel>

        <div
          className={`flex min-w-0 flex-1 flex-col gap-3 ${drag ? "dropzone-active" : ""}`}
          onDragOver={(e) => {
            if (e.dataTransfer.types.includes("Files")) {
              e.preventDefault();
              setDrag(true);
            }
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
        >
          <Panel className="flex flex-col gap-3 p-3">
            <nav aria-label={t("files.breadcrumbs")} className="flex flex-wrap items-center gap-1 font-mono text-sm">
              <button type="button" className="rounded px-1 hover:bg-bg-2" onClick={() => go("/")}>
                /
              </button>
              {crumbs.map((c, i) => {
                const p = "/" + crumbs.slice(0, i + 1).join("/");
                return (
                  <span key={p} className="flex items-center gap-1">
                    {i > 0 && <span className="text-faint">/</span>}
                    <button type="button" className="break-all rounded px-1 hover:bg-bg-2" aria-current={p === dir ? "page" : undefined} onClick={() => go(p)}>
                      {c}
                    </button>
                  </span>
                );
              })}
            </nav>
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" className="btn btn-secondary min-h-9 px-2" onClick={() => go(parentOf(dir))} disabled={dir === "/"} title={t("files.up")}>
                <Icon name="arrowUp" className="h-4 w-4" />
                <span className="sr-only">{t("files.up")}</span>
              </button>
              <button
                type="button"
                className="btn btn-secondary min-h-9 px-3"
                onClick={() => setDlg({ kind: "new", dirKind: "file" })}
                disabled={!data?.writable}
              >
                <Icon name="filePlus" className="h-4 w-4" />
                {t("files.newFile")}
              </button>
              <button
                type="button"
                className="btn btn-secondary min-h-9 px-3"
                onClick={() => setDlg({ kind: "new", dirKind: "dir" })}
                disabled={!data?.writable}
              >
                <Icon name="folderPlus" className="h-4 w-4" />
                {t("files.newFolder")}
              </button>
              <button type="button" className="btn btn-primary min-h-9 px-3" onClick={() => fileInput.current?.click()} disabled={!data?.writable}>
                <Icon name="upload" className="h-4 w-4" />
                {t("files.upload.button")}
              </button>
              <input
                ref={fileInput}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => {
                  if (e.target.files) addFiles(e.target.files);
                  e.target.value = "";
                }}
              />
              <div className="ml-auto flex flex-wrap items-center gap-2">
                <div className="flex rounded-[8px] border border-line" role="group" aria-label={t("files.view.label")}>
                  {views.map(({ v, icon }) => (
                    <button
                      key={v}
                      type="button"
                      className={`min-h-9 px-2 first:rounded-l-[7px] last:rounded-r-[7px] ${view === v ? "bg-bg-2 text-violet" : "text-muted hover:text-fg"}`}
                      aria-pressed={view === v}
                      title={t(`files.view.${v}`)}
                      onClick={() => setView(v)}
                    >
                      <Icon name={icon} className="h-4 w-4" />
                      <span className="sr-only">{t(`files.view.${v}`)}</span>
                    </button>
                  ))}
                </div>
                <label className="relative">
                  <span className="sr-only">{t("files.search")}</span>
                  <Icon name="search" className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-faint" />
                  <input
                    className="input min-h-9 w-48 pl-8"
                    value={filterInput}
                    placeholder={t("files.search")}
                    onChange={(e) => {
                      setOffset(0);
                      setFilterInput(e.target.value);
                    }}
                  />
                </label>
                <button
                  type="button"
                  className="btn btn-secondary min-h-9 px-2"
                  aria-pressed={hidden}
                  title={t(hidden ? "files.hideHidden" : "files.showHidden")}
                  onClick={() => {
                    setOffset(0);
                    setHidden(!hidden);
                  }}
                >
                  <Icon name={hidden ? "eye" : "eyeOff"} className="h-4 w-4" />
                  <span className="sr-only">{t("files.showHidden")}</span>
                </button>
                <button type="button" className="btn btn-secondary min-h-9 px-2" onClick={refresh} title={t("common.refresh")}>
                  <Icon name="restart" className="h-4 w-4" />
                  <span className="sr-only">{t("common.refresh")}</span>
                </button>
              </div>
            </div>
            {data && !data.writable && <p className="text-sm text-faint">{t(isAdmin && !asRoot ? "files.notWritableAdmin" : "files.notWritable")}</p>}
          </Panel>

          {uploads.view}

          {listErr && (
            <Notice tone={listErr === "path_blocked" ? "bad" : "warn"}>
              {errorText(t, list.error)}
              {listErr === "permission_denied" && isAdmin && !asRoot && <span className="mt-1 block text-sm">{t("files.rootHint")}</span>}
            </Notice>
          )}
          {data?.truncated && <Notice tone="info">{t("files.truncated")}</Notice>}
          {data?.virtual && <Notice tone="info">{t("files.virtual")}</Notice>}

          <Panel className="overflow-x-auto p-0">
            {view === "details" ? (
              <DataTable
                label={t("files.title")}
                rows={data?.entries}
                rowKey={(e) => e.raw ?? e.name}
                loading={list.isLoading}
                empty={filtered ? t("files.noMatch") : t("files.empty")}
                sort={sort}
                onSort={(s) => {
                  setOffset(0);
                  setSort((s as { key: SortKey; desc: boolean } | null) ?? { key: "name", desc: false });
                }}
                filters={{ name: filterInput, owner: ownerInput, kind }}
                onFilters={(f) => {
                  setOffset(0);
                  setFilterInput(f.name ?? "");
                  setOwnerInput(f.owner ?? "");
                  setKind((f.kind ?? "") as Kind);
                }}
                columns={[
                  {
                    key: "name",
                    label: t("files.col.name"),
                    sortValue: (e) => e.name,
                    filter: "text",
                    cell: (e) => (
                      <button type="button" className="flex min-w-0 items-center gap-2 text-left" onClick={() => open(e)}>
                        <Icon name={iconFor(e)} className={`h-4 w-4 ${isDir(e) ? "text-violet" : "text-faint"}`} />
                        <span className={`break-all font-mono ${e.display || e.raw ? "text-warn" : ""}`}>{shownName(e)}</span>
                        {e.type === "symlink" && <span className="break-all text-xs text-faint">→ {e.target ?? "?"}</span>}
                        {e.blocked && <span className="rounded-full border border-line px-1.5 text-[10px] text-bad">{t("files.blocked")}</span>}
                      </button>
                    ),
                  },
                  {
                    key: "type",
                    label: t("files.col.type"),
                    thClass: "w-28 hidden md:table-cell",
                    tdClass: "hidden text-muted md:table-cell",
                    sortValue: (e) => e.type,
                    filter: { options: kinds.map((k) => ({ value: k, label: t(`files.kind.${k}`) })) },
                    cell: (e) => <>{t(`files.kind.${kindOf(e)}`)}</>,
                  },
                  {
                    key: "size",
                    label: t("files.col.size"),
                    thClass: "w-24 text-right",
                    tdClass: "text-right tabular-nums text-muted",
                    sortValue: (e) => e.size,
                    cell: (e) => <>{e.type === "file" ? bytes(e.size, lang) : "–"}</>,
                  },
                  {
                    key: "mode",
                    label: t("files.col.mode"),
                    thClass: "w-32",
                    tdClass: "font-mono text-xs",
                    tdTitle: (e) => octal(e.mode),
                    sortValue: (e) => e.mode,
                    cell: (e) => <>{modeString(e.mode)}</>,
                  },
                  {
                    key: "owner",
                    label: t("files.col.owner"),
                    thClass: "w-40",
                    tdClass: "text-muted",
                    sortValue: (e) => `${e.user ?? e.uid}:${e.group ?? e.gid}`,
                    filter: "text",
                    cell: (e) => (
                      <>
                        {e.user ?? e.uid}:{e.group ?? e.gid}
                      </>
                    ),
                  },
                  {
                    key: "mtime",
                    label: t("files.col.mtime"),
                    thClass: "w-44",
                    tdClass: "text-muted",
                    sortValue: (e) => e.mtime,
                    cell: (e) => <>{dateTime(e.mtime, lang)}</>,
                  },
                  {
                    key: "actions",
                    label: t("common.actions"),
                    srOnly: true,
                    thClass: "w-12",
                    cell: (e) => <Menu label={t("files.actionsFor", { name: shownName(e) })} items={items(e)} />,
                  },
                ]}
              />
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2 text-sm">
                  <label className="flex items-center gap-1.5">
                    <span className="text-muted">{t("files.sortBy")}</span>
                    <select
                      className="input header-select min-h-8 py-1 text-sm"
                      value={sort.key}
                      onChange={(e) => {
                        setOffset(0);
                        setSort({ key: e.target.value as SortKey, desc: sort.desc });
                      }}
                    >
                      {sortKeys.map((k) => (
                        <option key={k} value={k}>
                          {t(`files.col.${k}`)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    className="btn btn-secondary min-h-8 px-2"
                    title={t(sort.desc ? "files.sortDesc" : "files.sortAsc")}
                    onClick={() => {
                      setOffset(0);
                      setSort({ ...sort, desc: !sort.desc });
                    }}
                  >
                    <span aria-hidden="true">{sort.desc ? "▼" : "▲"}</span>
                    <span className="sr-only">{t(sort.desc ? "files.sortDesc" : "files.sortAsc")}</span>
                  </button>
                  <label className="flex items-center gap-1.5">
                    <span className="text-muted">{t("files.col.type")}</span>
                    <select
                      className="input header-select min-h-8 py-1 text-sm"
                      value={kind}
                      onChange={(e) => {
                        setOffset(0);
                        setKind(e.target.value as Kind);
                      }}
                    >
                      <option value="">{t("table.all")}</option>
                      {kinds.map((k) => (
                        <option key={k} value={k}>
                          {t(`files.kind.${k}`)}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                {list.isLoading && <p className="px-3 py-6 text-muted">{t("common.loading")}</p>}
                {data && data.entries.length === 0 && <p className="px-3 py-6 text-muted">{filtered ? t("files.noMatch") : t("files.empty")}</p>}
                {data && data.entries.length > 0 && (
                  <ul
                    className={
                      view === "grid"
                        ? "grid grid-cols-[repeat(auto-fill,minmax(8.5rem,1fr))] gap-2 p-3"
                        : "grid grid-cols-[repeat(auto-fill,minmax(15rem,1fr))] gap-x-3 p-2"
                    }
                  >
                    {data.entries.map((e) =>
                      view === "grid" ? (
                        <li key={e.raw ?? e.name} className="relative rounded-[8px] border border-transparent hover:border-line hover:bg-bg-2/50">
                          <button
                            type="button"
                            className="flex w-full flex-col items-center gap-1.5 px-2 pb-2 pt-3 text-center"
                            onClick={() => open(e)}
                            title={`${shownName(e)} · ${modeString(e.mode)} · ${e.user ?? e.uid}:${e.group ?? e.gid} · ${dateTime(e.mtime, lang)}`}
                          >
                            <Icon name={iconFor(e)} className={`h-10 w-10 ${isDir(e) ? "text-violet" : "text-faint"}`} />
                            <span className={`line-clamp-2 break-all font-mono text-xs ${e.display || e.raw ? "text-warn" : ""}`}>{shownName(e)}</span>
                            <span className="text-[11px] text-faint">{e.type === "file" ? bytes(e.size, lang) : t(`files.kind.${kindOf(e)}`)}</span>
                          </button>
                          <div className="absolute right-0.5 top-0.5">
                            <Menu label={t("files.actionsFor", { name: shownName(e) })} items={items(e)} />
                          </div>
                        </li>
                      ) : (
                        <li key={e.raw ?? e.name} className="flex min-w-0 items-center gap-1 rounded-[6px] hover:bg-bg-2/50">
                          <button
                            type="button"
                            className="flex min-w-0 flex-1 items-center gap-2 px-2 py-1 text-left"
                            onClick={() => open(e)}
                            title={`${shownName(e)} · ${e.type === "file" ? bytes(e.size, lang) + " · " : ""}${dateTime(e.mtime, lang)}`}
                          >
                            <Icon name={iconFor(e)} className={`h-4 w-4 ${isDir(e) ? "text-violet" : "text-faint"}`} />
                            <span className={`truncate font-mono text-sm ${e.display || e.raw ? "text-warn" : ""}`}>{shownName(e)}</span>
                          </button>
                          <Menu label={t("files.actionsFor", { name: shownName(e) })} items={items(e)} />
                        </li>
                      ),
                    )}
                  </ul>
                )}
              </>
            )}
            {data && data.total > PAGE && (
              <div className="flex items-center justify-between border-t border-line px-3 py-2 text-sm">
                <span className="text-muted">{t("files.range", { from, to, total: data.total })}</span>
                <span className="flex gap-2">
                  <button
                    type="button"
                    className="btn btn-secondary min-h-8 px-2"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE))}
                  >
                    <Icon name="chevronLeft" className="h-4 w-4" />
                    <span className="sr-only">{t("common.previous")}</span>
                  </button>
                  <button type="button" className="btn btn-secondary min-h-8 px-2" disabled={to >= data.total} onClick={() => setOffset(offset + PAGE)}>
                    <Icon name="chevronRight" className="h-4 w-4" />
                    <span className="sr-only">{t("common.next")}</span>
                  </button>
                </span>
              </div>
            )}
          </Panel>
          <p className="text-xs text-faint">{t("files.dropHint", { limit: info.data?.upload_limit_mib ?? 1024 })}</p>
        </div>
      </div>

      {dialog}
      {dlg?.kind === "root" && (
        <Modal title={t("files.root.title")} onClose={() => setDlg(undefined)}>
          <Notice tone="warn">{t("files.root.warning")}</Notice>
          <Explain>{t("files.root.explain")}</Explain>
          <div className="mt-5 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setDlg(undefined)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() =>
                void act(async () => {
                  await withStepUp(() => api("POST", "/files/root/enable"));
                  await qc.invalidateQueries({ queryKey: ["fs-info"] });
                  setDlg(undefined);
                }, t("files.root.started"))
              }
            >
              {t("files.root.enable")}
            </button>
          </div>
        </Modal>
      )}
      {dlg?.kind === "new" && (
        <NameDialog
          title={t(dlg.dirKind === "dir" ? "files.newFolder" : "files.newFile")}
          initial=""
          onClose={() => setDlg(undefined)}
          onSubmit={(name) =>
            act(() => run((f) => fsCall("create", { dir, name, kind: dlg.dirKind }, f)), t("files.created", { name })).then((ok) => ok && setDlg(undefined))
          }
        />
      )}
      {dlg?.kind === "rename" && (
        <NameDialog
          title={t("files.renameTitle", { name: shownName(dlg.e) })}
          initial={dlg.e.raw ? "" : dlg.e.name}
          onClose={() => setDlg(undefined)}
          onSubmit={(name) =>
            act(
              () => run((f) => fsCall("rename", { ...targetOf(dir, dlg.e), new_name: name }, f), joinPath(dir, shownName(dlg.e))),
              t("files.renamed", { name }),
            ).then((ok) => ok && setDlg(undefined))
          }
        />
      )}
      {dlg?.kind === "transfer" && (
        <TransferDialog
          entry={dlg.e}
          copy={dlg.copy}
          dir={dir}
          onClose={() => setDlg(undefined)}
          onSubmit={(dest, newName) =>
            act(
              () =>
                run(
                  (f) => fsCall("transfer", { ...targetOf(dir, dlg.e), dest_dir: dest, new_name: newName || undefined, copy: dlg.copy }, f),
                  joinPath(dir, shownName(dlg.e)),
                ),
              t(dlg.copy ? "files.copied" : "files.moved", { name: shownName(dlg.e) }),
            ).then((ok) => ok && setDlg(undefined))
          }
        />
      )}
      {dlg?.kind === "chmod" && (
        <ChmodDialog
          entry={dlg.e}
          onClose={() => setDlg(undefined)}
          onSubmit={(mode) =>
            act(() => run((f) => fsCall("chmod", { ...targetOf(dir, dlg.e), mode }, f), joinPath(dir, shownName(dlg.e))), t("files.chmodDone")).then(
              (ok) => ok && setDlg(undefined),
            )
          }
        />
      )}
      {dlg?.kind === "chown" && (
        <ChownDialog
          entry={dlg.e}
          onClose={() => setDlg(undefined)}
          onSubmit={(user, group) =>
            act(
              () =>
                run(
                  (f) => fsCall("chown", { ...targetOf(dir, dlg.e), user: user || undefined, group: group || undefined }, f),
                  joinPath(dir, shownName(dlg.e)),
                ),
              t("files.chownDone"),
            ).then((ok) => ok && setDlg(undefined))
          }
        />
      )}
      {dlg?.kind === "props" && <PropsDialog target={targetOf(dir, dlg.e)} title={shownName(dlg.e)} onClose={() => setDlg(undefined)} />}
      {dlg?.kind === "delete" && (
        <DeleteDialog
          entry={dlg.e}
          onClose={() => setDlg(undefined)}
          onSubmit={(recursive) =>
            act(
              () =>
                run(
                  (f) => fsCall("delete", { ...targetOf(dir, dlg.e), recursive: recursive || undefined, confirm: recursive ? shownName(dlg.e) : undefined }, f),
                  joinPath(dir, shownName(dlg.e)),
                ),
              t("files.deleted", { name: shownName(dlg.e) }),
            ).then((ok) => ok && setDlg(undefined))
          }
        />
      )}
    </div>
  );
}

function treeBtn(active: boolean) {
  return `flex w-full items-center gap-2 rounded-[6px] px-2 py-1 text-left text-sm ${active ? "bg-bg-2 text-fg" : "text-muted hover:bg-bg-2"}`;
}

function TreeNode({
  path,
  name,
  depth,
  current,
  asRoot,
  hidden,
  onGo,
}: {
  path: string;
  name: string;
  depth: number;
  current: string;
  asRoot: boolean;
  hidden: boolean;
  onGo: (p: string) => void;
}) {
  const { t } = useTranslation();
  const [toggled, setToggled] = useState<boolean>();
  const onPath = current === path || current.startsWith(path === "/" ? "/" : path + "/");
  const open = toggled ?? onPath;
  const q = useQuery({
    queryKey: ["fs-tree", path, asRoot, hidden],
    queryFn: () => fsCall<FsListing>("list", { path, dirs_only: true, hidden, limit: 500 }, { as_root: asRoot }),
    enabled: open && depth < 24,
    retry: false,
  });
  return (
    <div>
      <div className="flex items-center" style={{ paddingLeft: depth * 12 }}>
        <button
          type="button"
          className="rounded p-0.5 text-faint hover:text-fg"
          aria-expanded={open}
          aria-label={t(open ? "files.collapse" : "files.expand", { name })}
          onClick={() => setToggled(!open)}
        >
          <Icon name="chevronRight" className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-90" : ""}`} />
        </button>
        <button type="button" className={treeBtn(current === path)} aria-current={current === path ? "page" : undefined} onClick={() => onGo(path)}>
          <Icon name="folder" className="h-4 w-4 text-violet" />
          <span className="truncate font-mono">{name}</span>
        </button>
      </div>
      {open &&
        q.data?.entries
          .filter((e) => !e.raw && !e.blocked)
          .map((e) => (
            <TreeNode
              key={e.name}
              path={joinPath(q.data.path, e.name)}
              name={e.name}
              depth={depth + 1}
              current={current}
              asRoot={asRoot}
              hidden={hidden}
              onGo={onGo}
            />
          ))}
    </div>
  );
}

function RootButton({ active, until, onEnable, onDisable }: { active: boolean; until?: string; onEnable: () => void; onDisable: () => void }) {
  const { t, i18n } = useTranslation();
  if (!active)
    return (
      <button type="button" className="btn btn-secondary" onClick={onEnable}>
        <Icon name="shield" className="h-4 w-4 text-magenta" />
        {t("files.root.enable")}
      </button>
    );
  return (
    <div className="flex items-center gap-2">
      <span className="rounded-full bg-[var(--magenta-btn)] px-2.5 py-1 text-xs font-semibold text-white">
        {t("files.root.activeUntil", { time: until ? new Date(until).toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit" }) : "" })}
      </span>
      <button type="button" className="btn btn-secondary" onClick={onDisable}>
        {t("files.root.disable")}
      </button>
    </div>
  );
}

function Busy({ children, busy, danger, disabled }: { children: ReactNode; busy: boolean; danger?: boolean; disabled?: boolean }) {
  return (
    <button type="submit" className={`btn ${danger ? "btn-danger" : "btn-primary"}`} disabled={busy || disabled}>
      {children}
    </button>
  );
}

function useBusy() {
  const [busy, setBusy] = useState(false);
  const wrap = (fn: () => Promise<unknown>) => async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };
  return { busy, wrap };
}

function NameDialog({
  title,
  initial,
  onClose,
  onSubmit,
}: {
  title: string;
  initial: string;
  onClose: () => void;
  onSubmit: (name: string) => Promise<unknown>;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial);
  const { busy, wrap } = useBusy();
  const bad = name !== "" && !validName(name);
  return (
    <Modal title={title} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={wrap(() => onSubmit(name))}>
        <Field label={t("files.name")} error={bad ? t("files.invalidName") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={name} autoFocus onChange={(e) => setName(e.target.value)} spellCheck={false} />}
        </Field>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <Busy busy={busy} disabled={!validName(name)}>
            {t("common.save")}
          </Busy>
        </div>
      </form>
    </Modal>
  );
}

function TransferDialog({
  entry,
  copy,
  dir,
  onClose,
  onSubmit,
}: {
  entry: FsEntry;
  copy: boolean;
  dir: string;
  onClose: () => void;
  onSubmit: (dest: string, newName: string) => Promise<unknown>;
}) {
  const { t } = useTranslation();
  const [dest, setDest] = useState(dir);
  const [newName, setNewName] = useState("");
  const { busy, wrap } = useBusy();
  const destOk = dest.startsWith("/") && !dest.includes("//") && !/(^|\/)\.\.?(\/|$)/.test(dest);
  const destClean = dest.length > 1 && dest.endsWith("/") ? dest.slice(0, -1) : dest;
  const sameDir = destClean === dir && !newName;
  return (
    <Modal title={t(copy ? "files.copyTitle" : "files.moveTitle", { name: shownName(entry) })} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={wrap(() => onSubmit(destClean, newName))}>
        <Field label={t("files.destination")} help={t("files.destinationHelp")} error={!destOk ? t("files.invalidPath") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={dest} autoFocus onChange={(e) => setDest(e.target.value)} spellCheck={false} />}
        </Field>
        <Field label={t("files.newNameOptional")} error={newName && !validName(newName) ? t("files.invalidName") : undefined}>
          {(p) => <input {...p} className="input font-mono" value={newName} placeholder={shownName(entry)} onChange={(e) => setNewName(e.target.value)} />}
        </Field>
        {!copy && <Explain>{t("files.moveExplain")}</Explain>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <Busy busy={busy} disabled={!destOk || sameDir || (!!newName && !validName(newName))}>
            {t(copy ? "files.copy" : "files.move")}
          </Busy>
        </div>
      </form>
    </Modal>
  );
}

const permBits: { who: "owner" | "group" | "other"; bits: [number, number, number] }[] = [
  { who: "owner", bits: [0o400, 0o200, 0o100] },
  { who: "group", bits: [0o40, 0o20, 0o10] },
  { who: "other", bits: [0o4, 0o2, 0o1] },
];

function ChmodDialog({ entry, onClose, onSubmit }: { entry: FsEntry; onClose: () => void; onSubmit: (mode: number) => Promise<unknown> }) {
  const { t } = useTranslation();
  const [mode, setMode] = useState(entry.mode & 0o7777);
  const [text, setText] = useState(octal(entry.mode));
  const { busy, wrap } = useBusy();
  const set = (m: number) => {
    setMode(m);
    setText(octal(m));
  };
  const toggle = (bit: number) => set(mode ^ bit);
  const specials: [number, string][] = [
    [0o4000, "setuid"],
    [0o2000, "setgid"],
    [0o1000, "sticky"],
  ];
  return (
    <Modal title={t("files.chmodTitle", { name: shownName(entry) })} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={wrap(() => onSubmit(mode))}>
        <table className="text-sm">
          <thead>
            <tr className="text-xs text-faint">
              <th />
              <th className="px-2 py-1">{t("files.perm.read")}</th>
              <th className="px-2 py-1">{t("files.perm.write")}</th>
              <th className="px-2 py-1">{t("files.perm.exec")}</th>
            </tr>
          </thead>
          <tbody>
            {permBits.map((r) => (
              <tr key={r.who}>
                <th className="py-1 pr-3 text-left font-medium">{t(`files.perm.${r.who}`)}</th>
                {r.bits.map((b, i) => (
                  <td key={b} className="px-2 py-1 text-center">
                    <input
                      type="checkbox"
                      aria-label={`${t(`files.perm.${r.who}`)} ${t(["files.perm.read", "files.perm.write", "files.perm.exec"][i] ?? "")}`}
                      checked={(mode & b) !== 0}
                      onChange={() => toggle(b)}
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <div className="flex flex-wrap gap-3">
          {specials.map(([b, k]) => (
            <label key={k} className="flex items-center gap-1.5 text-sm">
              <input type="checkbox" checked={(mode & b) !== 0} onChange={() => toggle(b)} />
              {t(`files.perm.${k}`)}
            </label>
          ))}
        </div>
        {(mode & 0o6000) !== 0 && <Notice tone="warn">{t("files.perm.specialWarning")}</Notice>}
        <Field label={t("files.perm.octal")}>
          {(p) => (
            <input
              {...p}
              className="input w-32 font-mono"
              value={text}
              inputMode="numeric"
              onChange={(e) => {
                setText(e.target.value);
                if (/^[0-7]{3,4}$/.test(e.target.value)) setMode(parseInt(e.target.value, 8));
              }}
            />
          )}
        </Field>
        <p className="font-mono text-sm text-muted">{modeString(mode)}</p>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <Busy busy={busy} disabled={!/^[0-7]{3,4}$/.test(text)}>
            {t("common.save")}
          </Busy>
        </div>
      </form>
    </Modal>
  );
}

function ChownDialog({ entry, onClose, onSubmit }: { entry: FsEntry; onClose: () => void; onSubmit: (user: string, group: string) => Promise<unknown> }) {
  const { t } = useTranslation();
  const [user, setUser] = useState(entry.user ?? "");
  const [group, setGroup] = useState(entry.group ?? "");
  const { busy, wrap } = useBusy();
  const re = /^[a-z_][a-z0-9_.-]{0,31}\$?$/i;
  const ok = (!user || re.test(user)) && (!group || re.test(group)) && (user !== (entry.user ?? "") || group !== (entry.group ?? ""));
  return (
    <Modal title={t("files.chownTitle", { name: shownName(entry) })} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={wrap(() => onSubmit(user, group))}>
        <Field label={t("files.col.user")}>{(p) => <input {...p} className="input font-mono" value={user} onChange={(e) => setUser(e.target.value)} />}</Field>
        <Field label={t("files.col.group")}>
          {(p) => <input {...p} className="input font-mono" value={group} onChange={(e) => setGroup(e.target.value)} />}
        </Field>
        <Explain>{t("files.chownExplain")}</Explain>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <Busy busy={busy} disabled={!ok}>
            {t("common.save")}
          </Busy>
        </div>
      </form>
    </Modal>
  );
}

function PropsDialog({ target, title, onClose }: { target: Target; title: string; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const { run } = useFsRunner();
  const q = useQuery({ queryKey: ["fs-stat", target], queryFn: () => run((f) => fsCall<FsStat>("stat", { ...target }, f)), retry: false });
  const s = q.data;
  const rows: [string, ReactNode][] = s
    ? [
        [t("files.props.path"), <span className="break-all font-mono">{s.path}</span>],
        [t("files.props.type"), t(`files.type.${s.type}`)],
        [t("files.col.size"), `${bytes(s.size, lang)} (${s.size.toLocaleString(lang)} B)`],
        [t("files.col.owner"), `${s.user ?? s.uid} (${s.uid}) : ${s.group ?? s.gid} (${s.gid})`],
        [t("files.col.mode"), <span className="font-mono">{`${modeString(s.mode)} (${octal(s.mode)})`}</span>],
        [t("files.props.mtime"), dateTime(s.mtime, lang)],
        [t("files.props.atime"), dateTime(s.atime, lang)],
        [t("files.props.ctime"), dateTime(s.ctime, lang)],
        [t("files.props.btime"), dateTime(s.btime, lang)],
        [t("files.props.links"), String(s.nlink)],
        [t("files.props.inode"), String(s.inode)],
        [t("files.props.access"), [s.readable && t("files.props.readable"), s.writable && t("files.props.writable")].filter(Boolean).join(", ") || "–"],
      ]
    : [];
  if (s?.type === "symlink") rows.splice(2, 0, [t("files.props.target"), <span className="break-all font-mono">{s.target ?? "?"}</span>]);
  return (
    <Modal title={t("files.propsTitle", { name: title })} onClose={onClose} wide>
      {q.isLoading && <p className="text-muted">{t("common.loading")}</p>}
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {s?.sensitive && (
        <div className="mb-3">
          <Notice tone="warn">{t("files.props.sensitive")}</Notice>
        </div>
      )}
      {s && (
        <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1.5 text-sm">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      )}
    </Modal>
  );
}

function DeleteDialog({ entry, onClose, onSubmit }: { entry: FsEntry; onClose: () => void; onSubmit: (recursive: boolean) => Promise<unknown> }) {
  const { t } = useTranslation();
  const dirEntry = entry.type === "dir";
  const [recursive, setRecursive] = useState(false);
  const [typed, setTyped] = useState("");
  const { busy, wrap } = useBusy();
  const name = shownName(entry);
  return (
    <Modal title={t("files.deleteTitle", { name })} onClose={onClose}>
      <form className="flex flex-col gap-4" onSubmit={wrap(() => onSubmit(recursive))}>
        <Notice tone="warn">{t(dirEntry ? "files.deleteDirWarning" : "files.deleteWarning")}</Notice>
        {entry.type === "symlink" && <p className="text-sm text-muted">{t("files.deleteLink")}</p>}
        {dirEntry && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} />
            {t("files.recursive")}
          </label>
        )}
        {recursive && (
          <Field label={t("files.typeName", { name })}>
            {(p) => <input {...p} className="input font-mono" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />}
          </Field>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <Busy busy={busy} danger disabled={recursive && typed !== name}>
            {t("common.delete")}
          </Busy>
        </div>
      </form>
    </Modal>
  );
}

// --- uploads ---

interface UpItem {
  id: number;
  file: File;
  dir: string;
  loaded: number;
  state: "queued" | "running" | "done" | "error" | "exists" | "cancelled";
  error?: string;
  overwrite?: boolean;
  ctrl?: AbortController;
}

let upSeq = 0;

function useUploads(asRoot: boolean, onDone: () => void) {
  const { t, i18n } = useTranslation();
  const [items, setItems] = useState<UpItem[]>([]);
  const [modeText, setModeText] = useState("0640");
  const ref = useRef<UpItem[]>([]);
  const update = (id: number, patch: Partial<UpItem>) => {
    ref.current = ref.current.map((x) => (x.id === id ? { ...x, ...patch } : x));
    setItems(ref.current);
  };
  const mode = /^[0-7]{3,4}$/.test(modeText) ? parseInt(modeText, 8) & 0o777 : 0o640;

  const pump = () => {
    const running = ref.current.filter((x) => x.state === "running").length;
    const next = ref.current.find((x) => x.state === "queued");
    if (!next || running >= 2) return;
    const ctrl = new AbortController();
    update(next.id, { state: "running", ctrl, loaded: 0 });
    uploadFile(next.file, next.dir, { overwrite: next.overwrite, mode, as_root: asRoot }, (n) => update(next.id, { loaded: n }), ctrl.signal)
      .then(() => {
        update(next.id, { state: "done", loaded: next.file.size });
        onDone();
      })
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.code === "already_exists") update(next.id, { state: "exists" });
        else if (e instanceof ApiError && e.code === "aborted") update(next.id, { state: "cancelled" });
        else update(next.id, { state: "error", error: errorText(t, e) });
      })
      .finally(pump);
    pump();
  };

  const add = (files: File[], dir: string, limit: number) => {
    const fresh = files.map<UpItem>((file) =>
      file.size > limit
        ? { id: ++upSeq, file, dir, loaded: 0, state: "error", error: t("errors.too_large") }
        : { id: ++upSeq, file, dir, loaded: 0, state: "queued" },
    );
    ref.current = [...ref.current.filter((x) => x.state !== "done" && x.state !== "cancelled"), ...fresh];
    setItems(ref.current);
    pump();
  };

  const visible = items.length > 0;
  const view = visible && (
    <Panel className="p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Icon name="upload" className="h-4 w-4 text-cyan" />
          {t("files.upload.title")}
        </h2>
        <span className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-muted">
            {t("files.upload.mode")}
            <input
              className="input min-h-7 w-20 py-0.5 font-mono text-xs"
              value={modeText}
              onChange={(e) => setModeText(e.target.value)}
              aria-invalid={!/^[0-7]{3,4}$/.test(modeText)}
            />
          </label>
          <button
            type="button"
            className="btn btn-ghost min-h-7 px-2 text-xs"
            onClick={() => {
              ref.current = ref.current.filter((x) => x.state === "running" || x.state === "queued");
              setItems(ref.current);
            }}
          >
            {t("files.upload.clear")}
          </button>
        </span>
      </div>
      <ul className="flex flex-col gap-2">
        {items.map((x) => (
          <li key={x.id} className="text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 flex-1 break-all font-mono">{x.file.name}</span>
              <span className="text-xs text-muted">
                {bytes(x.loaded, i18n.language)} / {bytes(x.file.size, i18n.language)}
              </span>
              <span className={`text-xs ${x.state === "error" ? "text-bad" : x.state === "done" ? "text-ok" : "text-muted"}`}>
                {t(`files.upload.state.${x.state}`)}
              </span>
              {(x.state === "running" || x.state === "queued") && (
                <button
                  type="button"
                  className="btn btn-ghost min-h-7 px-2 text-xs"
                  onClick={() => {
                    if (x.state === "running") x.ctrl?.abort();
                    else update(x.id, { state: "cancelled" });
                  }}
                >
                  {t("common.cancel")}
                </button>
              )}
              {x.state === "exists" && (
                <>
                  <button
                    type="button"
                    className="btn btn-danger min-h-7 px-2 text-xs"
                    onClick={() => {
                      update(x.id, { state: "queued", overwrite: true });
                      pump();
                    }}
                  >
                    {t("files.upload.overwrite")}
                  </button>
                  <button type="button" className="btn btn-ghost min-h-7 px-2 text-xs" onClick={() => update(x.id, { state: "cancelled" })}>
                    {t("files.upload.skip")}
                  </button>
                </>
              )}
            </div>
            {x.state === "running" && (
              <div
                className="progress mt-1"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={x.file.size ? Math.round((x.loaded / x.file.size) * 100) : 100}
                aria-label={x.file.name}
              >
                <span style={{ width: `${x.file.size ? (x.loaded / x.file.size) * 100 : 100}%` }} />
              </div>
            )}
            {x.error && <p className="text-xs text-bad">{x.error}</p>}
          </li>
        ))}
      </ul>
    </Panel>
  );
  return { add, view };
}
