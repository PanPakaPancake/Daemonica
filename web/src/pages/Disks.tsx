// Disks and mounts (SPEC §7.8 M1.7b, DEC-032): block devices, usage and
// inodes, mount/unmount through systemd, fstab edited as a structured list,
// checked with findmnt --verify and applied with a confirmation timer.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ChangeFlow, type Change } from "../components/ChangeFlow";
import { DataTable, type Column } from "../components/DataTable";
import { Icon } from "../components/icons";
import { Menu, Modal, type MenuItem } from "../components/Modal";
import { Explain, Field, Meter, Notice } from "../components/ui";
import { api, ApiError } from "../lib/api";
import {
  addOptions,
  critical,
  entryFor,
  flatten,
  mountable,
  optionTemplates,
  sameEntry,
  type Block,
  type Entry,
  type FstabCheck,
  type MountInfo,
  type MountResult,
  type Overview,
  type Problem,
  type Row,
} from "../lib/disks";
import { errorText } from "../lib/errors";
import { bytes, pct } from "../lib/format";
import { useSession } from "../lib/session";

type Tab = "devices" | "mounts" | "fstab";
const tabs: Tab[] = ["devices", "mounts", "fstab"];
type Done = (d: { msg: string; tone: "ok" | "bad" | "warn" } | undefined) => void;

export function Disks() {
  const { t } = useTranslation();
  const { me } = useSession();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("devices");
  const [done, setDone] = useState<{ msg: string; tone: "ok" | "bad" | "warn" }>();
  const [draft, setDraft] = useState<Entry[]>();
  const [edit, setEdit] = useState<{ entry: Entry; index: number }>();
  const q = useQuery({ queryKey: ["disks"], queryFn: () => api<Overview>("GET", "/disks"), refetchInterval: 30_000 });
  const o = q.data;
  const isAdmin = me?.role === "admin";
  const refresh = () => void qc.invalidateQueries({ queryKey: ["disks"] });
  const entries = draft ?? o?.fstab.entries ?? [];

  const putEntry = (e: Entry, index: number) => {
    const list = [...entries];
    if (index < 0) list.push(e);
    else list[index] = e;
    setDraft(list);
    setTab("fstab");
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">{t("disks.title")}</h1>
        <p className="mt-1 text-muted">{t("disks.intro")}</p>
      </div>
      {q.isError && <Notice tone="bad">{errorText(t, q.error)}</Notice>}
      {o?.error && <Notice tone="warn">{t("disks.lsblkFailed")}</Notice>}
      {done && (
        <Notice tone={done.tone} live>
          {done.msg}
        </Notice>
      )}
      <div role="tablist" aria-label={t("disks.title")} className="relative flex flex-nowrap gap-1 overflow-x-auto border-b border-line">
        {tabs.map((x) => (
          <button
            key={x}
            type="button"
            role="tab"
            id={`disks-tab-${x}`}
            aria-selected={tab === x}
            aria-controls={`disks-panel-${x}`}
            className={`-mb-px shrink-0 border-b-2 px-4 py-2 ${tab === x ? "border-cyan text-fg" : "border-transparent text-muted hover:text-fg"}`}
            onClick={() => setTab(x)}
          >
            {t(`disks.tab.${x}`)}
            {x === "fstab" && draft && <span className="ml-2 text-sm text-warn">●</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`disks-panel-${tab}`} aria-labelledby={`disks-tab-${tab}`}>
        {tab === "devices" && (
          <Devices
            o={o}
            loading={q.isLoading}
            isAdmin={isAdmin}
            onAdd={(b) => setEdit({ entry: entryFor(b, `/mnt/${b.label || b.name}`.replace(/[^A-Za-z0-9/_.-]/g, "-")), index: -1 })}
          />
        )}
        {tab === "mounts" && <Mounts o={o} loading={q.isLoading} isAdmin={isAdmin} onDone={setDone} refresh={refresh} />}
        {tab === "fstab" && (
          <FstabTab
            o={o}
            entries={entries}
            dirty={!!draft}
            isAdmin={isAdmin}
            onEdit={(entry, index) => setEdit({ entry, index })}
            onRemove={(i) => setDraft(entries.filter((_, j) => j !== i))}
            onReset={() => setDraft(undefined)}
            onApplied={(msg, tone) => {
              setDraft(undefined);
              setDone({ msg, tone });
              refresh();
            }}
            onDone={setDone}
            refresh={refresh}
          />
        )}
      </div>
      {edit && (
        <EntryEditor
          entry={edit.entry}
          blocks={o ? flatten(o.blocks) : []}
          isNew={edit.index < 0}
          onClose={() => setEdit(undefined)}
          onSave={(e) => {
            putEntry(e, edit.index);
            setEdit(undefined);
          }}
        />
      )}
    </div>
  );
}

function Devices({ o, loading, isAdmin, onAdd }: { o?: Overview; loading: boolean; isAdmin: boolean; onAdd: (b: Block) => void }) {
  const { t, i18n } = useTranslation();
  const rows = o ? flatten(o.blocks) : undefined;
  const inFstab = (b: Block) => !!o?.fstab.entries.some((e) => (b.uuid && e.spec === `UUID=${b.uuid}`) || e.spec === b.path);
  const items = (b: Row): MenuItem[] => [
    { label: t("disks.addToFstab"), icon: "plus", disabled: !isAdmin || !mountable(b) || inFstab(b), onSelect: () => onAdd(b) },
    { label: t("disks.copyUuid"), icon: "copy", disabled: !b.uuid, onSelect: () => void navigator.clipboard?.writeText(b.uuid ?? "").catch(() => undefined) },
    { label: t("disks.copyPath"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(b.path).catch(() => undefined) },
  ];
  const yes = t("common.yes");
  const no = t("common.no");
  const cols: Column<Row>[] = [
    {
      key: "name",
      label: t("disks.col.device"),
      sortValue: (b) => b.path,
      filter: "text",
      tdClass: "whitespace-nowrap",
      cell: (b) => (
        <span className="font-mono">
          {b.depth > 0 && (
            <span aria-hidden="true" className="text-faint">
              {"  ".repeat(b.depth - 1)}└{" "}
            </span>
          )}
          {b.path}
        </span>
      ),
    },
    { key: "type", label: t("disks.col.type"), sortValue: (b) => b.type, filter: "text", cell: (b) => b.type },
    {
      key: "size",
      label: t("disks.col.size"),
      sortValue: (b) => b.size,
      filter: "bytes",
      tdClass: "whitespace-nowrap",
      cell: (b) => bytes(b.size, i18n.language),
    },
    { key: "fstype", label: t("disks.col.fstype"), sortValue: (b) => b.fstype ?? "", filter: "text", cell: (b) => b.fstype || "–" },
    { key: "label", label: t("disks.col.label"), sortValue: (b) => b.label ?? "", filter: "text", cell: (b) => b.label || "–" },
    {
      key: "uuid",
      label: "UUID",
      sortValue: (b) => b.uuid ?? "",
      filter: "text",
      tdClass: "max-w-[16rem] truncate font-mono text-xs",
      tdTitle: (b) => b.uuid ?? "",
      cell: (b) => b.uuid || "–",
    },
    {
      key: "mounts",
      label: t("disks.col.mountpoints"),
      sortValue: (b) => b.mountpoints.join(" "),
      filter: "text",
      tdClass: "font-mono text-xs",
      cell: (b) => b.mountpoints.join(", ") || "–",
    },
    {
      key: "usage",
      label: t("disks.col.usage"),
      sortValue: (b) => (b.fsused !== undefined && b.fsavail !== undefined && b.fsused + b.fsavail > 0 ? (100 * b.fsused) / (b.fsused + b.fsavail) : null),
      filter: "number",
      tdClass: "min-w-[8rem]",
      cell: (b) =>
        b.fsused !== undefined && b.fsavail !== undefined && b.fsused + b.fsavail > 0 ? (
          <UsageCell pct={(100 * b.fsused) / (b.fsused + b.fsavail)} label={`${b.path}`} />
        ) : (
          "–"
        ),
    },
    { key: "model", label: t("disks.col.model"), sortValue: (b) => b.model ?? "", filter: "text", tdClass: "text-xs", cell: (b) => b.model || "–" },
    {
      key: "flags",
      label: t("disks.col.flags"),
      sortValue: (b) => [b.ro && t("disks.flag.ro"), b.rm && t("disks.flag.rm"), b.rota ? t("disks.flag.hdd") : t("disks.flag.ssd")].filter(Boolean).join(", "),
      filter: "text",
      tdClass: "text-xs",
      cell: (b) => [b.ro && t("disks.flag.ro"), b.rm && t("disks.flag.rm"), b.rota ? t("disks.flag.hdd") : t("disks.flag.ssd")].filter(Boolean).join(", "),
    },
    {
      key: "fstab",
      label: "fstab",
      sortValue: (b) => (inFstab(b) ? yes : no),
      filter: {
        options: [
          { value: yes, label: yes },
          { value: no, label: no },
        ],
      },
      cell: (b) => (inFstab(b) ? yes : <span className="text-faint">{no}</span>),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (b) => <Menu label={t("disks.actionsFor", { name: b.path })} items={items(b)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3">
      <p className="text-sm text-muted">{t("disks.devicesIntro")}</p>
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("disks.tab.devices")}
          columns={cols}
          rows={rows}
          rowKey={(b) => b.path + ":" + b.depth}
          loading={loading}
          className="min-w-[1200px]"
          rowMenu={(b) => ({ label: t("disks.actionsFor", { name: b.path }), items: items(b) })}
          empty={t("disks.noDevices")}
        />
      </div>
    </section>
  );
}

function UsageCell({ pct: v, label }: { pct: number; label: string }) {
  const { i18n } = useTranslation();
  return (
    <span className="flex items-center gap-2">
      <span className="w-16">
        <Meter value={v} label={label} />
      </span>
      <span className="tabular-nums text-xs">{pct(v, i18n.language)}</span>
    </span>
  );
}

function MountFeedback({ r }: { r: MountResult }) {
  const { t } = useTranslation();
  return (
    <>
      {r.users.length > 0 && (
        <>
          <p className="mt-1">{t("disks.busyBy")}</p>
          <ul className="mt-1 list-disc pl-5 font-mono text-xs">
            {r.users.map((u) => (
              <li key={u.pid}>
                {u.comm} (PID {u.pid}, {t(`disks.why.${u.why}`, { defaultValue: u.why })})
              </li>
            ))}
          </ul>
        </>
      )}
      {r.log.length > 0 && <pre className="mt-2 whitespace-pre-wrap break-all font-mono text-xs">{r.log.join("\n")}</pre>}
    </>
  );
}

function useMountAction(onDone: Done, refresh: () => void) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [result, setResult] = useState<{ target: string; mount: boolean; r: MountResult }>();
  const run = async (target: string, mount: boolean) => {
    onDone(undefined);
    setResult(undefined);
    try {
      const r = await withStepUp(() => api<MountResult>("POST", mount ? "/disks/mount" : "/disks/unmount", { target }));
      if (r.ok) onDone({ msg: t(mount ? "disks.mounted" : "disks.unmounted", { target }), tone: "ok" });
      else setResult({ target, mount, r });
    } catch (e) {
      onDone({ msg: e instanceof ApiError && e.code === "protected_mount" ? t("disks.err.protected_mount") : errorText(t, e), tone: "bad" });
    } finally {
      refresh();
    }
  };
  const view = result && (
    <Notice tone="bad" live>
      {t(result.mount ? "disks.mountFailed" : result.r.users.length ? "disks.busy" : "disks.unmountFailed", { target: result.target })}
      <MountFeedback r={result.r} />
    </Notice>
  );
  return { run, view };
}

function Mounts({ o, loading, isAdmin, onDone, refresh }: { o?: Overview; loading: boolean; isAdmin: boolean; onDone: Done; refresh: () => void }) {
  const { t, i18n } = useTranslation();
  const [ask, setAsk] = useState<MountInfo>();
  const { run, view } = useMountAction(onDone, refresh);
  const items = (m: MountInfo): MenuItem[] => [
    {
      label: critical(m.mountpoint) ? t("disks.criticalMount") : t("disks.unmount"),
      icon: "stop",
      danger: true,
      disabled: !isAdmin || critical(m.mountpoint),
      onSelect: () => setAsk(m),
    },
    { label: t("disks.copyPath"), icon: "copy", onSelect: () => void navigator.clipboard?.writeText(m.mountpoint).catch(() => undefined) },
  ];
  const cols: Column<MountInfo>[] = [
    { key: "mp", label: t("disks.col.mountpoint"), sortValue: (m) => m.mountpoint, filter: "text", tdClass: "font-mono", cell: (m) => m.mountpoint },
    { key: "dev", label: t("disks.col.device"), sortValue: (m) => m.device, filter: "text", tdClass: "font-mono text-xs", cell: (m) => m.device },
    { key: "fstype", label: t("disks.col.fstype"), sortValue: (m) => m.fstype, filter: "text", cell: (m) => m.fstype },
    {
      key: "total",
      label: t("disks.col.size"),
      sortValue: (m) => m.total,
      filter: "bytes",
      tdClass: "whitespace-nowrap",
      cell: (m) => bytes(m.total, i18n.language),
    },
    {
      key: "used",
      label: t("disks.col.used"),
      sortValue: (m) => m.used_pct,
      filter: "number",
      tdClass: "min-w-[9rem]",
      cell: (m) => <UsageCell pct={m.used_pct} label={m.mountpoint} />,
    },
    {
      key: "avail",
      label: t("disks.col.available"),
      sortValue: (m) => m.available,
      filter: "bytes",
      tdClass: "whitespace-nowrap",
      cell: (m) => bytes(m.available, i18n.language),
    },
    {
      key: "inodes",
      label: t("disks.col.inodes"),
      sortValue: (m) => (m.inodes_total > 0 ? m.inodes_pct : null),
      filter: "number",
      tdClass: "min-w-[9rem]",
      cell: (m) => (m.inodes_total > 0 ? <UsageCell pct={m.inodes_pct} label={`${m.mountpoint} inodes`} /> : "–"),
    },
    {
      key: "ro",
      label: t("disks.col.mode"),
      sortValue: (m) => (m.read_only ? t("disks.flag.ro") : t("disks.flag.rw")),
      filter: {
        options: [
          { value: t("disks.flag.rw"), label: t("disks.flag.rw") },
          { value: t("disks.flag.ro"), label: t("disks.flag.ro") },
        ],
      },
      cell: (m) => (m.read_only ? t("disks.flag.ro") : t("disks.flag.rw")),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (m) => <Menu label={t("disks.actionsFor", { name: m.mountpoint })} items={items(m)} />,
    },
  ];
  return (
    <section className="flex flex-col gap-3">
      {view}
      <div className="relative overflow-x-auto">
        <DataTable
          label={t("disks.tab.mounts")}
          columns={cols}
          rows={o?.mounts}
          rowKey={(m) => m.mountpoint}
          loading={loading}
          defaultSort={{ key: "mp", desc: false }}
          className="min-w-[1000px]"
          rowMenu={(m) => ({ label: t("disks.actionsFor", { name: m.mountpoint }), items: items(m) })}
          empty={t("disks.noMounts")}
        />
      </div>
      {o && o.swaps.length > 0 && (
        <p className="text-sm text-muted">
          {t("disks.swap")}:{" "}
          {o.swaps.map((s) => (
            <span key={s.device} className="mr-3">
              <span className="font-mono">{s.device}</span> {bytes(s.used, i18n.language)} / {bytes(s.size, i18n.language)}
            </span>
          ))}
        </p>
      )}
      {ask && (
        <Modal title={t("disks.unmountTitle", { target: ask.mountpoint })} onClose={() => setAsk(undefined)}>
          <p>{t("disks.unmountConfirm", { target: ask.mountpoint })}</p>
          <div className="mt-6 flex justify-end gap-2">
            <button type="button" className="btn btn-secondary" onClick={() => setAsk(undefined)}>
              {t("common.cancel")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                const m = ask;
                setAsk(undefined);
                void run(m.mountpoint, false);
              }}
            >
              <Icon name="stop" className="h-4 w-4" />
              {t("disks.unmount")}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function problemText(t: (k: string, o?: Record<string, unknown>) => string, p: Problem): string {
  if (p.code === "verify") return p.msg ?? "";
  return t(`disks.problem.${p.code}`, { field: p.field ? t(`disks.field.${p.field}`) : "" });
}

function FstabTab({
  o,
  entries,
  dirty,
  isAdmin,
  onEdit,
  onRemove,
  onReset,
  onApplied,
  onDone,
  refresh,
}: {
  o?: Overview;
  entries: Entry[];
  dirty: boolean;
  isAdmin: boolean;
  onEdit: (e: Entry, i: number) => void;
  onRemove: (i: number) => void;
  onReset: () => void;
  onApplied: (msg: string, tone: "ok" | "warn") => void;
  onDone: Done;
  refresh: () => void;
}) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [check, setCheck] = useState<FstabCheck>();
  const [change, setChange] = useState<Change>();
  const [busy, setBusy] = useState(false);
  const { run, view } = useMountAction(onDone, refresh);
  const mounted = new Set((o?.mounts ?? []).map((m) => m.mountpoint));
  const orig = o?.fstab.entries ?? [];
  const changed = (e: Entry) => e.line === 0 || !orig.some((x) => x.line === e.line && sameEntry(x, e));
  const problemsAt = (i: number) => (check?.problems ?? []).filter((p) => p.index === i);

  const items = (e: Entry, i: number): MenuItem[] => {
    const isMounted = mounted.has(e.file);
    const swap = e.type === "swap";
    return [
      { label: t("common.edit"), icon: "edit", disabled: !isAdmin, onSelect: () => onEdit(e, i) },
      {
        label: t("disks.mount"),
        icon: "play",
        disabled: !isAdmin || swap || isMounted || dirty || e.line === 0,
        onSelect: () => void run(e.file, true),
      },
      {
        label: critical(e.file) ? t("disks.criticalMount") : t("disks.unmount"),
        icon: "stop",
        disabled: !isAdmin || swap || !isMounted || critical(e.file),
        onSelect: () => void run(e.file, false),
      },
      { label: t("common.remove"), icon: "trash", danger: true, disabled: !isAdmin || e.file === "/", onSelect: () => onRemove(i) },
    ];
  };
  const indexed = entries.map((e, i) => ({ ...e, i }));
  type R = (typeof indexed)[number];
  const cols: Column<R>[] = [
    {
      key: "spec",
      label: t("disks.field.spec"),
      sortValue: (e) => e.spec,
      filter: "text",
      tdClass: "max-w-[20rem] truncate font-mono text-xs",
      tdTitle: (e) => e.spec,
      cell: (e) => (
        <span>
          {changed(e) && (
            <span className="mr-1 text-warn" title={t("disks.changedEntry")}>
              ●
            </span>
          )}
          {e.spec}
        </span>
      ),
    },
    { key: "file", label: t("disks.field.file"), sortValue: (e) => e.file, filter: "text", tdClass: "font-mono", cell: (e) => e.file },
    { key: "type", label: t("disks.field.type"), sortValue: (e) => e.type, filter: "text", cell: (e) => e.type },
    { key: "options", label: t("disks.field.options"), sortValue: (e) => e.options, filter: "text", tdClass: "font-mono text-xs", cell: (e) => e.options },
    { key: "freq", label: t("disks.field.freq"), sortValue: (e) => e.freq, filter: "number", cell: (e) => e.freq },
    { key: "pass", label: t("disks.field.pass"), sortValue: (e) => e.pass, filter: "number", cell: (e) => e.pass },
    {
      key: "state",
      label: t("disks.col.state"),
      sortValue: (e) => (e.type === "swap" ? "swap" : mounted.has(e.file) ? t("disks.isMounted") : t("disks.notMounted")),
      filter: "text",
      cell: (e) =>
        e.type === "swap" ? (
          "swap"
        ) : mounted.has(e.file) ? (
          <span className="text-ok">✓ {t("disks.isMounted")}</span>
        ) : (
          <span className="text-muted">{t("disks.notMounted")}</span>
        ),
    },
    {
      key: "problems",
      label: t("disks.col.problems"),
      filter: false,
      cell: (e) =>
        problemsAt(e.i).map((p) => (
          <span key={p.code + p.field} className={`block text-xs ${p.warning ? "text-warn" : "text-bad"}`}>
            {p.warning ? "⚠" : "✖"} {problemText(t, p)}
          </span>
        )),
    },
    {
      key: "actions",
      label: t("common.actions"),
      srOnly: true,
      tdClass: "text-right",
      cell: (e) => <Menu label={t("disks.actionsFor", { name: e.file })} items={items(e, e.i)} />,
    },
  ];

  const plan = async () => {
    setBusy(true);
    onDone(undefined);
    try {
      const r = await withStepUp(() => api<FstabCheck>("POST", "/disks/fstab_plan", { entries }));
      setCheck(r);
      if (r.change) setChange(r.change);
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setBusy(false);
    }
  };
  const verify = async () => {
    setBusy(true);
    try {
      setCheck(await api<FstabCheck>("POST", "/disks/fstab_check", { entries }));
    } catch (e) {
      onDone({ msg: errorText(t, e), tone: "bad" });
    } finally {
      setBusy(false);
    }
  };
  const global = (check?.problems ?? []).filter((p) => p.index < 0);

  return (
    <section className="flex flex-col gap-3">
      <div className="relative flex flex-nowrap items-center gap-2 overflow-x-auto">
        <p className="mr-auto min-w-0 truncate text-sm text-muted">{dirty ? t("disks.unsaved") : t("disks.fstabIntro")}</p>
        <button
          type="button"
          className="btn btn-secondary min-h-9 shrink-0"
          disabled={!isAdmin}
          onClick={() => onEdit({ spec: "", file: "", type: "ext4", options: "defaults,nofail", freq: 0, pass: 2, line: 0 }, -1)}
        >
          <Icon name="plus" className="h-4 w-4" />
          {t("disks.addEntry")}
        </button>
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={busy} onClick={() => void verify()}>
          <Icon name="check" className="h-4 w-4" />
          {t("disks.verify")}
        </button>
        <button type="button" className="btn btn-secondary min-h-9 shrink-0" disabled={!dirty || busy} onClick={onReset}>
          {t("disks.discard")}
        </button>
        <button type="button" className="btn btn-primary min-h-9 shrink-0" disabled={!isAdmin || !dirty || busy} onClick={() => void plan()}>
          <Icon name="save" className="h-4 w-4" />
          {t("disks.saveFstab")}
        </button>
      </div>
      {view}
      {(o?.fstab.errors ?? []).length > 0 && <Notice tone="warn">{t("disks.unparsed", { lines: (o?.fstab.errors ?? []).join(" · ") })}</Notice>}
      {check && check.blocking && <Notice tone="bad">{t("disks.rejected")}</Notice>}
      {check && !check.blocking && !check.change && <Notice tone="ok">{t("disks.verifyOk")}</Notice>}
      {global.length > 0 && (
        <Notice tone={global.some((p) => !p.warning) ? "bad" : "warn"}>
          <ul className="list-disc pl-5 text-sm">
            {global.map((p, i) => (
              <li key={i} className={p.warning ? "" : "text-bad"}>
                {problemText(t, p)}
              </li>
            ))}
          </ul>
        </Notice>
      )}
      <div className="relative overflow-x-auto">
        <DataTable
          label="fstab"
          columns={cols}
          rows={o ? indexed : undefined}
          rowKey={(e) => `${e.i}`}
          className="min-w-[1100px]"
          rowMenu={(e) => ({ label: t("disks.actionsFor", { name: e.file }), items: items(e, e.i) })}
          empty={t("disks.noEntries")}
        />
      </div>
      <Explain>
        <p>{t("disks.fstabExplain")}</p>
      </Explain>
      {change && (
        <Modal title={t("disks.applyTitle")} onClose={() => change.state !== "applied" && setChange(undefined)} wide>
          <ChangeFlow
            change={change}
            ns="disks"
            onChange={(c) => (c ? setChange({ ...change, ...c }) : setChange(undefined))}
            onDone={(msg, tone) => {
              setCheck(undefined);
              onApplied(msg || t("disks.saved"), tone);
            }}
          />
        </Modal>
      )}
    </section>
  );
}

function EntryEditor({
  entry,
  blocks,
  isNew,
  onClose,
  onSave,
}: {
  entry: Entry;
  blocks: Row[];
  isNew: boolean;
  onClose: () => void;
  onSave: (e: Entry) => void;
}) {
  const { t } = useTranslation();
  const [e, setE] = useState<Entry>(entry);
  const set = (p: Partial<Entry>) => setE({ ...e, ...p });
  const devices = blocks.filter((b) => b.fstype);
  const fileErr = e.type !== "swap" && !e.file.startsWith("/") ? t("disks.fileInvalid") : undefined;
  const specErr = e.spec.trim() === "" ? t("disks.specMissing") : undefined;
  const kernelName = /^\/dev\/(sd|vd|xvd|nvme|hd|mmcblk)/.test(e.spec);
  return (
    <Modal title={isNew ? t("disks.addEntry") : t("disks.editEntry", { file: entry.file })} onClose={onClose} wide>
      <form
        className="flex flex-col gap-4"
        onSubmit={(ev) => {
          ev.preventDefault();
          if (!fileErr && !specErr) onSave({ ...e, spec: e.spec.trim(), file: e.file.trim(), options: e.options.trim() || "defaults" });
        }}
      >
        <Field label={t("disks.field.spec")} help={kernelName ? t("disks.preferUuid") : t("disks.specHelp")} error={specErr}>
          {(p) => (
            <>
              <input {...p} className="input font-mono" list="disk-devices" value={e.spec} onChange={(x) => set({ spec: x.target.value })} />
              <datalist id="disk-devices">
                {devices.map((b) => (
                  <option key={b.path} value={b.uuid ? `UUID=${b.uuid}` : b.path}>
                    {`${b.path} ${b.fstype ?? ""} ${b.label ?? ""}`}
                  </option>
                ))}
              </datalist>
            </>
          )}
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("disks.field.file")} error={fileErr}>
            {(p) => <input {...p} className="input font-mono" value={e.file} placeholder="/srv/data" onChange={(x) => set({ file: x.target.value })} />}
          </Field>
          <Field label={t("disks.field.type")}>
            {(p) => <input {...p} className="input font-mono" list="disk-fstypes" value={e.type} onChange={(x) => set({ type: x.target.value })} />}
          </Field>
          <datalist id="disk-fstypes">
            {["ext4", "xfs", "btrfs", "vfat", "swap", "tmpfs", "nfs", "nfs4", "cifs", "auto"].map((x) => (
              <option key={x} value={x} />
            ))}
          </datalist>
        </div>
        <Field label={t("disks.field.options")} help={t("disks.optionsHelp")}>
          {(p) => <input {...p} className="input font-mono" value={e.options} onChange={(x) => set({ options: x.target.value })} />}
        </Field>
        <div className="flex flex-wrap gap-2" role="group" aria-label={t("disks.templates")}>
          {optionTemplates.map((o) => (
            <button key={o} type="button" className="btn btn-secondary min-h-8 font-mono text-xs" onClick={() => set({ options: addOptions(e.options, o) })}>
              + {o}
            </button>
          ))}
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("disks.field.freq")}>
            {(p) => (
              <select {...p} className="input" value={e.freq} onChange={(x) => set({ freq: Number(x.target.value) })}>
                <option value={0}>0</option>
                <option value={1}>1</option>
              </select>
            )}
          </Field>
          <Field label={t("disks.field.pass")} help={t("disks.passHelp")}>
            {(p) => (
              <select {...p} className="input" value={e.pass} onChange={(x) => set({ pass: Number(x.target.value) })}>
                <option value={0}>0</option>
                <option value={1}>1</option>
                <option value={2}>2</option>
              </select>
            )}
          </Field>
        </div>
        {e.type !== "swap" && e.file !== "/" && !`,${e.options},`.includes(",nofail,") && <Notice tone="warn">{t("disks.nofailHint")}</Notice>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!!fileErr || !!specErr}>
            <Icon name="check" className="h-4 w-4" />
            {t("disks.takeOver")}
          </button>
        </div>
      </form>
    </Modal>
  );
}
