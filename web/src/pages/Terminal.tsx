import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import "@xterm/xterm/css/xterm.css";
import { Icon } from "../components/icons";
import { Notice } from "../components/ui";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import { MAX_TERMINALS, useTerminals, type TermMode, type TermTab } from "../lib/terminals";

/** mm:ss until t (ms), "0:00" when over. */
export function leftUntil(t: number, now: number): string {
  const s = Math.max(0, Math.floor((t - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function useNow(enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [enabled]);
  return now;
}

export function TerminalPage() {
  const { t } = useTranslation();
  const { me } = useSession();
  const { tabs, active, setActive, open, close } = useTerminals();
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);
  const isAdmin = me?.role === "admin";
  const tab = tabs.find((x) => x.id === active);
  const full = tabs.length >= MAX_TERMINALS;

  const start = async (mode: TermMode, input?: string) => {
    setErr(undefined);
    setBusy(true);
    try {
      await open(mode, input);
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  // "Run in terminal" from the script library: a new standard shell with the
  // command typed in, waiting for Enter.
  const loc = useLocation();
  const nav = useNavigate();
  const input = (loc.state as { input?: string } | null)?.input;
  const handled = useRef(false);
  useEffect(() => {
    if (!input || handled.current || me?.role === "readonly" || full) return;
    handled.current = true;
    void nav(loc.pathname, { replace: true, state: null });
    void start("standard", input);
  });

  if (me?.role === "readonly") return <Notice tone="info">{t("terminal.readonly")}</Notice>;

  return (
    <div className="flex h-[calc(100dvh-7.5rem)] min-h-[420px] flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">{t("terminal.title")}</h1>
          <p className="mt-1 text-muted">
            {t("terminal.intro", { user: me?.linux_user })} {t(`terminal.note.${tab?.mode ?? "standard"}`, { user: tab?.user ?? me?.linux_user })}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn btn-primary" disabled={busy || full} onClick={() => void start("standard")} title={t("terminal.newHint")}>
            <Icon name="plus" className="h-4 w-4" />
            {t("terminal.new")}
          </button>
          {isAdmin && (
            <>
              <button type="button" className="btn btn-danger" disabled={busy || full} onClick={() => void start("root")} title={t("terminal.rootHint")}>
                <Icon name="shield" className="h-4 w-4" />
                {t("terminal.root")}
              </button>
              <button type="button" className="btn btn-secondary" disabled={busy || full} onClick={() => void start("sudo")} title={t("terminal.sudoHint")}>
                <Icon name="shield" className="h-4 w-4" />
                {t("terminal.sudo")}
              </button>
            </>
          )}
        </div>
      </div>

      {err && (
        <Notice tone="bad" live>
          {err}
        </Notice>
      )}
      {full && <Notice tone="info">{t("terminal.full", { max: MAX_TERMINALS })}</Notice>}

      {tabs.length === 0 ? (
        <div className="grid flex-1 place-items-center rounded-[12px] border border-dashed border-line p-6 text-center text-muted">
          <div>
            <Icon name="terminal" className="mx-auto h-10 w-10 text-faint" />
            <p className="mt-3">{t("terminal.empty")}</p>
            <p className="mt-1 text-sm text-faint">{t("terminal.keys")}</p>
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-[12px] border border-line bg-[#0d0a14]">
          <div className="relative flex items-center gap-1 overflow-x-auto border-b border-line bg-bg-1 px-1" role="tablist" aria-label={t("terminal.tabs")}>
            {tabs.map((x) => (
              <div key={x.id} className={`flex shrink-0 items-center rounded-t-[8px] ${x.id === active ? "bg-[#0d0a14] text-fg" : "text-muted hover:text-fg"}`}>
                <button
                  type="button"
                  role="tab"
                  aria-selected={x.id === active}
                  className={`flex items-center gap-1.5 py-2 pl-3 pr-1 font-mono text-sm ${x.status === "ended" ? "opacity-60" : ""}`}
                  onClick={() => setActive(x.id)}
                >
                  {x.mode !== "standard" && <Icon name="shield" className="h-3.5 w-3.5 text-bad" />}
                  {x.user ?? "…"} #{x.n}
                </button>
                <button type="button" className="rounded p-1 text-faint hover:text-fg" title={t("terminal.close")} onClick={() => close(x.id)}>
                  <Icon name="close" className="h-3.5 w-3.5" />
                  <span className="sr-only">{t("terminal.close")}</span>
                </button>
              </div>
            ))}
          </div>
          {tab && <TabView key={tab.id} tab={tab} onReopen={() => void start(tab.mode)} onClose={() => close(tab.id)} />}
        </div>
      )}
    </div>
  );
}

function endText(t: TFunction, reason = "connection"): string {
  if (reason.startsWith("error:")) return t(`errors.${reason.slice(6)}`, { defaultValue: t("errors.internal_error") });
  return t(`terminal.ended.${reason}`, { defaultValue: t("terminal.ended.connection") });
}

function TabView({ tab, onReopen, onClose }: { tab: TermTab; onReopen: () => void; onClose: () => void }) {
  const { t } = useTranslation();
  const host = useRef<HTMLDivElement>(null);
  const [searching, setSearching] = useState(false);
  const [q, setQ] = useState("");
  const elevated = tab.mode !== "standard";
  const now = useNow(elevated && tab.status !== "ended");

  // Attach the tab's terminal element while shown; keep it fitted to the space.
  useEffect(() => {
    const h = host.current;
    if (!h) return;
    h.appendChild(tab.el);
    if (!tab.term.element) tab.term.open(tab.el);
    const fit = () => {
      try {
        tab.fit.fit();
      } catch {
        // not laid out yet
      }
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(h);
    tab.term.focus();
    return () => {
      ro.disconnect();
      tab.el.remove();
    };
  }, [tab]);

  const find = (next: boolean) => {
    if (!q) return;
    if (next) tab.search.findNext(q);
    else tab.search.findPrevious(q);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {elevated && (
        <div className="elevated-bar flex flex-wrap items-center justify-between gap-2 px-3 py-1 text-sm font-semibold" role="status">
          <span className="flex items-center gap-2">
            <Icon name="shield" className="h-4 w-4" />
            {t(tab.mode === "root" ? "terminal.elevatedRoot" : "terminal.elevatedSudo", { user: tab.user })}
          </span>
          {tab.until && tab.status !== "ended" && <span>{t("terminal.endsIn", { time: leftUntil(tab.until, now) })}</span>}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-1 border-b border-line bg-bg-1/60 px-2 py-1">
        <button
          type="button"
          className={`btn btn-ghost min-h-8 px-2 ${searching ? "text-violet" : ""}`}
          title={t("terminal.search")}
          aria-pressed={searching}
          onClick={() => setSearching(!searching)}
        >
          <Icon name="search" className="h-4 w-4" />
          <span className="sr-only">{t("terminal.search")}</span>
        </button>
        <button
          type="button"
          className="btn btn-ghost min-h-8 px-2"
          title={t("terminal.copy")}
          onClick={() => {
            const sel = tab.term.getSelection();
            if (sel) void navigator.clipboard?.writeText(sel).catch(() => undefined);
            tab.term.focus();
          }}
        >
          <Icon name="copy" className="h-4 w-4" />
          <span className="sr-only">{t("terminal.copy")}</span>
        </button>
        <button
          type="button"
          className="btn btn-ghost min-h-8 px-2"
          title={t("terminal.paste")}
          disabled={tab.status !== "open"}
          onClick={() =>
            void navigator.clipboard
              ?.readText()
              .then((txt) => {
                tab.term.paste(txt);
                tab.term.focus();
              })
              .catch(() => undefined)
          }
        >
          <Icon name="paste" className="h-4 w-4" />
          <span className="sr-only">{t("terminal.paste")}</span>
        </button>
        {searching && (
          <form
            className="flex items-center gap-1"
            onSubmit={(e) => {
              e.preventDefault();
              find(true);
            }}
          >
            <input
              className="input min-h-8 w-48 px-2 py-1 text-sm"
              value={q}
              autoFocus
              placeholder={t("terminal.searchPlaceholder")}
              aria-label={t("terminal.search")}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") {
                  setSearching(false);
                  tab.term.focus();
                }
              }}
            />
            <button type="button" className="btn btn-ghost min-h-8 px-2" title={t("terminal.prev")} onClick={() => find(false)}>
              <Icon name="arrowUp" className="h-4 w-4" />
              <span className="sr-only">{t("terminal.prev")}</span>
            </button>
            <button type="submit" className="btn btn-ghost min-h-8 px-2" title={t("terminal.next")}>
              <Icon name="arrowUp" className="h-4 w-4 rotate-180" />
              <span className="sr-only">{t("terminal.next")}</span>
            </button>
          </form>
        )}
        <span className="ml-auto text-xs text-faint">{tab.status === "connecting" ? t("terminal.connecting") : t("terminal.keys")}</span>
      </div>
      <div className="relative min-h-0 flex-1">
        <div ref={host} className="absolute inset-0 p-2" />
        {tab.status === "ended" && (
          <div className="absolute inset-x-0 bottom-0 flex flex-wrap items-center justify-between gap-2 border-t border-line bg-bg-1/95 px-3 py-2 text-sm">
            <span>{endText(t, tab.reason)}</span>
            <span className="flex gap-2">
              <button type="button" className="btn btn-secondary min-h-8" onClick={onReopen}>
                {t("terminal.reopen")}
              </button>
              <button type="button" className="btn btn-ghost min-h-8" onClick={onClose}>
                {t("terminal.close")}
              </button>
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
