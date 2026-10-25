// Web terminal sessions (SPEC §7.5). Terminals live in this provider, not in
// the page, so they keep running while the user looks at other pages. Each
// tab owns an xterm.js instance rendered into its own element, which the
// terminal page attaches while it is shown.
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Terminal } from "@xterm/xterm";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "./api";
import { useSession } from "./session";

export type TermMode = "standard" | "root" | "sudo";
export const MAX_TERMINALS = 5;

export interface TermTab {
  id: string;
  n: number;
  mode: TermMode;
  status: "connecting" | "open" | "ended";
  /** End reason sent by the server (exit, idle, expired, session_ended, allowlist, …). */
  reason?: string;
  user?: string;
  /** End of an elevated session (ms). */
  until?: number;
  term: Terminal;
  fit: FitAddon;
  search: SearchAddon;
  el: HTMLDivElement;
}

interface TicketInfo {
  mode: TermMode;
  user: string;
  idle_minutes: number;
  until?: string;
}

interface Ctx {
  tabs: TermTab[];
  active?: string;
  setActive: (id: string) => void;
  /** input is typed into the new shell (not sent with Enter). */
  open: (mode: TermMode, input?: string) => Promise<void>;
  close: (id: string) => void;
}

const TermCtx = createContext<Ctx | null>(null);

export function useTerminals(): Ctx {
  const c = useContext(TermCtx);
  if (!c) throw new Error("TerminalProvider missing");
  return c;
}

const enc = new TextEncoder();

function frame(type: "d" | "r", body: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(body.length + 1);
  out[0] = type.charCodeAt(0);
  out.set(body, 1);
  return out;
}

function resizeFrame(cols: number, rows: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint16(0, cols);
  new DataView(b.buffer).setUint16(2, rows);
  return frame("r", b);
}

const theme = {
  background: "#0d0a14",
  foreground: "#e6e1f0",
  cursor: "#c084fc",
  selectionBackground: "#7c3aed66",
  black: "#1c1726",
  red: "#f87171",
  green: "#4ade80",
  yellow: "#facc15",
  blue: "#60a5fa",
  magenta: "#c084fc",
  cyan: "#22d3ee",
  white: "#e6e1f0",
  brightBlack: "#6b6380",
  brightRed: "#fca5a5",
  brightGreen: "#86efac",
  brightYellow: "#fde047",
  brightBlue: "#93c5fd",
  brightMagenta: "#d8b4fe",
  brightCyan: "#67e8f9",
  brightWhite: "#ffffff",
};

export function TerminalProvider({ children }: { children: ReactNode }) {
  const { withStepUp } = useSession();
  const [tabs, setTabs] = useState<TermTab[]>([]);
  const [active, setActive] = useState<string>();
  const sockets = useRef(new Map<string, WebSocket>());
  const counter = useRef(0);
  const tabsRef = useRef(tabs);
  useEffect(() => {
    tabsRef.current = tabs;
  }, [tabs]);

  const update = useCallback((id: string, patch: Partial<TermTab>) => setTabs((ts) => ts.map((t) => (t.id === id ? { ...t, ...patch } : t))), []);

  const open = useCallback(
    async (mode: TermMode, input?: string) => {
      const term = new Terminal({
        cursorBlink: true,
        fontFamily: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 14,
        scrollback: 5000,
        theme,
        allowProposedApi: false,
      });
      const fit = new FitAddon();
      const search = new SearchAddon();
      term.loadAddon(fit);
      term.loadAddon(search);
      const el = document.createElement("div");
      el.className = "h-full w-full";
      // The size is only known once the element is shown; ask the server for a sensible default.
      const { ticket, info } = await withStepUp(() =>
        api<{ ticket: string; info: TicketInfo }>("POST", "/terminal/ticket", { mode, cols: term.cols, rows: term.rows }),
      );
      const id = crypto.randomUUID();
      counter.current += 1;
      const tab: TermTab = {
        id,
        n: counter.current,
        mode,
        status: "connecting",
        user: info.user,
        until: info.until ? Date.parse(info.until) : undefined,
        term,
        fit,
        search,
        el,
      };
      setTabs((ts) => [...ts, tab]);
      setActive(id);

      const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/v1/terminal/ws?ticket=${encodeURIComponent(ticket)}`);
      ws.binaryType = "arraybuffer";
      sockets.current.set(id, ws);
      const send = (b: Uint8Array<ArrayBuffer>) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(b);
      };
      ws.onopen = () => {
        update(id, { status: "open" });
        send(resizeFrame(term.cols, term.rows));
        if (input) send(frame("d", enc.encode(input.replace(/[\r\n]/g, ""))));
      };
      ws.onmessage = (ev) => term.write(new Uint8Array(ev.data as ArrayBuffer));
      ws.onclose = (ev) => {
        sockets.current.delete(id);
        const reason = ev.code === 4000 && ev.reason ? ev.reason : "connection";
        update(id, { status: "ended", reason });
      };
      term.onData((d) => send(frame("d", enc.encode(d))));
      term.onBinary((d) =>
        send(
          frame(
            "d",
            Uint8Array.from(d, (c) => c.charCodeAt(0) & 0xff),
          ),
        ),
      );
      term.onResize(({ cols, rows }) => send(resizeFrame(cols, rows)));
      term.attachCustomKeyEventHandler((e) => {
        if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey) return true;
        if (e.code === "KeyC") {
          const sel = term.getSelection();
          if (sel) void navigator.clipboard?.writeText(sel).catch(() => undefined);
          return false;
        }
        if (e.code === "KeyV") {
          void navigator.clipboard
            ?.readText()
            .then((txt) => term.paste(txt))
            .catch(() => undefined);
          return false;
        }
        return true;
      });
    },
    [withStepUp, update],
  );

  const close = useCallback((id: string) => {
    sockets.current.get(id)?.close(1000);
    sockets.current.delete(id);
    tabsRef.current.find((x) => x.id === id)?.term.dispose();
    const rest = tabsRef.current.filter((x) => x.id !== id);
    setTabs((ts) => ts.filter((x) => x.id !== id));
    setActive((a) => (a === id ? rest[rest.length - 1]?.id : a));
  }, []);

  // Leaving the signed-in area (logout) ends all terminals; the server ends them as well.
  useEffect(
    () => () => {
      for (const ws of sockets.current.values()) ws.close(1000);
      sockets.current.clear();
      for (const t of tabsRef.current) t.term.dispose();
    },
    [],
  );

  const value = useMemo(() => ({ tabs, active, setActive, open, close }), [tabs, active, open, close]);
  return <TermCtx.Provider value={value}>{children}</TermCtx.Provider>;
}
