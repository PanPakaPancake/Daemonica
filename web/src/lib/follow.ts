import type { TFunction } from "i18next";
import { useEffect, useRef } from "react";
import { api } from "./api";

/** Live follow of a log query over WebSocket (POST /follow/ticket, then
 * /follow/ws). The server sends {entries, skipped} at most once per second;
 * skipped counts entries dropped by its rate limit. Pass params = undefined
 * to stop following. params.after continues from a known cursor. */
export function useFollow<T>(
  op: "journal.query" | "firewall.logs",
  params: Record<string, unknown> | undefined,
  onData: (entries: T[], skipped: number) => void,
  onEnd: (reason: string) => void,
) {
  const data = useRef(onData);
  const end = useRef(onEnd);
  useEffect(() => {
    data.current = onData;
    end.current = onEnd;
  });
  const key = params === undefined ? undefined : JSON.stringify(params);
  useEffect(() => {
    if (key === undefined) return;
    let ws: WebSocket | undefined;
    let closed = false;
    void (async () => {
      try {
        const { ticket } = await api<{ ticket: string }>("POST", "/follow/ticket", { op, params: JSON.parse(key) as unknown });
        if (closed) return;
        ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/v1/follow/ws?ticket=${encodeURIComponent(ticket)}`);
        ws.onmessage = (ev) => {
          const m = JSON.parse(String(ev.data)) as { entries: T[]; skipped: number };
          data.current(m.entries, m.skipped);
        };
        ws.onclose = (ev) => {
          if (!closed) end.current(ev.code === 4000 ? ev.reason : "closed");
        };
      } catch (e) {
        if (!closed) end.current(e instanceof Error ? e.message : "error");
      }
    })();
    return () => {
      closed = true;
      ws?.close();
    };
  }, [op, key]);
}

/** Message for a follow that the server ended ("error:<code>", "allowlist", …). */
export function followEndText(t: TFunction, reason: string): string {
  if (reason.startsWith("error:")) return t(`errors.${reason.slice(6)}`, { defaultValue: t("errors.internal_error") });
  return t("common.followEnded");
}
