import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";
import { errorText } from "../lib/errors";
import { useSession } from "../lib/session";
import { Icon } from "./icons";
import { Notice } from "./ui";

/** A planned change of the Plan → Apply → Confirm flow (SPEC §3.2 rule 10). */
export interface Change {
  id: string;
  summary: string;
  diff: string;
  risk: "low" | "medium" | "high";
  state: "planned" | "applied" | "confirmed" | "rolled_back" | "failed" | "discarded";
  deadline?: string;
}

/** Seconds left until deadline; onExpire fires once from the timer callback. */
export function useCountdown(deadline: string | undefined, onExpire: () => void) {
  const [now, setNow] = useState(() => Date.now());
  const expire = useRef(onExpire);
  useEffect(() => {
    expire.current = onExpire;
  });
  useEffect(() => {
    if (!deadline) return;
    const end = Date.parse(deadline);
    const id = window.setInterval(() => {
      const n = Date.now();
      setNow(n);
      if (n >= end) {
        window.clearInterval(id);
        expire.current();
      }
    }, 500);
    return () => window.clearInterval(id);
  }, [deadline]);
  return deadline ? Math.max(0, Math.ceil((Date.parse(deadline) - now) / 1000)) : 0;
}

export function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="max-h-96 overflow-auto rounded-[8px] border border-line bg-bg-0 p-3 font-mono text-sm">
      {diff.split("\n").map((l, i) => (
        <span
          key={i}
          className={l.startsWith("+++") || l.startsWith("---") ? "text-faint" : l.startsWith("+") ? "text-ok" : l.startsWith("-") ? "text-bad" : "text-muted"}
        >
          {l + "\n"}
        </span>
      ))}
    </pre>
  );
}

/** Preview, apply, confirm (over a new connection) or revert a planned change.
 * ns names the i18n namespace with confirmPrompt, risk.* and rolledBackTimeout. */
export function ChangeFlow({
  change,
  ns,
  onChange,
  onDone,
  children,
}: {
  change: Change;
  ns: string;
  onChange: (c: Change | undefined) => void;
  /** Called when the flow ended; msg describes the outcome. */
  onDone: (msg: string, tone: "ok" | "warn") => void;
  /** Extra hints shown while the change waits for confirmation (e.g. a new URL). */
  children?: ReactNode;
}) {
  const { t } = useTranslation();
  const { withStepUp } = useSession();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  // The helper rolls the change back when the timer runs out, independent of the browser.
  const left = useCountdown(change.state === "applied" ? change.deadline : undefined, () => {
    onChange(undefined);
    onDone(t(`${ns}.rolledBackTimeout`), "warn");
  });

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(undefined);
    try {
      await fn();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };
  const path = (op: string) => `/changes/${encodeURIComponent(change.id)}/${op}`;

  const apply = () => run(async () => onChange(await withStepUp(() => api<Change>("POST", path("apply")))));
  // The confirmation travels over a NEW connection (the apply response closed
  // the old one), which proves the new configuration still admits this browser.
  const confirm = () =>
    run(async () => {
      const c = await api<Change>("POST", path("confirm"));
      onChange(undefined);
      onDone(c.state === "confirmed" ? t("change.confirmed") : "", "ok");
    });
  const rollback = () =>
    run(async () => {
      await api<Change>("POST", path("rollback"));
      onChange(undefined);
      onDone(t("change.rolledBack"), "ok");
    });

  return (
    <div className="flex flex-col gap-4">
      <h3 className="font-semibold">{t("change.preview")}</h3>
      <DiffView diff={change.diff} />
      <p className={change.risk === "high" ? "font-semibold text-bad" : "text-warn"}>{t(`${ns}.risk.${change.risk}`)}</p>
      {err && <Notice tone="bad">{err}</Notice>}
      {change.state === "planned" && (
        <div className="flex flex-wrap gap-2">
          <button type="button" className={`btn ${change.risk === "high" ? "btn-danger" : "btn-primary"}`} disabled={busy} onClick={() => void apply()}>
            {busy ? t("change.applying") : t("change.apply")}
          </button>
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => onChange(undefined)}>
            {t("common.cancel")}
          </button>
        </div>
      )}
      {change.state === "applied" && (
        <>
          <Notice tone="warn" live>
            {t(`${ns}.confirmPrompt`, { seconds: left })}
          </Notice>
          {children}
          <div className="flex flex-wrap gap-2">
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void confirm()}>
              <Icon name="check" />
              {t("change.keep")}
            </button>
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void rollback()}>
              {t("change.undo")}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
