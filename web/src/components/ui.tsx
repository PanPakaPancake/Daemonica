import { useId, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

export function Wordmark({ size = "md" }: { size?: "md" | "lg" }) {
  // Placeholder until the owner's logo/mascot assets are added (SPEC §5.4, STATUS B5).
  const big = size === "lg";
  return (
    <div className="flex items-center gap-2 select-none" aria-label="Daemonia">
      <span aria-hidden="true" className={`font-mono font-semibold text-cyan ${big ? "text-3xl" : "text-lg"}`}>
        &gt;_
      </span>
      <span className={`font-bold grad-text ${big ? "text-4xl" : "text-xl"}`}>Daemonia</span>
    </div>
  );
}

export function Panel({ children, edge = false, className = "" }: { children: ReactNode; edge?: boolean; className?: string }) {
  return <section className={`panel ${edge ? "panel-edge" : ""} p-6 ${className}`}>{children}</section>;
}

type Tone = "info" | "ok" | "warn" | "bad";
const toneIcon: Record<Tone, string> = { info: "ℹ", ok: "✓", warn: "⚠", bad: "✖" };
const toneClass: Record<Tone, string> = { info: "text-info", ok: "text-ok", warn: "text-warn", bad: "text-bad" };

/** Status message: always icon + text, never colour alone (SPEC §5.2). */
export function Notice({ tone, children, live = false }: { tone: Tone; children: ReactNode; live?: boolean }) {
  return (
    <div
      role={tone === "bad" ? "alert" : live ? "status" : undefined}
      className="flex gap-3 rounded-[8px] border border-line bg-bg-2 px-4 py-3"
    >
      <span aria-hidden="true" className={`font-bold ${toneClass[tone]}`}>
        {toneIcon[tone]}
      </span>
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

export function Explain({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <details className="rounded-[8px] border border-line px-4 py-2 text-muted">
      <summary className="cursor-pointer font-medium text-fg">{t("common.whatHappens")}</summary>
      <div className="pt-2">{children}</div>
    </details>
  );
}

export function Field({
  label,
  help,
  error,
  children,
}: {
  label: string;
  help?: string;
  error?: string;
  children: (props: { id: string; "aria-describedby"?: string; "aria-invalid"?: boolean }) => ReactNode;
}) {
  const id = useId();
  const helpId = `${id}-help`;
  const errId = `${id}-err`;
  const describedBy = [help ? helpId : "", error ? errId : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="font-medium">
        {label}
      </label>
      {children({ id, "aria-describedby": describedBy, "aria-invalid": error ? true : undefined })}
      {help && (
        <p id={helpId} className="text-sm text-muted">
          {help}
        </p>
      )}
      {error && (
        <p id={errId} className="text-sm text-bad">
          <span aria-hidden="true">✖ </span>
          {error}
        </p>
      )}
    </div>
  );
}

export function Steps({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex flex-wrap gap-2 text-sm" aria-label="progress">
      {steps.map((s, i) => (
        <li
          key={s}
          aria-current={i === current ? "step" : undefined}
          className={`rounded-full border px-3 py-1 ${
            i === current ? "border-cyan text-fg" : i < current ? "border-line text-muted" : "border-line text-faint"
          }`}
        >
          <span aria-hidden="true">{i < current ? "✓ " : `${i + 1}. `}</span>
          {s}
        </li>
      ))}
    </ol>
  );
}
