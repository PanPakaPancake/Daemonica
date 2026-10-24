import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Icon, type IconName } from "./icons";

export function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  const { t } = useTranslation();
  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60" />
        <Dialog.Content
          className={`panel panel-edge fixed left-1/2 top-1/2 z-50 max-h-[90vh] -translate-x-1/2 -translate-y-1/2 overflow-auto p-6 ${wide ? "w-[min(94vw,760px)]" : "w-[min(94vw,480px)]"}`}
          aria-describedby={undefined}
        >
          <div className="mb-4 flex items-start justify-between gap-3">
            <Dialog.Title className="break-all text-lg font-semibold">{title}</Dialog.Title>
            <Dialog.Close className="btn btn-secondary min-h-8 px-2" aria-label={t("common.close")}>
              <Icon name="close" className="h-4 w-4" />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export interface MenuItem {
  label: string;
  icon?: IconName;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
}

/** Small accessible action menu (button + list of menu items). */
export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const first = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    first.current?.focus();
    const onDown = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);
  return (
    <div
      ref={root}
      className="relative"
      onKeyDown={(e) => {
        if (e.key === "Escape") setOpen(false);
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const btns = Array.from(root.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]:not(:disabled)") ?? []);
          const i = btns.indexOf(document.activeElement as HTMLButtonElement);
          btns[(i + (e.key === "ArrowDown" ? 1 : btns.length - 1)) % btns.length]?.focus();
        }
      }}
    >
      <button
        type="button"
        className="btn btn-ghost min-h-8 px-2"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={id}
        aria-label={label}
        title={label}
        onClick={() => setOpen(!open)}
      >
        <Icon name="more" className="h-5 w-5" />
      </button>
      {open && (
        <div id={id} role="menu" className="menu-pop absolute right-0 z-40 mt-1 min-w-52 py-1">
          {items.map((it, i) => (
            <button
              key={it.label}
              ref={i === 0 ? first : undefined}
              type="button"
              role="menuitem"
              disabled={it.disabled}
              className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-bg-2 focus:bg-bg-2 focus:outline-none disabled:opacity-50 ${it.danger ? "text-bad" : ""}`}
              onClick={() => {
                setOpen(false);
                it.onSelect();
              }}
            >
              {it.icon && <Icon name={it.icon} className="h-4 w-4" />}
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
