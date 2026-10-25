import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
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

/** Small accessible action menu (button + list of menu items). The list is
 * rendered in a portal with fixed positioning so that scroll containers
 * (tables with overflow) never clip it; it opens upwards when there is no
 * room below. */
export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [pos, setPos] = useState<{ right: number; top?: number; bottom?: number } | null>(null);
  const open = pos !== null;
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const first = useRef<HTMLButtonElement>(null);

  const toggle = () => {
    if (open || !btn.current) {
      setPos(null);
      return;
    }
    const r = btn.current.getBoundingClientRect();
    const need = items.length * 34 + 12;
    const right = Math.max(8, window.innerWidth - r.right);
    if (window.innerHeight - r.bottom < need && r.top > window.innerHeight - r.bottom) setPos({ right, bottom: window.innerHeight - r.top + 4 });
    else setPos({ right, top: r.bottom + 4 });
  };

  useEffect(() => {
    if (!open) return;
    first.current?.focus();
    const onDown = (e: MouseEvent) => {
      const n = e.target as Node;
      if (!menu.current?.contains(n) && !btn.current?.contains(n)) setPos(null);
    };
    const close = () => setPos(null);
    document.addEventListener("mousedown", onDown);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [open]);

  return (
    <div
      className="relative"
      onKeyDown={(e) => {
        if (e.key === "Escape" && open) {
          setPos(null);
          btn.current?.focus();
        }
        if (open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
          e.preventDefault();
          const btns = Array.from(menu.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]:not(:disabled)") ?? []);
          const i = btns.indexOf(document.activeElement as HTMLButtonElement);
          btns[(i + (e.key === "ArrowDown" ? 1 : btns.length - 1)) % btns.length]?.focus();
        }
      }}
    >
      <button
        ref={btn}
        type="button"
        className="btn btn-ghost min-h-8 px-2"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={id}
        aria-label={label}
        title={label}
        onClick={toggle}
      >
        <Icon name="more" className="h-5 w-5" />
      </button>
      {pos &&
        createPortal(
          <div
            ref={menu}
            id={id}
            role="menu"
            className="menu-pop fixed z-[55] min-w-52 py-1"
            style={{ right: pos.right, top: pos.top, bottom: pos.bottom }}
          >
            {items.map((it, i) => (
              <button
                key={it.label}
                ref={i === 0 ? first : undefined}
                type="button"
                role="menuitem"
                disabled={it.disabled}
                className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-bg-2 focus:bg-bg-2 focus:outline-none disabled:opacity-50 ${it.danger ? "text-bad" : ""}`}
                onClick={() => {
                  setPos(null);
                  it.onSelect();
                }}
              >
                {it.icon && <Icon name={it.icon} className="h-4 w-4" />}
                {it.label}
              </button>
            ))}
          </div>,
          document.body,
        )}
    </div>
  );
}
