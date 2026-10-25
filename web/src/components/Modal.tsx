import * as Dialog from "@radix-ui/react-dialog";
import { useCallback, useEffect, useId, useRef, useState, type MouseEvent as ReactMouseEvent, type ReactNode, type RefObject } from "react";
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
type MenuPos = { left?: number; right?: number; top?: number; bottom?: number };

const menuWidth = 224;
const menuHeight = (n: number) => n * 34 + 12;

/** The menu list itself, rendered into document.body (no scroll container clips it). */
function MenuPopup({
  id,
  label,
  items,
  pos,
  onClose,
  keep,
}: {
  id?: string;
  label: string;
  items: MenuItem[];
  pos: MenuPos;
  onClose: (refocus: boolean) => void;
  /** Clicks inside this element do not close the menu (its toggle button). */
  keep?: RefObject<HTMLElement | null>;
}) {
  const menu = useRef<HTMLDivElement>(null);
  useEffect(() => {
    menu.current?.querySelector<HTMLButtonElement>("[role=menuitem]:not(:disabled)")?.focus();
    const onDown = (e: MouseEvent) => {
      const n = e.target as Node;
      if (!menu.current?.contains(n) && !keep?.current?.contains(n)) onClose(false);
    };
    const close = () => onClose(false);
    document.addEventListener("mousedown", onDown);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("blur", close);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("blur", close);
    };
  }, [onClose, keep]);

  return createPortal(
    <div
      ref={menu}
      id={id}
      role="menu"
      aria-label={label}
      className="menu-pop fixed z-[55] min-w-52 py-1"
      style={pos}
      onContextMenu={(e) => e.preventDefault()}
      onKeyDown={(e) => {
        if (e.key === "Escape" || e.key === "Tab") {
          e.preventDefault();
          onClose(true);
        }
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const btns = Array.from(menu.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]:not(:disabled)") ?? []);
          const i = btns.indexOf(document.activeElement as HTMLButtonElement);
          btns[(i + (e.key === "ArrowDown" ? 1 : btns.length - 1)) % btns.length]?.focus();
        }
      }}
    >
      {items.map((it) => (
        <button
          key={it.label}
          type="button"
          role="menuitem"
          disabled={it.disabled}
          className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-bg-2 focus:bg-bg-2 focus:outline-none disabled:opacity-50 ${it.danger ? "text-bad" : ""}`}
          onClick={() => {
            onClose(false);
            it.onSelect();
          }}
        >
          {it.icon && <Icon name={it.icon} className="h-4 w-4" />}
          {it.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}

export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [pos, setPos] = useState<MenuPos | null>(null);
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback((refocus: boolean) => {
    setPos(null);
    if (refocus) btn.current?.focus();
  }, []);

  const toggle = () => {
    if (pos || !btn.current) {
      setPos(null);
      return;
    }
    const r = btn.current.getBoundingClientRect();
    const right = Math.max(8, window.innerWidth - r.right);
    if (window.innerHeight - r.bottom < menuHeight(items.length) && r.top > window.innerHeight - r.bottom)
      setPos({ right, bottom: window.innerHeight - r.top + 4 });
    else setPos({ right, top: r.bottom + 4 });
  };

  return (
    <div className="relative">
      <button
        ref={btn}
        type="button"
        className="btn btn-ghost min-h-8 px-2"
        aria-haspopup="menu"
        aria-expanded={!!pos}
        aria-controls={pos ? id : undefined}
        aria-label={label}
        title={label}
        onClick={toggle}
      >
        <Icon name="more" className="h-5 w-5" />
      </button>
      {pos && <MenuPopup id={id} label={label} items={items} pos={pos} onClose={close} keep={btn} />}
    </div>
  );
}

/**
 * Right-click menus: call onContextMenu(event, label, items) from an element's
 * contextmenu handler and render `menu`. The browser's own menu stays
 * available with Shift+right-click, on form fields, links and selected text.
 */
export function useContextMenu() {
  const [state, setState] = useState<{ label: string; items: MenuItem[]; pos: MenuPos } | null>(null);
  const from = useRef<HTMLElement | null>(null);
  const close = useCallback((refocus: boolean) => {
    setState(null);
    if (refocus) from.current?.focus();
  }, []);

  const onContextMenu = useCallback((e: ReactMouseEvent, label: string, items: MenuItem[]) => {
    const target = e.target as HTMLElement;
    if (e.shiftKey || items.length === 0) return;
    if (target.closest("input, textarea, select, a[href], [contenteditable=true]")) return;
    if (window.getSelection()?.toString()) return;
    e.preventDefault();
    let x = e.clientX;
    let y = e.clientY;
    if (x === 0 && y === 0) {
      // keyboard (context-menu key / Shift+F10): open at the element
      const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
      x = r.left + 16;
      y = r.bottom;
    }
    const pos: MenuPos = {};
    if (x + menuWidth > window.innerWidth - 8) pos.right = Math.max(8, window.innerWidth - x);
    else pos.left = x;
    if (y + menuHeight(items.length) > window.innerHeight - 8 && y > window.innerHeight / 2) pos.bottom = window.innerHeight - y;
    else pos.top = y;
    from.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setState({ label, items, pos });
  }, []);

  const menu = state && <MenuPopup label={state.label} items={state.items} pos={state.pos} onClose={close} />;
  return { onContextMenu, menu };
}
