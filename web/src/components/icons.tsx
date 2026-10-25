// Self-drawn 24×24 stroke icons (no icon dependency, DEC-013). Purely
// decorative: always aria-hidden, the accompanying text carries the meaning.
import type { ReactNode } from "react";

export type IconName =
  | "overview"
  | "services"
  | "jobs"
  | "system"
  | "users"
  | "key"
  | "network"
  | "firewall"
  | "updates"
  | "disk"
  | "clock"
  | "terminal"
  | "files"
  | "logs"
  | "process"
  | "capture"
  | "shield"
  | "passkey"
  | "sessions"
  | "audit"
  | "settings"
  | "sun"
  | "moon"
  | "logout"
  | "language"
  | "menu"
  | "play"
  | "stop"
  | "restart"
  | "search"
  | "download"
  | "signal"
  | "close"
  | "chevronLeft"
  | "chevronRight"
  | "check"
  | "folder"
  | "file"
  | "link"
  | "upload"
  | "more"
  | "eye"
  | "eyeOff"
  | "edit"
  | "trash"
  | "copy"
  | "move"
  | "lock"
  | "info"
  | "home"
  | "plus"
  | "save"
  | "arrowUp"
  | "folderPlus"
  | "filePlus"
  | "filter"
  | "viewList"
  | "viewGrid"
  | "viewCompact"
  | "paste";

const paths: Record<IconName, ReactNode> = {
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </>
  ),
  services: (
    <>
      <rect x="3" y="4" width="18" height="6" rx="1.5" />
      <rect x="3" y="14" width="18" height="6" rx="1.5" />
      <path d="M7 7h.01M7 17h.01" />
    </>
  ),
  jobs: (
    <>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M3 10h18M8 3v4M16 3v4M9 15l2 2 4-4" />
    </>
  ),
  system: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" rx="1" />
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5" />
      <path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.8c1.8.8 3 2.6 3.5 5.2" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4.5" />
      <path d="M11.2 11.8 20 3M16 7l2.5 2.5M18.5 4.5 21 7" />
    </>
  ),
  network: (
    <>
      <rect x="9" y="2.5" width="6" height="5" rx="1" />
      <rect x="2.5" y="16.5" width="6" height="5" rx="1" />
      <rect x="15.5" y="16.5" width="6" height="5" rx="1" />
      <path d="M12 7.5V12M5.5 16.5V12h13v4.5" />
    </>
  ),
  firewall: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="1.5" />
      <path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 9.3v5.4M9 14.7V20" />
    </>
  ),
  updates: (
    <>
      <path d="M20 12a8 8 0 1 1-2.3-5.7" />
      <path d="M20 4v5h-5M12 8v5l3 2" />
    </>
  ),
  disk: (
    <>
      <ellipse cx="12" cy="6" rx="8" ry="3" />
      <path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  terminal: (
    <>
      <rect x="2.5" y="4" width="19" height="16" rx="2" />
      <path d="m7 9 3 3-3 3M12.5 15H17" />
    </>
  ),
  files: <path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4.6l2 2.2h8.4A1.5 1.5 0 0 1 21 8.7v9.8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z" />,
  logs: (
    <>
      <path d="M6 3h9l4 4v14H6z" />
      <path d="M15 3v4h4M9 11h7M9 14.5h7M9 18h4" />
    </>
  ),
  process: <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />,
  capture: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 5 5M7.5 11h1.5l1-2 2 4 1-2h1.5" />
    </>
  ),
  shield: <path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6z" />,
  passkey: (
    <>
      <circle cx="9" cy="7.5" r="4" />
      <path d="M2.5 20.5c.6-3.6 3.2-5.5 6.5-5.5 1.3 0 2.5.3 3.5.9" />
      <circle cx="17.5" cy="13.5" r="2.5" />
      <path d="M17.5 16v5.5M17.5 19h2" />
    </>
  ),
  sessions: (
    <>
      <rect x="2.5" y="4" width="13" height="10" rx="1.5" />
      <path d="M6 18h6M9 14v4" />
      <rect x="17" y="8" width="4.5" height="12" rx="1.2" />
    </>
  ),
  audit: (
    <>
      <path d="M8 4H6a1.5 1.5 0 0 0-1.5 1.5v14A1.5 1.5 0 0 0 6 21h12a1.5 1.5 0 0 0 1.5-1.5v-14A1.5 1.5 0 0 0 18 4h-2" />
      <rect x="8" y="2.5" width="8" height="3.5" rx="1" />
      <path d="m8.5 13.5 2.5 2.5 4.5-5" />
    </>
  ),
  settings: (
    <>
      <path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0" />
      <circle cx="16" cy="6" r="2" />
      <circle cx="10" cy="12" r="2" />
      <circle cx="18" cy="18" r="2" />
    </>
  ),
  sun: (
    <>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </>
  ),
  moon: <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" />,
  logout: (
    <>
      <path d="M14 4h4.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H14" />
      <path d="M10 8l-4 4 4 4M6 12h10" />
    </>
  ),
  language: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.6 3.7 5.6 3.7 9s-1.2 6.4-3.7 9c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3z" />
    </>
  ),
  chevronLeft: <path d="m14.5 6-6 6 6 6" />,
  chevronRight: <path d="m9.5 6 6 6-6 6" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  play: <path d="M8 5.5v13l10-6.5z" />,
  stop: <rect x="6.5" y="6.5" width="11" height="11" rx="1.5" />,
  restart: (
    <>
      <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3" />
      <path d="M19.5 4.5v4h-4" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4 4" />
    </>
  ),
  download: <path d="M12 4v11m-4.5-4.5L12 15l4.5-4.5M5 19.5h14" />,
  signal: <path d="M13 3 5 13.5h6L10 21l8-10.5h-6z" />,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  folder: <path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4.2l2 2.2H19a1.5 1.5 0 0 1 1.5 1.5v8.3A1.5 1.5 0 0 1 19 19.5H5A1.5 1.5 0 0 1 3.5 18z" />,
  folderPlus: (
    <>
      <path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4.2l2 2.2H19a1.5 1.5 0 0 1 1.5 1.5v8.3A1.5 1.5 0 0 1 19 19.5H5A1.5 1.5 0 0 1 3.5 18z" />
      <path d="M12 11v5.5M9.25 13.75h5.5" />
    </>
  ),
  file: (
    <>
      <path d="M13.5 3H7a1.5 1.5 0 0 0-1.5 1.5v15A1.5 1.5 0 0 0 7 21h10a1.5 1.5 0 0 0 1.5-1.5V8z" />
      <path d="M13.5 3v5h5" />
    </>
  ),
  filePlus: (
    <>
      <path d="M13.5 3H7a1.5 1.5 0 0 0-1.5 1.5v15A1.5 1.5 0 0 0 7 21h10a1.5 1.5 0 0 0 1.5-1.5V8z" />
      <path d="M13.5 3v5h5M12 11.5v6M9 14.5h6" />
    </>
  ),
  link: (
    <>
      <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" />
      <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />
    </>
  ),
  upload: <path d="M12 15.5V4.5M7.5 9 12 4.5 16.5 9M5 19.5h14" />,
  more: <path d="M6 12h.01M12 12h.01M18 12h.01" />,
  eye: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M10.6 5.6A9.6 9.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.7 3.4M6.6 6.6C3.9 8.3 2.5 12 2.5 12S6 18.5 12 18.5c1.9 0 3.5-.6 4.9-1.5" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3.5 3.5l17 17" />
    </>
  ),
  edit: (
    <>
      <path d="M4.5 19.5h4l10-10a2.8 2.8 0 0 0-4-4l-10 10z" />
      <path d="m13.5 6.5 4 4" />
    </>
  ),
  trash: (
    <>
      <path d="M4.5 6.5h15M9.5 6.5V4.5h5v2M6.5 6.5l.9 12.6A1.5 1.5 0 0 0 8.9 20.5h6.2a1.5 1.5 0 0 0 1.5-1.4l.9-12.6" />
      <path d="M10 10.5v6M14 10.5v6" />
    </>
  ),
  copy: (
    <>
      <rect x="8.5" y="8.5" width="12" height="12" rx="1.5" />
      <path d="M15.5 8.5V5A1.5 1.5 0 0 0 14 3.5H5A1.5 1.5 0 0 0 3.5 5v9A1.5 1.5 0 0 0 5 15.5h3.5" />
    </>
  ),
  move: <path d="M4 12h14m-4-4 4 4-4 4M4 5v14" />,
  paste: (
    <>
      <rect x="5.5" y="4.5" width="13" height="16" rx="1.5" />
      <path d="M9 4.5V3.5h6v1M9 11h6M9 15h4" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="1.5" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5.5M12 7.5h.01" />
    </>
  ),
  home: (
    <>
      <path d="M4 11 12 4l8 7" />
      <path d="M6 9.5v10h12v-10M10 19.5v-5h4v5" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  save: (
    <>
      <path d="M5 3.5h11.5l4 4V19a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 19V5A1.5 1.5 0 0 1 5 3.5z" />
      <path d="M7.5 3.5v5h8v-5M7.5 20.5v-6.5h9v6.5" />
    </>
  ),
  arrowUp: <path d="M12 19.5v-15M6.5 10 12 4.5l5.5 5.5" />,
  filter: <path d="M3.5 5h17l-6.5 7.5v6l-4 2v-8z" />,
  viewList: <path d="M8 6h12.5M8 12h12.5M8 18h12.5M3.5 6h.01M3.5 12h.01M3.5 18h.01" />,
  viewGrid: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </>
  ),
  viewCompact: <path d="M3.5 5.5h7M3.5 10h7M3.5 14.5h7M3.5 19h7M13.5 5.5h7M13.5 10h7M13.5 14.5h7M13.5 19h7" />,
};

export function Icon({ name, className = "h-[18px] w-[18px]" }: { name: IconName; className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={`shrink-0 ${className}`}
    >
      {paths[name]}
    </svg>
  );
}
