import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet, useLocation } from "react-router";
import { setLanguage } from "../i18n";
import { useSession } from "../lib/session";
import { applyTheme, initialTheme, type Theme } from "../lib/theme";
import { Icon, type IconName } from "./icons";
import { BrandIcon, Wordmark } from "./ui";

interface NavItem {
  to?: string;
  key: string;
  icon: IconName;
  adminOnly?: boolean;
  hideReadOnly?: boolean;
}
interface NavGroup {
  key: string;
  items: NavItem[];
}

// SPEC §5.5 navigation groups. Items without a route arrive in later milestones.
const groups: NavGroup[] = [
  { key: "nav.overview", items: [{ to: "/", key: "nav.overview", icon: "overview" }] },
  {
    key: "nav.servicesJobs",
    items: [
      { to: "/services", key: "nav.services", icon: "services" },
      { key: "nav.jobs", icon: "jobs" },
    ],
  },
  {
    key: "nav.system",
    items: [
      { to: "/users", key: "nav.users", icon: "users" },
      { to: "/ssh-keys", key: "nav.sshKeys", icon: "key", hideReadOnly: true },
      { key: "nav.network", icon: "network" },
      { key: "nav.firewall", icon: "firewall" },
      { key: "nav.updates", icon: "updates" },
      { key: "nav.disks", icon: "disk" },
      { key: "nav.timeHost", icon: "clock" },
    ],
  },
  {
    key: "nav.tools",
    items: [
      { key: "nav.terminal", icon: "terminal" },
      { key: "nav.files", icon: "files" },
      { to: "/logs", key: "nav.logs", icon: "logs", hideReadOnly: true },
      { to: "/processes", key: "nav.processes", icon: "process" },
      { key: "nav.capture", icon: "capture" },
    ],
  },
  {
    key: "nav.security",
    items: [
      { to: "/security/passkeys", key: "nav.passkeys", icon: "passkey" },
      { to: "/security/sessions", key: "nav.sessions", icon: "sessions" },
      { to: "/security/accounts", key: "nav.accounts", icon: "shield", adminOnly: true },
      { to: "/security/audit", key: "nav.audit", icon: "audit", adminOnly: true },
      { to: "/security/settings", key: "nav.settings", icon: "settings", adminOnly: true },
    ],
  },
];

export function Layout() {
  const { t, i18n } = useTranslation();
  const { me, logout } = useSession();
  const [collapsed, setCollapsed] = useState(false);
  // Below md the navigation is an off-canvas drawer (SPEC §5.5 responsive).
  const [drawer, setDrawer] = useState(false);
  const location = useLocation();
  const [lastPath, setLastPath] = useState(location.pathname);
  if (lastPath !== location.pathname) {
    setLastPath(location.pathname);
    setDrawer(false);
  }
  useEffect(() => {
    if (!drawer) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setDrawer(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawer]);
  const [theme, setTheme] = useState<Theme>(initialTheme);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next, true);
  };

  // In the mobile drawer the navigation is always shown expanded.
  const narrow = collapsed && !drawer;
  const itemBase = `flex items-center gap-2.5 rounded-[8px] py-1.5 ${narrow ? "justify-center px-0" : "px-2"}`;

  return (
    <div className="min-h-screen md:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 btn btn-secondary">
        {t("nav.skip")}
      </a>
      {drawer && <div className="fixed inset-0 z-30 bg-black/60 md:hidden" aria-hidden="true" onClick={() => setDrawer(false)} />}
      <aside
        id="main-nav"
        className={`${drawer ? "fixed inset-y-0 left-0 z-40 w-72 overflow-y-auto shadow-2xl" : "hidden"} border-r border-line bg-bg-1 md:sticky md:top-0 md:block md:h-screen md:overflow-y-auto ${collapsed ? "md:w-16" : "md:w-64"} shrink-0`}
      >
        <div className={`flex gap-2 px-3 py-4 ${narrow ? "flex-col items-center" : "flex-col items-stretch"}`}>
          {narrow ? <BrandIcon /> : <Wordmark />}
          <button
            type="button"
            className="btn btn-secondary min-h-9 self-end px-2 md:hidden"
            aria-label={t("nav.closeMenu")}
            onClick={() => setDrawer(false)}
          >
            <Icon name="close" />
          </button>
          <button
            type="button"
            className={`btn btn-secondary hidden min-h-9 px-2 md:inline-flex ${collapsed ? "" : "self-end"}`}
            aria-label={collapsed ? t("nav.expand") : t("nav.collapse")}
            title={collapsed ? t("nav.expand") : t("nav.collapse")}
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((c) => !c)}
          >
            <Icon name={collapsed ? "chevronRight" : "chevronLeft"} />
          </button>
        </div>
        <nav aria-label="main" className={`flex flex-col gap-4 pb-6 ${narrow ? "px-2" : "px-3"}`}>
          {groups.map((g) => (
            <div key={g.key}>
              {narrow ? (
                <hr className="mx-2 mb-2 border-line" />
              ) : (
                <p className="px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-faint">{t(g.key)}</p>
              )}
              <ul className="flex flex-col gap-0.5">
                {g.items.filter((it) => (!it.adminOnly || me?.role === "admin") && (!it.hideReadOnly || me?.role !== "readonly")).map((it) =>
                  it.to ? (
                    <li key={it.key}>
                      <NavLink
                        to={it.to}
                        end
                        title={narrow ? t(it.key) : undefined}
                        aria-label={narrow ? t(it.key) : undefined}
                        className={({ isActive }) =>
                          `${itemBase} relative ${isActive ? "bg-bg-2 font-semibold text-fg" : "text-muted hover:bg-bg-2 hover:text-fg"}`
                        }
                      >
                        {({ isActive }) => (
                          <>
                            {isActive && <span aria-hidden="true" className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded grad-bar" />}
                            <span className={isActive ? "text-cyan" : ""}>
                              <Icon name={it.icon} />
                            </span>
                            {!narrow && <span className="truncate">{t(it.key)}</span>}
                          </>
                        )}
                      </NavLink>
                    </li>
                  ) : (
                    <li
                      key={it.key}
                      className={`${itemBase} text-faint opacity-70`}
                      aria-disabled="true"
                      title={`${t(it.key)} – ${t("common.comingSoon")}`}
                    >
                      <Icon name={it.icon} />
                      {narrow ? (
                        <span className="sr-only">{t(it.key)}</span>
                      ) : (
                        <>
                          <span className="truncate">{t(it.key)}</span>
                          <span className="ml-auto rounded-full border border-line px-1.5 text-[10px] uppercase tracking-wide">{t("nav.soon")}</span>
                        </>
                      )}
                    </li>
                  ),
                )}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-bg-1 px-4 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <button
              type="button"
              className="btn btn-secondary min-h-9 px-2.5 md:hidden"
              aria-label={t("nav.openMenu")}
              aria-controls="main-nav"
              aria-expanded={drawer}
              onClick={() => setDrawer(true)}
            >
              <Icon name="menu" />
            </button>
            <span className="hidden items-center gap-1.5 truncate font-mono text-sm text-muted sm:flex">
              <Icon name="services" className="h-4 w-4 text-cyan" />
              {window.location.hostname}
            </span>
            {me && (
              <span className="rounded-full border border-line-strong px-2 py-0.5 text-xs font-semibold">{t(`header.role.${me.role}`)}</span>
            )}
            {me?.step_up && (
              <span className="flex items-center gap-1 rounded-full border border-cyan px-2 py-0.5 text-xs text-cyan">
                <Icon name="check" className="h-3.5 w-3.5" />
                {t("header.stepUpActive")}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-muted" htmlFor="lang">
              <Icon name="language" />
              <span className="sr-only">{t("header.language")}</span>
            </label>
            <select
              id="lang"
              className="input min-h-9 py-1 header-select"
              value={i18n.language}
              onChange={(e) => setLanguage(e.target.value === "en" ? "en" : "de")}
            >
              <option value="de">Deutsch</option>
              <option value="en">English</option>
            </select>
            <button
              type="button"
              className="btn btn-secondary min-h-9 px-2.5"
              onClick={toggleTheme}
              aria-label={theme === "dark" ? t("header.toLight") : t("header.toDark")}
              title={theme === "dark" ? t("header.toLight") : t("header.toDark")}
            >
              <Icon name={theme === "dark" ? "sun" : "moon"} />
            </button>
            {me && (
              <button
                type="button"
                className="btn btn-secondary min-h-9 gap-2 whitespace-nowrap"
                onClick={() => void logout()}
                title={t("header.logout")}
              >
                <span className="font-mono text-sm">{me.linux_user}</span>
                <Icon name="logout" />
                <span className="sr-only">{t("header.logout")}</span>
              </button>
            )}
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-6xl flex-1 p-4 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
