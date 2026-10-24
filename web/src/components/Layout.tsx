import { useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router";
import { setLanguage } from "../i18n";
import { useSession } from "../lib/session";
import { applyTheme, initialTheme, type Theme } from "../lib/theme";
import { BrandIcon, Wordmark } from "./ui";

interface NavItem {
  to?: string;
  key: string;
}
interface NavGroup {
  key: string;
  items: NavItem[];
}

// SPEC §5.5 navigation groups. Items without a route arrive in later milestones.
const groups: NavGroup[] = [
  { key: "nav.overview", items: [{ to: "/", key: "nav.overview" }] },
  { key: "nav.servicesJobs", items: [] },
  { key: "nav.system", items: [] },
  { key: "nav.tools", items: [] },
  {
    key: "nav.security",
    items: [{ to: "/security/passkeys", key: "nav.passkeys" }, { key: "nav.sessions" }, { key: "nav.audit" }, { key: "nav.settings" }],
  },
];

export function Layout() {
  const { t, i18n } = useTranslation();
  const { me, logout } = useSession();
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState<Theme>(initialTheme);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
  };

  return (
    <div className="min-h-screen md:flex">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 btn btn-secondary">
        {t("nav.skip")}
      </a>
      <aside className={`border-b border-line bg-bg-1 md:border-b-0 md:border-r ${collapsed ? "md:w-16" : "md:w-64"} shrink-0`}>
        <div className={`flex gap-2 px-3 py-4 ${collapsed ? "flex-col items-center" : "flex-col items-stretch"}`}>
          {collapsed ? <BrandIcon /> : <Wordmark />}
          <button
            type="button"
            className={`btn btn-secondary min-h-9 px-2 ${collapsed ? "" : "self-end"}`}
            aria-label={collapsed ? t("nav.expand") : t("nav.collapse")}
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((c) => !c)}
          >
            <span aria-hidden="true">{collapsed ? "»" : "«"}</span>
          </button>
        </div>
        {!collapsed && (
          <nav aria-label="main" className="flex flex-col gap-4 px-3 pb-6">
            {groups.map((g) => (
              <div key={g.key}>
                <p className="px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-faint">{t(g.key)}</p>
                <ul className="flex flex-col gap-0.5">
                  {g.items.length === 0 && <li className="px-2 py-1 text-sm text-faint">{t("common.comingSoon")}</li>}
                  {g.items.map((it) =>
                    it.to ? (
                      <li key={it.key}>
                        <NavLink
                          to={it.to}
                          end
                          className={({ isActive }) =>
                            `block rounded-[8px] px-2 py-1.5 ${isActive ? "bg-bg-2 font-semibold text-fg" : "text-muted hover:bg-bg-2 hover:text-fg"}`
                          }
                        >
                          {({ isActive }) => (
                            <span className="flex items-center gap-2">
                              {isActive && <span aria-hidden="true" className="h-4 w-1 rounded grad-bar" />}
                              {t(it.key)}
                            </span>
                          )}
                        </NavLink>
                      </li>
                    ) : (
                      <li key={it.key} className="px-2 py-1.5 text-faint" aria-disabled="true">
                        {t(it.key)}
                      </li>
                    ),
                  )}
                </ul>
              </div>
            ))}
          </nav>
        )}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-bg-1 px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm text-muted">{window.location.hostname}</span>
            {me && (
              <span className="rounded-full border border-line-strong px-2 py-0.5 text-xs font-semibold">{t(`header.role.${me.role}`)}</span>
            )}
            {me?.step_up && (
              <span className="rounded-full border border-cyan px-2 py-0.5 text-xs text-cyan">
                <span aria-hidden="true">✓ </span>
                {t("header.stepUpActive")}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label className="sr-only" htmlFor="lang">
              {t("header.language")}
            </label>
            <select
              id="lang"
              className="input min-h-9 w-auto py-1"
              value={i18n.language}
              onChange={(e) => setLanguage(e.target.value === "en" ? "en" : "de")}
            >
              <option value="de">Deutsch</option>
              <option value="en">English</option>
            </select>
            <button type="button" className="btn btn-secondary min-h-9" onClick={toggleTheme} aria-label={t("header.theme")}>
              {theme === "dark" ? t("header.light") : t("header.dark")}
            </button>
            {me && (
              <button type="button" className="btn btn-secondary min-h-9" onClick={() => void logout()}>
                {me.linux_user} · {t("header.logout")}
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
