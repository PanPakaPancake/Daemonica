import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { useTranslation } from "react-i18next";
import { BrowserRouter, Link, Navigate, Route, Routes } from "react-router";
import "./styles.css";
import "./i18n";
import { Layout } from "./components/Layout";
import { Notice, Panel, Wordmark } from "./components/ui";
import { api, type Passkey, type SetupState } from "./lib/api";
import { SessionProvider, useSession } from "./lib/session";
import { applyTheme, initialTheme } from "./lib/theme";
import { Login } from "./pages/Login";
import { Passkeys } from "./pages/Passkeys";
import { Recovery } from "./pages/Recovery";
import { Setup } from "./pages/Setup";

applyTheme(initialTheme());

function Overview() {
  const { t } = useTranslation();
  const pk = useQuery({ queryKey: ["passkeys"], queryFn: () => api<Passkey[]>("GET", "/passkeys") });
  const items = [
    { key: "cert", done: true },
    { key: "allowlist", done: true },
    { key: "secondPasskey", done: (pk.data?.length ?? 0) >= 2 },
    { key: "firewall", done: false },
    { key: "updates", done: false },
  ];
  const done = items.filter((i) => i.done).length;
  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-semibold">{t("overview.title")}</h1>
      <Panel edge>
        <h2 className="font-semibold">{t("overview.checklist", { done, total: items.length })}</h2>
        <ul className="mt-3 flex flex-col gap-2">
          {items.map((i) => (
            <li key={i.key} className="flex items-center gap-2">
              <span aria-hidden="true" className={i.done ? "text-ok" : "text-faint"}>
                {i.done ? "✓" : "○"}
              </span>
              <span className={i.done ? "" : "text-muted"}>{t(`overview.items.${i.key}`)}</span>
              <span className="sr-only">{i.done ? t("common.yes") : t("common.no")}</span>
            </li>
          ))}
        </ul>
        {(pk.data?.length ?? 0) < 2 && (
          <Link to="/security/passkeys" className="mt-4 inline-block text-violet underline">
            {t("passkeys.add")}
          </Link>
        )}
      </Panel>
      <Notice tone="info">{t("overview.empty")}</Notice>
    </div>
  );
}

function NotFound() {
  const { t } = useTranslation();
  return (
    <main className="grid min-h-[60vh] place-items-center p-4">
      <Panel className="max-w-md text-center">
        <Wordmark />
        <h1 className="mt-4 text-xl font-semibold">{t("notFound.title")}</h1>
        <Link to="/" className="btn btn-secondary mt-6">
          {t("notFound.back")}
        </Link>
      </Panel>
    </main>
  );
}

/** Routes requiring a session; redirects to setup or login otherwise. */
function Protected({ children }: { children: ReactNode }) {
  const { me, loading } = useSession();
  const state = useQuery({ queryKey: ["setup-state"], queryFn: () => api<SetupState>("GET", "/setup/state"), staleTime: 60_000 });
  if (loading || state.isLoading) return null;
  if (state.data && !state.data.setup_done) return <Navigate to="/setup" replace />;
  if (!me) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

const qc = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } } });

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={qc}>
        <SessionProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/setup" element={<Setup />} />
              <Route path="/recovery" element={<Recovery />} />
              <Route
                element={
                  <Protected>
                    <Layout />
                  </Protected>
                }
              >
                <Route index element={<Overview />} />
                <Route path="security/passkeys" element={<Passkeys />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </SessionProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
