import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { useTranslation } from "react-i18next";
import { BrowserRouter, Link, Navigate, Route, Routes } from "react-router";
import { setNonce } from "get-nonce";
import "./styles.css";
import "./i18n";
import { Layout } from "./components/Layout";
import { Panel, Wordmark } from "./components/ui";
import { api, type SetupState } from "./lib/api";
import { SessionProvider, useSession } from "./lib/session";
import { applyTheme, initialTheme } from "./lib/theme";
import { Login } from "./pages/Login";
import { Passkeys } from "./pages/Passkeys";
import { Accounts } from "./pages/Accounts";
import { Audit } from "./pages/Audit";
import { Settings } from "./pages/Settings";
import { Invite, Recovery } from "./pages/Recovery";
import { Sessions } from "./pages/Sessions";
import { Setup } from "./pages/Setup";
import { OverviewPage } from "./pages/Overview";
import { Services } from "./pages/Services";
import { Logs } from "./pages/Logs";
import { Processes } from "./pages/Processes";
import { Users } from "./pages/Users";
import { SSHKeys } from "./pages/SSHKeys";
import { Files } from "./pages/Files";
import { FileEditor } from "./pages/FileEditor";
import { Network } from "./pages/Network";
import { TerminalPage } from "./pages/Terminal";

// Per-response style nonce from the server (DEC-018): lets Radix's scroll lock
// insert its <style> element under the strict CSP.
const styleNonce = document.querySelector<HTMLMetaElement>('meta[name="style-nonce"]')?.content;
if (styleNonce && styleNonce !== "__STYLE_NONCE__") {
  setNonce(styleNonce);
  // Other UI libraries (xterm.js) create <style> elements without a nonce
  // option; give every style element created by our own scripts the nonce.
  const create = document.createElement.bind(document);
  document.createElement = ((tag: string, options?: ElementCreationOptions) => {
    const el = create(tag, options);
    if (tag.toLowerCase() === "style") el.setAttribute("nonce", styleNonce);
    return el;
  }) as typeof document.createElement;
}

applyTheme(initialTheme());

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
              <Route path="/invite" element={<Invite />} />
              <Route
                element={
                  <Protected>
                    <Layout />
                  </Protected>
                }
              >
                <Route index element={<OverviewPage />} />
                <Route path="services" element={<Services />} />
                <Route path="logs" element={<Logs />} />
                <Route path="processes" element={<Processes />} />
                <Route path="users" element={<Users />} />
                <Route path="ssh-keys" element={<SSHKeys />} />
                <Route path="files" element={<Files />} />
                <Route path="files/edit" element={<FileEditor />} />
                <Route path="terminal" element={<TerminalPage />} />
                <Route path="network" element={<Network />} />
                <Route path="security/passkeys" element={<Passkeys />} />
                <Route path="security/sessions" element={<Sessions />} />
                <Route path="security/accounts" element={<Accounts />} />
                <Route path="security/audit" element={<Audit />} />
                <Route path="security/settings" element={<Settings />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </SessionProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
