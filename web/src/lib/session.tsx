import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, setUnauthorizedHandler, type CeremonyStart, type WhoAmI } from "./api";
import { errorText } from "./errors";
import { getPasskey } from "./webauthn";
import { Notice } from "../components/ui";

interface SessionCtx {
  me: WhoAmI | undefined;
  loading: boolean;
  refresh: () => Promise<unknown>;
  logout: () => Promise<void>;
  /** Runs fn; if the server demands a step-up, asks for the passkey and retries once. */
  withStepUp: <T>(fn: () => Promise<T>) => Promise<T>;
}

const Ctx = createContext<SessionCtx | null>(null);

export function useSession(): SessionCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("SessionProvider missing");
  return c;
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { t } = useTranslation();
  const q = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      try {
        return await api<WhoAmI>("GET", "/session");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    retry: false,
    refetchInterval: 60_000,
  });

  useEffect(() => {
    setUnauthorizedHandler(() => qc.setQueryData(["session"], null));
  }, [qc]);

  // Step-up dialog state; the pending promise resolves when the user confirms.
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const pending = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);

  const confirmStepUp = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      const start = await api<CeremonyStart>("POST", "/auth/stepup/begin");
      const response = await getPasskey(start.options);
      await api("POST", "/auth/stepup/finish", { ceremony_id: start.ceremony_id, response });
      await qc.invalidateQueries({ queryKey: ["session"] });
      setOpen(false);
      pending.current?.resolve();
    } catch (e) {
      setErr(errorText(t, e));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    setOpen(false);
    pending.current?.reject(new ApiError(403, "step_up_required"));
    pending.current = null;
  };

  const withStepUp = useCallback(async <T,>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof ApiError && e.code === "step_up_required")) throw e;
      await new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject };
        setErr(undefined);
        setOpen(true);
      });
      return fn();
    }
  }, []);

  const logout = async () => {
    try {
      await api("POST", "/auth/logout");
    } finally {
      qc.setQueryData(["session"], null);
      qc.clear();
    }
  };

  return (
    <Ctx.Provider value={{ me: q.data ?? undefined, loading: q.isLoading, refresh: () => q.refetch(), logout, withStepUp }}>
      {children}
      <Dialog.Root open={open} onOpenChange={(o) => !o && cancel()}>
        <Dialog.Portal>
          {/* Above other dialogs (z-50): step-up is often requested from inside one. */}
          <Dialog.Overlay className="fixed inset-0 z-[60] bg-black/60" />
          <Dialog.Content className="panel panel-edge fixed left-1/2 top-1/2 z-[60] w-[min(92vw,440px)] -translate-x-1/2 -translate-y-1/2 p-6">
            <Dialog.Title className="text-lg font-semibold">{t("stepup.title")}</Dialog.Title>
            <Dialog.Description className="mt-2 text-muted">{t("stepup.text")}</Dialog.Description>
            {err && (
              <div className="mt-4">
                <Notice tone="bad">{err}</Notice>
              </div>
            )}
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" className="btn btn-secondary" onClick={cancel}>
                {t("common.cancel")}
              </button>
              <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void confirmStepUp()}>
                {t("stepup.confirm")}
              </button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </Ctx.Provider>
  );
}
