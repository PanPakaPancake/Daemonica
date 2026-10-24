import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "../components/Modal";
import { Notice } from "../components/ui";
import { api, ApiError } from "./api";
import type { Flags, FsInfo } from "./files";
import { useSession } from "./session";

export function useFsInfo(enabled = true) {
  return useQuery({
    queryKey: ["fs-info"],
    queryFn: () => api<FsInfo>("GET", "/files/info"),
    enabled,
    refetchInterval: 30_000,
  });
}

export function rootActive(info: FsInfo | undefined): boolean {
  return !!info?.root.active && !!info.root.until && Date.parse(info.root.until) > Date.now();
}

/**
 * Runs file operations with the session's flags. A "sensitive_path" answer
 * opens a warning; after confirmation the call is repeated with
 * confirm_sensitive, which additionally needs a fresh passkey step-up.
 */
export function useFsRunner() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { me, withStepUp } = useSession();
  const info = useFsInfo(!!me && me.role !== "readonly");
  const asRoot = rootActive(info.data);
  const [ask, setAsk] = useState<{ path?: string } | null>(null);
  const answer = useRef<((ok: boolean) => void) | null>(null);

  const run = useCallback(
    async <T,>(fn: (f: Flags) => Promise<T>, path?: string): Promise<T> => {
      const flags: Flags = { as_root: asRoot };
      try {
        return await withStepUp(() => fn(flags));
      } catch (e) {
        if (e instanceof ApiError && e.code === "root_mode_required") void qc.invalidateQueries({ queryKey: ["fs-info"] });
        if (!(e instanceof ApiError && e.code === "sensitive_path")) throw e;
        const ok = await new Promise<boolean>((resolve) => {
          answer.current = resolve;
          setAsk({ path });
        });
        if (!ok) throw e;
        return withStepUp(() => fn({ ...flags, confirm_sensitive: true }));
      }
    },
    [asRoot, withStepUp, qc],
  );

  const close = (ok: boolean) => {
    setAsk(null);
    answer.current?.(ok);
    answer.current = null;
  };

  const dialog: ReactNode = ask && (
    <Modal title={t("files.sensitive.title")} onClose={() => close(false)}>
      <Notice tone="warn">{t("files.sensitive.text")}</Notice>
      {ask.path && <p className="mt-3 break-all font-mono text-sm">{ask.path}</p>}
      <p className="mt-3 text-sm text-muted">{t("files.sensitive.stepUp")}</p>
      <div className="mt-5 flex justify-end gap-2">
        <button type="button" className="btn btn-secondary" onClick={() => close(false)}>
          {t("common.cancel")}
        </button>
        <button type="button" className="btn btn-danger" onClick={() => close(true)}>
          {t("files.sensitive.confirm")}
        </button>
      </div>
    </Modal>
  );

  return { run, asRoot, info, dialog };
}
