import type { TFunction } from "i18next";
import { ApiError } from "./api";

/** Translates any thrown value into a user-facing message (never raw server text). */
export function errorText(t: TFunction, err: unknown): string {
  if (err instanceof ApiError) {
    const key = `errors.${err.code}`;
    const msg = t(key, { defaultValue: t("errors.internal_error") });
    return err.correlationId ? `${msg} ${t("errors.reference", { id: err.correlationId })}` : msg;
  }
  if (err instanceof DOMException || (err instanceof Error && err.message === "cancelled")) {
    return t("errors.passkey_cancelled");
  }
  return t("errors.internal_error");
}
