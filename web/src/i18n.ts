import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import de from "./locales/de.json";
import en from "./locales/en.json";

const stored = (() => {
  try {
    return localStorage.getItem("daemonica.lang");
  } catch {
    return null;
  }
})();

void i18n.use(initReactI18next).init({
  resources: { de: { translation: de }, en: { translation: en } },
  lng: stored === "en" || stored === "de" ? stored : "de",
  fallbackLng: "de",
  interpolation: { escapeValue: false }, // React escapes all text output itself
  returnNull: false,
});

export function setLanguage(lang: "de" | "en") {
  void i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem("daemonica.lang", lang);
  } catch {
    /* per-viewer convenience only */
  }
}

export default i18n;
