export type Theme = "dark" | "light";

export function initialTheme(): Theme {
  try {
    const s = localStorage.getItem("daemonia.theme");
    if (s === "dark" || s === "light") return s;
  } catch {
    /* ignore */
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
  try {
    localStorage.setItem("daemonia.theme", t);
  } catch {
    /* ignore */
  }
}
