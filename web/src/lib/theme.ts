export type Theme = "dark" | "light";

const KEY = "daemonica.theme";

// Dark is the default regardless of prefers-color-scheme (SPEC §5.2, DEC-013).
// Only an explicit user choice is stored.
export function initialTheme(): Theme {
  try {
    const s = localStorage.getItem(KEY);
    if (s === "dark" || s === "light") return s;
  } catch {
    /* storage unavailable */
  }
  return "dark";
}

export function applyTheme(t: Theme, persist = false) {
  document.documentElement.dataset.theme = t;
  if (!persist) return;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage unavailable */
  }
}
