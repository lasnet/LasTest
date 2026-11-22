(() => {
  "use strict";

  const storageKey = "lastest.theme";
  const themes = new Set(["green", "blue", "black", "light"]);
  const root = document.documentElement;
  let savedTheme;

  try {
    savedTheme = localStorage.getItem(storageKey);
  } catch {
    // Storage can be unavailable in restricted browser contexts.
  }

  root.dataset.theme = themes.has(savedTheme) ? savedTheme : "light";

  document.addEventListener("DOMContentLoaded", () => {
    const selects = document.querySelectorAll("[data-theme-select]");
    for (const select of selects) {
      select.value = root.dataset.theme;
      select.addEventListener("change", () => {
        const theme = select.value;
        root.dataset.theme = theme;
        for (const control of selects) control.value = theme;
        try {
          localStorage.setItem(storageKey, theme);
        } catch {
          // The selection still applies to the current page.
        }
      });
    }
  });
})();
