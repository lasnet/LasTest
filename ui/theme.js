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
    const select = document.querySelector("#theme-select");
    if (!select) return;
    select.value = root.dataset.theme;
    select.addEventListener("change", () => {
      root.dataset.theme = select.value;
      try {
        localStorage.setItem(storageKey, select.value);
      } catch {
        // The selection still applies to the current page.
      }
    });
  });
})();
