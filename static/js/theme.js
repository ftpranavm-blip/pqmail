/* Apply the saved (or system) colour theme before first paint to avoid a flash. */
(function () {
  "use strict";
  var theme = null;
  try { theme = window.localStorage.getItem("pqmail-theme"); } catch (e) { /* storage blocked */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
