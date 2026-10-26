/* PQMail UI helpers (no external dependencies, CSP-friendly). */
(function () {
  "use strict";

  // Auto-dismiss flash messages after 6 seconds.
  document.querySelectorAll(".flash").forEach(function (el) {
    setTimeout(function () {
      el.style.transition = "opacity .6s";
      el.style.opacity = "0";
      setTimeout(function () { el.remove(); }, 700);
    }, 6000);
  });

  // Confirm dangerous actions.
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (event) {
      if (!window.confirm(el.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Copy-to-clipboard buttons (fingerprints, public keys).
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.querySelector(btn.getAttribute("data-copy"));
      if (!target) return;
      var text = target.textContent.trim();
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = old; }, 1200);
      });
    });
  });

  // Quick-fill demo login.
  document.querySelectorAll("[data-demo-user]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var email = document.getElementById("email");
      if (email) email.value = btn.getAttribute("data-demo-user");
      var pass = document.getElementById("passphrase");
      if (pass && btn.getAttribute("data-demo-pass")) pass.value = btn.getAttribute("data-demo-pass");
    });
  });

  // Light / dark theme toggle (choice is remembered in this browser only).
  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      try { window.localStorage.setItem("pqmail-theme", next); } catch (e) { /* ignore */ }
    });
  }

  // Mobile navigation toggle.
  var navToggle = document.querySelector(".nav-toggle");
  var navLinks = document.getElementById("nav-links");
  if (navToggle && navLinks) {
    navToggle.addEventListener("click", function () {
      var open = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // Close an open dropdown menu when clicking elsewhere or pressing Escape.
  document.addEventListener("click", function (event) {
    document.querySelectorAll("details.menu[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      document.querySelectorAll("details.menu[open]").forEach(function (m) { m.removeAttribute("open"); });
    }
  });

  // Keyboard shortcuts: "g" then a letter jumps to a page; "c" composes. Ignored while typing.
  var pending = false;
  var targets = { i: "/inbox", s: "/sent", d: "/dashboard", t: "/trash", c: "/contacts", k: "/keys" };
  document.addEventListener("keydown", function (event) {
    var el = event.target;
    var typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
    if (typing || event.ctrlKey || event.metaKey || event.altKey) return;
    var key = event.key.toLowerCase();
    if (pending) {
      pending = false;
      if (targets[key]) { window.location.href = targets[key]; }
      return;
    }
    if (key === "g") { pending = true; setTimeout(function () { pending = false; }, 1200); }
    else if (key === "c") { window.location.href = "/compose"; }
  });

  // QKD transcript: step through the protocol one stage at a time.
  var stepBox = document.getElementById("qkd-steps");
  if (stepBox) { stepBox.classList.add("qkd-steps-js"); }
  var stepButtons = document.querySelectorAll("[data-qkd-step]");
  stepButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var wanted = btn.getAttribute("data-qkd-step");
      stepButtons.forEach(function (b) { b.setAttribute("aria-pressed", b === btn ? "true" : "false"); });
      document.querySelectorAll(".qkd-step").forEach(function (panel) {
        panel.classList.toggle("active", panel.getAttribute("data-step") === wanted);
      });
    });
  });
})();
