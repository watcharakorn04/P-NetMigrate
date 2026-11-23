// Shared shell behaviour: theme toggle, language links, live API health badge, mobile nav.
(function () {
  "use strict";
  var T = window.NM_I18N || {};

  // ---- Light / Dark theme (persisted in localStorage)
  var themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var dark = document.documentElement.classList.toggle("dark");
      try { localStorage.setItem("netmigrate-theme", dark ? "dark" : "light"); } catch (e) {}
    });
  }

  // ---- Language links keep the current editor draft (page reloads with ?lang=)
  document.querySelectorAll("[data-lang-link]").forEach(function (a) {
    a.addEventListener("click", function () {
      document.dispatchEvent(new CustomEvent("nm:before-lang-switch"));
    });
  });

  // ---- Mobile navigation drawer
  var nav = document.getElementById("sidenav");
  var backdrop = document.getElementById("nav-backdrop");
  function setNav(open) {
    if (!nav) return;
    nav.classList.toggle("-translate-x-full", !open);
    backdrop.classList.toggle("hidden", !open);
  }
  var openBtn = document.getElementById("nav-open");
  if (openBtn) openBtn.addEventListener("click", function () { setNav(true); });
  if (backdrop) backdrop.addEventListener("click", function () { setNav(false); });

  // ---- Live API health badge (polls /api/health)
  var dot = document.getElementById("health-dot");
  var text = document.getElementById("health-text");
  var badge = document.getElementById("health-badge");
  function paint(state, title) {
    var colors = { ok: "bg-emerald-500", rule: "bg-amber-500", off: "bg-rose-500" };
    dot.className = "h-2 w-2 rounded-full " + colors[state];
    text.textContent = state === "ok" ? T.health_ai_ready : state === "rule" ? T.health_rule_only : T.health_offline;
    badge.title = title || "";
  }
  function poll() {
    if (!dot) return;
    fetch("/api/health?lang=" + encodeURIComponent(window.NM_LANG || "th"), { cache: "no-store" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (h) {
        paint(h.ai_available ? "ok" : "rule", h.message + (h.llm_model ? " (" + h.llm_model + ")" : ""));
        document.dispatchEvent(new CustomEvent("nm:health", { detail: h }));
      })
      .catch(function () { paint("off"); });
  }
  poll();
  setInterval(poll, 30000);
})();
