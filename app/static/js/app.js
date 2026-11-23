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

// Shared helpers for the module pages. Server text is always inserted with textContent.
window.NM = (function () {
  "use strict";
  var T = window.NM_I18N || {};
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }
  function api(url, opts) {
    opts = opts || {};
    if (opts.json !== undefined) {
      opts.body = JSON.stringify(opts.json);
      opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
      delete opts.json;
    }
    return fetch(url, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) {
          var d = body && body.detail;
          if (Array.isArray(d)) d = d.map(function (x) { return x.msg; }).join("; ");
          throw new Error(d || (T.request_failed + " (" + r.status + ")"));
        }
        return body;
      });
    });
  }
  function fmtDate(iso) {
    if (!iso) return "";
    try { return new Date(iso).toLocaleString(window.NM_LANG === "th" ? "th-TH" : "en-GB"); } catch (e) { return iso; }
  }
  function download(name, text, type) {
    var blob = text instanceof Blob ? text : new Blob([text], { type: type || "text/plain;charset=utf-8" });
    var a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  function copy(text, btn) {
    var done = function () { if (!btn) return; var old = btn.textContent; btn.textContent = T.copied; setTimeout(function () { btn.textContent = old; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(done);
    var ta = el("textarea", "fixed -left-[9999px]"); ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } finally { ta.remove(); }
  }
  var BADGE = {
    RULE: "bg-emerald-100 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300",
    AI: "bg-amber-100 text-amber-900 ring-amber-600/30 dark:bg-amber-500/15 dark:text-amber-300",
    SYSTEM: "bg-sky-100 text-sky-800 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300",
    UNCONVERTED: "bg-rose-100 text-rose-800 ring-rose-600/20 dark:bg-rose-500/15 dark:text-rose-300",
    NOT_NEEDED: "bg-slate-200 text-slate-700 ring-slate-500/20 dark:bg-slate-700/60 dark:text-slate-300",
  };
  var STATUS = {
    done: "bg-emerald-100 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300",
    success: "bg-emerald-100 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300",
    review: "bg-amber-100 text-amber-900 ring-amber-600/30 dark:bg-amber-500/15 dark:text-amber-300",
    running: "bg-sky-100 text-sky-800 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300",
    queued: "bg-slate-200 text-slate-700 ring-slate-500/20 dark:bg-slate-700/60 dark:text-slate-300",
    skipped: "bg-slate-200 text-slate-700 ring-slate-500/20 dark:bg-slate-700/60 dark:text-slate-300",
    error: "bg-rose-100 text-rose-800 ring-rose-600/20 dark:bg-rose-500/15 dark:text-rose-300",
    failed: "bg-rose-100 text-rose-800 ring-rose-600/20 dark:bg-rose-500/15 dark:text-rose-300",
  };
  function chip(kind, text, map) {
    return el("span", "nm-chip " + ((map || STATUS)[kind] || STATUS.queued), text);
  }
  function dirName(d) { return T["dir_" + d] || d; }
  function modeName(m) { return T["mode_" + m] || m; }
  return { T: T, el: el, api: api, fmtDate: fmtDate, download: download, copy: copy, chip: chip,
           BADGE: BADGE, STATUS: STATUS, dirName: dirName, modeName: modeName };
})();
