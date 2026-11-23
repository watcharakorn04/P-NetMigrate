// Single conversion workspace (module 1). All server text is inserted with textContent.
(function () {
  "use strict";
  var T = window.NM_I18N || {};
  var LANG = window.NM_LANG || "th";
  var $ = function (id) { return document.getElementById(id); };

  var editor = $("editor"), direction = $("direction"), fileInput = $("file-input");
  var currentFile = null;      // File chosen via upload (sent as multipart) until the editor is edited
  var lastRequest = null;      // {direction, text} of the last conversion — reused by "Send Selected"
  var lastResult = null;

  var BADGE = {
    RULE: "bg-emerald-100 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300",
    AI: "bg-amber-100 text-amber-900 ring-amber-600/30 dark:bg-amber-500/15 dark:text-amber-300",
    SYSTEM: "bg-sky-100 text-sky-800 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300",
    UNCONVERTED: "bg-rose-100 text-rose-800 ring-rose-600/20 dark:bg-rose-500/15 dark:text-rose-300",
    NOT_NEEDED: "bg-slate-200 text-slate-700 ring-slate-500/20 dark:bg-slate-700/60 dark:text-slate-300",
  };
  var STRIPE = { RULE: "border-emerald-500", AI: "border-amber-500", SYSTEM: "border-sky-500", UNCONVERTED: "border-rose-500", NOT_NEEDED: "border-slate-400" };
  var ROW_TINT = { AI: "bg-amber-50/70 dark:bg-amber-500/5", UNCONVERTED: "bg-rose-50/70 dark:bg-rose-500/5" };
  var ORDER = ["RULE", "AI", "SYSTEM", "UNCONVERTED", "NOT_NEEDED"];

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  // ---------------------------------------------------------------- draft persistence
  var DRAFT_KEY = "netmigrate-draft";
  function saveDraft() {
    try { sessionStorage.setItem(DRAFT_KEY, JSON.stringify({ text: editor.value, direction: direction.value })); } catch (e) {}
  }
  function restoreDraft() {
    try {
      var d = JSON.parse(sessionStorage.getItem(DRAFT_KEY) || "null");
      if (d) { editor.value = d.text || ""; if (d.direction) direction.value = d.direction; }
    } catch (e) {}
  }
  document.addEventListener("nm:before-lang-switch", saveDraft);

  function updateCount() {
    var text = editor.value;
    $("line-count").textContent = text ? text.split(/\r?\n/).length : 0;
  }

  // ---------------------------------------------------------------- input helpers
  editor.addEventListener("input", function () {
    currentFile = null;
    $("file-name").textContent = "";
    updateCount();
    saveDraft();
  });
  direction.addEventListener("change", saveDraft);

  fileInput.addEventListener("change", function () {
    var f = fileInput.files && fileInput.files[0];
    if (!f) return;
    currentFile = f;
    $("file-name").textContent = f.name;
    var reader = new FileReader();
    reader.onload = function () { editor.value = String(reader.result || ""); updateCount(); saveDraft(); };
    reader.readAsText(f);
    fileInput.value = "";
  });

  document.querySelectorAll("[data-sample]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var vendor = btn.getAttribute("data-sample");
      fetch("/static/samples/" + vendor + "_sample.txt", { cache: "no-store" })
        .then(function (r) { return r.text(); })
        .then(function (text) {
          editor.value = text;
          currentFile = null;
          $("file-name").textContent = vendor + "_sample.txt";
          direction.value = vendor === "cisco" ? "c2h" : "h2c";
          updateCount();
          saveDraft();
        });
    });
  });

  $("clear-btn").addEventListener("click", function () {
    editor.value = ""; currentFile = null; $("file-name").textContent = ""; updateCount(); saveDraft();
  });

  function selectedMode() {
    var r = document.querySelector('input[name="mode"]:checked');
    return r ? r.value : "rule_only";
  }

  function setBusy(busy) {
    ["prescan-btn", "convert-btn", "send-selected"].forEach(function (id) {
      var b = $(id);
      if (!b) return;
      if (busy) b.disabled = true;
      else if (id !== "send-selected") b.disabled = false;  // send-selected depends on ticks
    });
    if (!busy) refreshSendButton();
    $("busy").classList.toggle("hidden", !busy);
  }

  function formData() {
    if (!editor.value.trim() && !currentFile) { $("error").textContent = T.empty_input; return null; }
    var fd = new FormData();
    fd.append("direction", direction.value);
    fd.append("lang", LANG);
    if (currentFile) fd.append("file", currentFile, currentFile.name);
    else fd.append("config", editor.value);
    return fd;
  }

  function post(url, fd) {
    $("error").textContent = "";
    setBusy(true);
    return fetch(url, { method: "POST", body: fd })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (!r.ok) throw new Error((body && body.detail) || (T.request_failed + " (" + r.status + ")"));
          return body;
        });
      })
      .catch(function (err) { $("error").textContent = err.message || T.request_failed; throw err; })
      .finally(function () { setBusy(false); });
  }

  // ---------------------------------------------------------------- pre-scan
  function renderPrescan(p) {
    $("prescan-empty").classList.add("hidden");
    $("prescan-body").classList.remove("hidden");
    $("ps-coverage").textContent = p.coverage_percent.toFixed(p.coverage_percent % 1 ? 1 : 0) + "%";
    $("ps-bar").style.width = p.coverage_percent + "%";
    $("ps-bar").className = "h-full rounded-full transition-all " +
      (p.coverage_percent >= 90 ? "bg-emerald-500" : p.coverage_percent >= 60 ? "bg-amber-500" : "bg-rose-500");
    $("ps-total").textContent = p.total_lines;
    $("ps-supported").textContent = p.supported_lines;
    $("ps-unsupported").textContent = p.unsupported_lines;
    $("ps-secrets").textContent = p.secret_stripped_count;
    var list = $("ps-list");
    list.replaceChildren();
    if (!p.unsupported_items.length) { list.appendChild(el("li", "text-slate-400", T.none)); return; }
    p.unsupported_items.forEach(function (item) {
      var li = el("li", "rounded-md border border-slate-200 p-2 dark:border-slate-800");
      var top = el("div", "flex gap-2");
      top.appendChild(el("span", "shrink-0 font-mono text-xs tabular-nums text-slate-400", T.line_no + " " + item.line_no));
      top.appendChild(el("code", "break-all font-mono text-xs", item.command));
      li.appendChild(top);
      li.appendChild(el("div", "mt-1 text-xs text-slate-500 dark:text-slate-400", item.reason));
      list.appendChild(li);
    });
  }

  $("prescan-btn").addEventListener("click", function () {
    var fd = formData();
    if (fd) post("/api/prescan", fd).then(renderPrescan).catch(function () {});
  });

  // ---------------------------------------------------------------- result
  function modeName(m) { return T["mode_" + m] || m; }

  function renderLines() {
    var r = lastResult, box = $("result-lines"), showLabels = $("show-labels").checked;
    box.replaceChildren();
    r.lines.forEach(function (line) {
      var row = el("div", "group flex items-start gap-3 border-l-4 pl-2 pr-4 " + STRIPE[line.provenance] + " " + (ROW_TINT[line.provenance] || "") +
        " hover:bg-slate-100/70 dark:hover:bg-slate-800/50");
      row.appendChild(el("span", "w-8 shrink-0 select-none text-right text-xs leading-6 tabular-nums text-slate-400", line.source_line || ""));
      if (showLabels) {
        var badge = el("span", "mt-0.5 inline-flex w-48 shrink-0 justify-center truncate rounded px-1.5 py-0.5 font-sans text-[11px] font-medium leading-4 ring-1 ring-inset " + BADGE[line.provenance], line.label);
        badge.title = line.label;
        row.appendChild(badge);
      }
      var code = el("pre", "min-w-0 flex-1 whitespace-pre-wrap break-all " + (line.is_comment ? "text-slate-500 dark:text-slate-400" : ""), line.text || " ");
      row.appendChild(code);
      if (line.warning) {
        var warn = el("span", "mt-1 shrink-0 cursor-help text-amber-500", "⚠");
        warn.title = line.warning;
        row.appendChild(warn);
      }
      box.appendChild(row);
    });
  }

  function renderLegend(r) {
    var legend = $("legend");
    legend.replaceChildren();
    ORDER.forEach(function (key) {
      var n = r.provenance_counts[key] || 0;
      var chip = el("span", "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 ring-1 ring-inset " + BADGE[key]);
      chip.appendChild(el("span", "font-medium", T["prov_" + key]));
      chip.appendChild(el("span", "tabular-nums opacity-75", String(n)));
      legend.appendChild(chip);
    });
    legend.classList.remove("hidden");
    legend.classList.add("flex");
  }

  function renderMessages(r) {
    var notices = $("notices");
    notices.replaceChildren();
    r.notices.forEach(function (n) { notices.appendChild(el("p", "", "ℹ " + n)); });
    if (r.ai_sent_line_numbers.length) {
      notices.appendChild(el("p", "text-xs opacity-80", T.ai_sent + ": " + r.ai_sent_line_numbers.join(", ")));
    }
    notices.classList.toggle("hidden", !notices.childNodes.length);

    var list = $("warn-list");
    list.replaceChildren();
    r.warnings.forEach(function (w) { list.appendChild(el("li", "", w)); });
    $("warn-count").textContent = r.warnings.length;
    $("warnings").classList.toggle("hidden", !r.warnings.length);
  }

  function renderSelective(r) {
    var wrap = $("selective"), list = $("selective-list");
    list.replaceChildren();
    $("select-all").checked = false;
    var show = r.effective_mode === "rule_only" && r.unconverted_items.length > 0;
    wrap.classList.toggle("hidden", !show);
    if (!show) return;
    r.unconverted_items.forEach(function (item) {
      var li = el("li", "rounded-md border border-slate-200 dark:border-slate-800");
      var label = el("label", "flex cursor-pointer items-start gap-2 p-2 hover:bg-slate-50 dark:hover:bg-slate-800/50");
      var cb = el("input", "mt-0.5 rounded border-slate-300 text-amber-500 focus:ring-amber-500 dark:border-slate-600 dark:bg-slate-800");
      cb.type = "checkbox";
      cb.value = item.line_no;
      cb.disabled = !window.NM_AI_AVAILABLE;
      cb.addEventListener("change", refreshSendButton);
      label.appendChild(cb);
      var body = el("span", "min-w-0");
      var top = el("span", "flex gap-2");
      top.appendChild(el("span", "shrink-0 font-mono text-xs tabular-nums text-slate-400", T.line_no + " " + item.line_no));
      top.appendChild(el("code", "break-all font-mono text-xs", item.command));
      body.appendChild(top);
      body.appendChild(el("span", "mt-0.5 block text-xs text-slate-500 dark:text-slate-400", item.reason));
      label.appendChild(body);
      li.appendChild(label);
      list.appendChild(li);
    });
    $("select-all").disabled = !window.NM_AI_AVAILABLE;
    refreshSendButton();
  }

  function checkedLines() {
    return Array.prototype.map.call(document.querySelectorAll("#selective-list input:checked"), function (c) { return c.value; });
  }
  function refreshSendButton() {
    var btn = $("send-selected");
    if (btn) btn.disabled = !window.NM_AI_AVAILABLE || checkedLines().length === 0;
  }

  function renderResult(r) {
    lastResult = r;
    $("result-empty").classList.add("hidden");
    $("result-lines").classList.remove("hidden");
    $("copy-btn").disabled = false;
    $("download-btn").disabled = false;
    $("mode-info").textContent = T.requested_mode + ": " + modeName(r.requested_mode) + " · " + T.effective_mode + ": " + modeName(r.effective_mode);
    renderMessages(r);
    renderLegend(r);
    renderLines();
    renderSelective(r);
  }

  $("convert-btn").addEventListener("click", function () {
    var fd = formData();
    if (!fd) return;
    fd.append("mode", selectedMode());
    var snapshot = { direction: direction.value, text: editor.value };
    post("/api/convert", fd).then(function (r) { lastRequest = snapshot; renderResult(r); }).catch(function () {});
  });

  $("select-all").addEventListener("change", function (e) {
    document.querySelectorAll("#selective-list input[type=checkbox]").forEach(function (c) { if (!c.disabled) c.checked = e.target.checked; });
    refreshSendButton();
  });

  $("send-selected").addEventListener("click", function () {
    if (!lastRequest) return;
    var fd = new FormData();
    fd.append("direction", lastRequest.direction);
    fd.append("config", lastRequest.text);
    fd.append("line_numbers", checkedLines().join(","));
    fd.append("lang", LANG);
    post("/api/convert/selected", fd).then(renderResult).catch(function () {});
  });

  $("show-labels").addEventListener("change", function () { if (lastResult) renderLines(); });

  // ---------------------------------------------------------------- copy / download (clean CLI text)
  $("copy-btn").addEventListener("click", function () {
    if (!lastResult) return;
    var btn = $("copy-btn");
    var done = function () { btn.textContent = T.copied; setTimeout(function () { btn.textContent = T.copy; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(lastResult.text).then(done);
    } else {
      var ta = el("textarea", "fixed -left-[9999px]");
      ta.value = lastResult.text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } finally { ta.remove(); }
    }
  });

  $("download-btn").addEventListener("click", function () {
    if (!lastResult) return;
    var stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 13).replace("T", "-");
    var dir = lastResult.source_vendor === "cisco_ios_xe" ? "cisco-to-huawei" : "huawei-to-cisco";
    var blob = new Blob([lastResult.text], { type: "text/plain;charset=utf-8" });
    var a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = "netmigrate-" + dir + "-" + stamp + ".txt";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  });

  restoreDraft();
  updateCount();
})();
