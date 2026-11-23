// Module 4 — deployment: build filtered plan, edit, confirm, run (simulation by default), SSE log.
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var plan = null, planSource = null, logEntries = [], es = null;
  var LEVEL_CLS = { INFO: "text-sky-300", SUCCESS: "text-emerald-300", WARNING: "text-amber-300", ERROR: "text-rose-400", COMMAND: "text-slate-100" };
  var VENDOR = { cisco_ios_xe: "Cisco IOS-XE", huawei_vrp: "Huawei VRP" };

  function srcMode() { return document.querySelector('input[name="dep-src"]:checked').value; }
  function depMode() { return document.querySelector('input[name="dep-mode"]:checked').value; }
  function commandsText() { return $("dep-commands").value; }
  function countCommands() { $("dep-cmd-count").textContent = commandsText().split(/\r?\n/).filter(function (l) { return l.trim(); }).length; }

  document.querySelectorAll('input[name="dep-src"]').forEach(function (r) {
    r.addEventListener("change", function () {
      $("dep-src-history").classList.toggle("hidden", srcMode() !== "history");
      $("dep-src-text").classList.toggle("hidden", srcMode() !== "text");
    });
  });
  document.querySelectorAll('input[name="dep-mode"]').forEach(function (r) {
    r.addEventListener("change", function () { $("dep-live").classList.toggle("hidden", depMode() !== "live"); });
  });

  function loadConversions() {
    NM.api("/api/history?limit=50").then(function (res) {
      var sel = $("dep-conversion");
      res.items.forEach(function (r) {
        var o = el("option", null, "#" + r.id + " · " + (r.hostname || r.filename || "—") + " · " + NM.dirName(r.direction) + " · " + NM.fmtDate(r.created_at));
        o.value = r.id; sel.appendChild(o);
      });
      var pre = $("deploy-root").getAttribute("data-preselect");
      if (pre) { sel.value = pre; if (sel.value === pre) $("dep-plan").click(); }
    });
  }

  function loadDevices(vendor) {
    NM.api("/api/devices" + (vendor ? "?vendor=" + vendor : "")).then(function (res) {
      var sel = $("dep-device"); sel.replaceChildren();
      var none = el("option", null, T.dep_device_none); none.value = ""; sel.appendChild(none);
      res.items.forEach(function (d) {
        var o = el("option", null, d.name + " · " + d.ip + ":" + d.ssh_port + (d.location ? " · " + d.location : "")); o.value = d.id; sel.appendChild(o);
      });
    });
  }

  function renderPlan(p) {
    plan = p;
    $("dep-review").classList.remove("hidden");
    $("dep-target").classList.remove("hidden");
    $("dep-commands").value = p.commands.join("\n");
    countCommands();
    var ul = $("dep-removed"); ul.replaceChildren();
    p.removed.forEach(function (r) {
      var li = el("li", "flex gap-2 rounded border border-slate-200 p-1.5 dark:border-slate-800");
      li.appendChild(NM.chip(r.reason === "credential" || r.reason === "unconverted" ? "error" : r.reason === "ai_review" ? "review" : "skipped", T["dep_reason_" + r.reason] || r.reason));
      li.appendChild(el("code", "min-w-0 break-all font-mono text-slate-600 dark:text-slate-300", r.reason === "credential" ? T.dep_secret_hidden : r.text));
      ul.appendChild(li);
    });
    $("dep-removed-count").textContent = p.removed.length;
    $("dep-ai-count").textContent = p.ai_review_count;
    $("dep-ack").checked = false;
    $("dep-ack-wrap").classList.toggle("hidden", !p.requires_review_ack);
    $("dep-ack-wrap").classList.toggle("flex", p.requires_review_ack);
    loadDevices(p.vendor);
  }

  $("dep-plan").addEventListener("click", function () {
    $("dep-error").textContent = "";
    var body;
    if (srcMode() === "history") {
      if (!$("dep-conversion").value) { $("dep-error").textContent = T.dep_pick_conversion; $("dep-target").classList.remove("hidden"); return; }
      body = { conversion_id: parseInt($("dep-conversion").value, 10) };
    } else {
      if (!$("dep-text").value.trim()) { $("dep-error").textContent = T.empty_input; $("dep-target").classList.remove("hidden"); return; }
      body = { text: $("dep-text").value, vendor: $("dep-vendor").value };
    }
    planSource = body;
    NM.api("/api/deploy/plan", { method: "POST", json: body }).then(renderPlan).catch(function (e) { $("dep-error").textContent = e.message; });
  });
  $("dep-commands").addEventListener("input", countCommands);

  $("dep-run").addEventListener("click", function () {
    $("dep-error").textContent = "";
    if (!plan) return;
    if (plan.requires_review_ack && !$("dep-ack").checked) { $("dep-error").textContent = T.dep_need_ack; return; }
    if (depMode() === "live") {
      if (!$("dep-device").value) { $("dep-error").textContent = T.dep_need_device; return; }
      if (!$("dep-lab").checked) { $("dep-error").textContent = T.dep_need_lab; return; }
    }
    var cmds = commandsText().split(/\r?\n/).filter(function (l) { return l.trim(); });
    if (!cmds.length) { $("dep-error").textContent = T.dep_no_commands; return; }
    $("dep-confirm-sub").textContent = (depMode() === "live" ? T.dep_mode_live : T.dep_mode_sim) + " · " + VENDOR[plan.vendor] +
      " · " + ($("dep-device").selectedOptions[0] ? $("dep-device").selectedOptions[0].textContent : "") + " · " + cmds.length + " " + T.dep_commands;
    $("dep-confirm-list").textContent = cmds.join("\n");
    $("dep-confirm").showModal();
  });
  $("dep-confirm-cancel").addEventListener("click", function () { $("dep-confirm").close(); });

  $("dep-confirm-ok").addEventListener("click", function () {
    $("dep-confirm").close();
    var body = {
      vendor: plan.vendor, commands: commandsText(), mode: depMode(), confirm: true,
      acknowledge_review: $("dep-ack").checked, lab_confirm: $("dep-lab").checked,
      conversion_id: planSource && planSource.conversion_id ? planSource.conversion_id : null,
      device_id: $("dep-device").value ? parseInt($("dep-device").value, 10) : null,
    };
    if (depMode() === "live") { body.username = $("dep-user").value; body.password = $("dep-pass").value; }
    NM.api("/api/deploy/run", { method: "POST", json: body })
      .then(function (res) { $("dep-pass").value = ""; stream(res); })
      .catch(function (e) { $("dep-error").textContent = e.message; });
  });

  function renderLog() {
    var box = $("dep-log"), q = $("dep-log-q").value.toLowerCase();
    var levels = {};
    document.querySelectorAll("[data-level]").forEach(function (c) { levels[c.getAttribute("data-level")] = c.checked; });
    box.replaceChildren();
    logEntries.forEach(function (e) {
      if (!levels[e.level] || (q && e.message.toLowerCase().indexOf(q) < 0)) return;
      var row = el("div", "flex gap-2");
      row.appendChild(el("span", "shrink-0 text-slate-500", e.ts.slice(11, 19)));
      row.appendChild(el("span", "w-16 shrink-0 font-semibold " + LEVEL_CLS[e.level], e.level));
      row.appendChild(el("span", "min-w-0 whitespace-pre-wrap break-all", e.message));
      box.appendChild(row);
    });
    box.scrollTop = box.scrollHeight;
  }

  function setStatus(s) { var w = $("dep-status"); w.replaceChildren(NM.chip(s, T["status_" + s] || s)); }

  function stream(res) {
    if (es) es.close();
    logEntries = [];
    renderLog();
    setStatus("running");
    $("dep-log-dl").classList.add("hidden");
    es = new EventSource("/api/deploy/jobs/" + res.job_id + "/events");
    es.addEventListener("log", function (ev) { logEntries.push(JSON.parse(ev.data)); renderLog(); });
    es.addEventListener("done", function (ev) {
      var d = JSON.parse(ev.data);
      setStatus(d.status);
      es.close(); es = null;
      $("dep-log-dl").href = "/api/deployments/" + d.deployment_id + "/log.txt";
      $("dep-log-dl").classList.remove("hidden");
      loadHistory();
    });
    es.onerror = function () { if (es) { es.close(); es = null; } };
  }

  function loadHistory() {
    NM.api("/api/deployments").then(function (res) {
      var body = $("dep-history"); body.replaceChildren();
      if (!res.items.length) { var tr = el("tr"), td = el("td", "p-6 text-center text-slate-400", T.dep_history_empty); td.colSpan = 7; tr.appendChild(td); body.appendChild(tr); }
      res.items.forEach(function (d) {
        var tr = el("tr");
        tr.appendChild(el("td", "nm-td tabular-nums text-slate-400", String(d.id)));
        tr.appendChild(el("td", "nm-td whitespace-nowrap text-xs", NM.fmtDate(d.created_at)));
        tr.appendChild(el("td", "nm-td text-xs", (d.device_name || "—") + (d.host ? " · " + d.host : "")));
        tr.appendChild(el("td", "nm-td text-xs", d.mode === "live" ? T.dep_mode_live : T.dep_mode_sim));
        var st = el("td", "nm-td"); st.appendChild(NM.chip(d.status, T["status_" + d.status] || d.status)); tr.appendChild(st);
        tr.appendChild(el("td", "nm-td tabular-nums", String(d.command_count)));
        var act = el("td", "nm-td text-right"); var a = el("a", "nm-btn px-2 py-1 text-xs", T.download_log); a.href = "/api/deployments/" + d.id + "/log.txt"; act.appendChild(a); tr.appendChild(act);
        body.appendChild(tr);
      });
    });
  }

  $("dep-log-q").addEventListener("input", renderLog);
  document.querySelectorAll("[data-level]").forEach(function (c) { c.addEventListener("change", renderLog); });
  loadConversions();
  loadHistory();
})();
