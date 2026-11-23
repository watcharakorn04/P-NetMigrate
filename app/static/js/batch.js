// Module 2 — batch conversion queue. Each queued file is sent on its own (progress, 2.3)
// under one batch id; the server builds the combined .zip from the audit history.
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var queue = [];       // {file, direction, status, rows: []}
  var batchId = null;
  var running = false;

  function isZip(f) { return /\.zip$/i.test(f.name); }
  function accepted(f) { return /\.(txt|cfg|zip)$/i.test(f.name); }

  function addFiles(list) {
    $("batch-error").textContent = "";
    Array.prototype.forEach.call(list, function (f) {
      if (!accepted(f)) { $("batch-error").textContent = T.batch_bad_type + ": " + f.name; return; }
      queue.push({ file: f, direction: "default", status: "queued", rows: [] });
    });
    render();
  }

  function dirSelect(item) {
    var s = el("select", "nm-input py-1 text-xs");
    [["default", T.batch_use_default], ["auto", T.dir_auto], ["c2h", T.dir_c2h], ["h2c", T.dir_h2c]].forEach(function (o) {
      var opt = el("option", null, o[1]); opt.value = o[0]; s.appendChild(opt);
    });
    s.value = item.direction;
    s.disabled = item.status !== "queued";
    s.addEventListener("change", function () { item.direction = s.value; });
    return s;
  }

  function provCell(counts) {
    var wrap = el("div", "flex flex-wrap gap-1");
    ["RULE", "AI", "SYSTEM", "UNCONVERTED", "NOT_NEEDED"].forEach(function (k) {
      if (!counts[k]) return;
      var c = el("span", "nm-chip " + NM.BADGE[k], T["prov_" + k] + " " + counts[k]);
      wrap.appendChild(c);
    });
    return wrap;
  }

  function resultRow(r) {
    var tr = el("tr", "bg-slate-50/50 dark:bg-slate-800/20");
    var name = el("td", "nm-td pl-8 font-mono text-xs");
    name.textContent = "↳ " + r.filename;
    tr.appendChild(name);
    tr.appendChild(el("td", "nm-td text-xs", r.direction ? NM.dirName(r.direction) : "—"));
    var st = el("td", "nm-td");
    st.appendChild(NM.chip(r.status, T["status_" + r.status] || r.status));
    if (r.reason) st.appendChild(el("div", "mt-1 max-w-xs text-xs text-slate-500 dark:text-slate-400", r.reason));
    tr.appendChild(st);
    var cov = el("td", "nm-td tabular-nums");
    if (r.coverage_percent !== undefined) {
      cov.appendChild(el("div", "text-sm font-semibold", r.coverage_percent + "%"));
      var bar = el("div", "mt-1 h-1.5 w-24 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700");
      var fill = el("div", "h-full " + (r.coverage_percent >= 90 ? "bg-emerald-500" : r.coverage_percent >= 60 ? "bg-amber-500" : "bg-rose-500"));
      fill.style.width = r.coverage_percent + "%";
      bar.appendChild(fill); cov.appendChild(bar);
    }
    tr.appendChild(cov);
    var prov = el("td", "nm-td");
    if (r.provenance_counts) prov.appendChild(provCell(r.provenance_counts));
    tr.appendChild(prov);
    tr.appendChild(el("td", "nm-td tabular-nums", r.secret_stripped_count !== undefined ? String(r.secret_stripped_count) : ""));
    var act = el("td", "nm-td whitespace-nowrap text-right");
    if (r.history_id) {
      var dl = el("a", "nm-btn px-2 py-1 text-xs", T.download_txt);
      dl.href = "/api/history/" + r.history_id + "/download";
      var view = el("a", "nm-btn ml-1 px-2 py-1 text-xs", T.view);
      view.href = "/history/" + r.history_id;
      act.appendChild(dl); act.appendChild(view);
    }
    tr.appendChild(act);
    return tr;
  }

  function render() {
    var body = $("batch-rows");
    body.replaceChildren();
    if (!queue.length) {
      var tr = el("tr"); var td = el("td", "p-8 text-center text-slate-400", T.batch_empty); td.colSpan = 7; tr.appendChild(td); body.appendChild(tr);
    }
    queue.forEach(function (item, idx) {
      var tr = el("tr");
      var name = el("td", "nm-td");
      name.appendChild(el("div", "font-mono text-xs font-medium", item.file.name));
      name.appendChild(el("div", "text-[11px] text-slate-400", (isZip(item.file) ? "ZIP · " : "") + Math.max(1, Math.round(item.file.size / 1024)) + " KB"));
      tr.appendChild(name);
      var d = el("td", "nm-td"); d.appendChild(dirSelect(item)); tr.appendChild(d);
      var st = el("td", "nm-td"); st.appendChild(NM.chip(item.status, T["status_" + item.status] || item.status));
      if (item.error) st.appendChild(el("div", "mt-1 text-xs text-rose-600 dark:text-rose-400", item.error));
      tr.appendChild(st);
      var filler = el("td", "nm-td"); filler.colSpan = 3; tr.appendChild(filler);
      var act = el("td", "nm-td text-right");
      if (item.status === "queued" && !running) {
        var rm = el("button", "nm-btn px-2 py-1 text-xs", T.remove); rm.type = "button";
        rm.addEventListener("click", function () { queue.splice(idx, 1); render(); });
        act.appendChild(rm);
      }
      tr.appendChild(act);
      body.appendChild(tr);
      item.rows.forEach(function (r) { body.appendChild(resultRow(r)); });
    });
    var done = queue.filter(function (q) { return q.status !== "queued" && q.status !== "running"; }).length;
    $("batch-progress-text").textContent = queue.length ? (T.batch_progress + " " + done + " / " + queue.length) : "";
    $("batch-bar").style.width = queue.length ? (100 * done / queue.length) + "%" : "0%";
    $("batch-start").disabled = running || !queue.some(function (q) { return q.status === "queued"; });
    var dl = $("batch-download");
    var ready = batchId && !running && done > 0;
    dl.classList.toggle("pointer-events-none", !ready);
    dl.classList.toggle("opacity-40", !ready);
    dl.setAttribute("aria-disabled", ready ? "false" : "true");
    if (ready) dl.href = "/api/batch/" + batchId + "/download";
  }

  function next() {
    var item = queue.find(function (q) { return q.status === "queued"; });
    if (!item) { running = false; render(); return; }
    item.status = "running";
    render();
    var fd = new FormData();
    fd.append("files", item.file, item.file.name);
    fd.append("direction", item.direction === "default" ? $("batch-direction").value : item.direction);
    fd.append("mode", $("batch-mode").value);
    fd.append("lang", window.NM_LANG || "th");
    if (batchId) fd.append("batch_id", batchId);
    NM.api("/api/batch/convert", { method: "POST", body: fd })
      .then(function (res) {
        batchId = res.batch_id;
        item.rows = res.rows;
        var bad = res.rows.length && res.rows.every(function (r) { return r.status === "skipped" || r.status === "error"; });
        item.status = bad ? "skipped" : res.rows.some(function (r) { return r.status === "review"; }) ? "review" : "done";
      })
      .catch(function (err) { item.status = "error"; item.error = err.message; })
      .finally(next);
  }

  $("batch-files").addEventListener("change", function (e) { addFiles(e.target.files); e.target.value = ""; });
  var dz = $("dropzone");
  ["dragenter", "dragover"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add("border-teal-500"); }); });
  ["dragleave", "drop"].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove("border-teal-500"); }); });
  dz.addEventListener("drop", function (e) { if (e.dataTransfer) addFiles(e.dataTransfer.files); });
  $("batch-start").addEventListener("click", function () { if (running) return; running = true; next(); });
  $("batch-clear").addEventListener("click", function () { if (running) return; queue = []; batchId = null; render(); });
  render();
})();
