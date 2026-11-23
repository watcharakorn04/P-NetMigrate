// Module 5.3 — one history record: metadata, before/after aligned view, difflib compare.
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var id = $("detail-root").getAttribute("data-conversion-id");
  var record = null, aligned = [];
  var VENDOR = { cisco_ios_xe: "Cisco IOS-XE", huawei_vrp: "Huawei VRP" };
  var TINT = { AI: "bg-amber-50/80 dark:bg-amber-500/5", UNCONVERTED: "bg-rose-50/80 dark:bg-rose-500/5" };
  var STRIPE = { RULE: "border-emerald-500", AI: "border-amber-500", SYSTEM: "border-sky-500", UNCONVERTED: "border-rose-500", NOT_NEEDED: "border-slate-400" };
  var DIFF = { equal: "", replace: "bg-amber-50 dark:bg-amber-500/10", delete: "bg-rose-50 dark:bg-rose-500/10", insert: "bg-emerald-50 dark:bg-emerald-500/10" };

  function stat(label, value) {
    var d = el("div", "nm-card p-3");
    d.appendChild(el("div", "text-xs text-slate-500 dark:text-slate-400", label));
    d.appendChild(el("div", "mt-0.5 text-lg font-semibold tabular-nums", String(value)));
    return d;
  }

  function renderMeta(r) {
    $("dt-name").textContent = r.hostname || r.filename || "";
    $("dt-meta").textContent = NM.fmtDate(r.created_at) + " · " + NM.dirName(r.direction) + " · " + T.requested_mode + ": " +
      NM.modeName(r.requested_mode) + " · " + T.effective_mode + ": " + NM.modeName(r.effective_mode) +
      " · " + (r.kind === "batch" ? T.kind_batch : T.kind_single) + (r.filename ? " · " + r.filename : "");
    var s = $("dt-stats"); s.replaceChildren();
    s.appendChild(stat(T.coverage, r.coverage_percent + "%"));
    s.appendChild(stat(T.prov_RULE, r.count_rule));
    s.appendChild(stat(T.prov_AI, r.count_ai));
    s.appendChild(stat(T.prov_SYSTEM, r.count_system));
    s.appendChild(stat(T.prov_UNCONVERTED, r.count_unconverted));
    s.appendChild(stat(T.secret_stripped, r.secret_stripped_count));
    var n = $("dt-notices"); n.replaceChildren();
    r.notices.forEach(function (x) { n.appendChild(el("p", "", "ℹ " + x)); });
    n.classList.toggle("hidden", !r.notices.length);
    var wl = $("dt-warn-list"); wl.replaceChildren();
    r.warnings.forEach(function (w) { wl.appendChild(el("li", "", w)); });
    $("dt-warn-count").textContent = r.warnings.length;
    $("dt-warnings").classList.toggle("hidden", !r.warnings.length);
    $("dt-left-head").textContent = T.diff_before + " — " + VENDOR[r.source_vendor];
    $("dt-right-head").textContent = T.diff_after + " — " + VENDOR[r.target_vendor];
  }

  function renderAligned() {
    var box = $("dt-aligned"), hide = $("dt-only-changed").checked;
    box.replaceChildren();
    aligned.forEach(function (row) {
      if (hide && !row.source.trim() && !row.outputs.length) return;
      var wrap = el("div", "grid grid-cols-2 border-b border-slate-100 dark:border-slate-800/60");
      var left = el("div", "flex gap-2 px-2");
      left.appendChild(el("span", "w-8 shrink-0 select-none text-right text-slate-400", row.no || ""));
      left.appendChild(el("pre", "min-w-0 flex-1 whitespace-pre-wrap break-all", row.source || " "));
      wrap.appendChild(left);
      var right = el("div", "border-l border-slate-200 dark:border-slate-800");
      if (!row.outputs.length) right.appendChild(el("div", "px-2 text-slate-300 dark:text-slate-600", " "));
      row.outputs.forEach(function (line) {
        var r = el("div", "flex items-start gap-2 border-l-4 pl-2 pr-2 " + STRIPE[line.provenance] + " " + (TINT[line.provenance] || ""));
        var badge = el("span", "nm-chip mt-0.5 shrink-0 " + NM.BADGE[line.provenance], line.label);
        r.appendChild(badge);
        r.appendChild(el("pre", "min-w-0 flex-1 whitespace-pre-wrap break-all " + (line.is_comment ? "text-slate-500 dark:text-slate-400" : ""), line.text || " "));
        if (line.warning) { var w = el("span", "mt-1 cursor-help text-amber-500", "⚠"); w.title = line.warning; r.appendChild(w); }
        right.appendChild(r);
      });
      wrap.appendChild(right);
      box.appendChild(wrap);
    });
  }

  function renderCompare(res, otherId) {
    var c = res.counts;
    $("dt-compare-summary").textContent = "#" + id + " ⇄ #" + otherId + " — " + T.diff_similarity + " " + Math.round(res.ratio * 100) + "% · " +
      T.diff_changed + " " + c.replace + " · " + T.diff_removed + " " + c.delete + " · " + T.diff_added + " " + c.insert +
      (res.same_target ? "" : " · ⚠ " + T.diff_vendor_mismatch);
    var box = $("dt-compare-rows"); box.replaceChildren();
    res.rows.forEach(function (row) {
      var g = el("div", "grid grid-cols-2 " + DIFF[row.tag]);
      [["left_no", "left"], ["right_no", "right"]].forEach(function (k, i) {
        var cell = el("div", "flex gap-2 px-2 " + (i ? "border-l border-slate-200 dark:border-slate-800" : ""));
        cell.appendChild(el("span", "w-8 shrink-0 select-none text-right text-slate-400", row[k[0]] || ""));
        cell.appendChild(el("pre", "min-w-0 flex-1 whitespace-pre-wrap break-all", row[k[1]] === null ? " " : row[k[1]] || " "));
        g.appendChild(cell);
      });
      box.appendChild(g);
    });
  }

  NM.api("/api/history/" + id + "?lang=" + (window.NM_LANG || "th")).then(function (r) { record = r; renderMeta(r); });
  NM.api("/api/history/" + id + "/diff?lang=" + (window.NM_LANG || "th")).then(function (d) { aligned = d.rows; renderAligned(); });
  $("dt-only-changed").addEventListener("change", renderAligned);
  $("dt-copy").addEventListener("click", function () { if (record) NM.copy(record.output_text, $("dt-copy")); });
  $("dt-delete").addEventListener("click", function () {
    if (!confirm(T.confirm_delete)) return;
    NM.api("/api/history/" + id, { method: "DELETE" }).then(function () { location.href = "/history"; });
  });
  $("dt-compare").addEventListener("click", function () {
    var other = $("dt-other").value;
    if (!other) return;
    NM.api("/api/history/compare?a=" + id + "&b=" + encodeURIComponent(other))
      .then(function (res) { renderCompare(res, other); })
      .catch(function (e) { $("dt-compare-summary").textContent = e.message; $("dt-compare-rows").replaceChildren(); });
  });
})();
