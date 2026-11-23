// Module 5 — dashboard tiles/charts + audit history list.
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var SVG = "http://www.w3.org/2000/svg";
  var PAGE = 20, offset = 0, total = 0;
  var ORDER = ["RULE", "AI", "SYSTEM", "UNCONVERTED", "NOT_NEEDED"];
  var DOT = { RULE: "bg-emerald-500", AI: "bg-amber-500", SYSTEM: "bg-sky-500", UNCONVERTED: "bg-rose-500", NOT_NEEDED: "bg-slate-400" };

  function svg(tag, attrs) {
    var n = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    return n;
  }

  // Single-series bar chart: one hue, thin bars, rounded tops anchored to the baseline,
  // recessive axis, per-bar hover tooltip (title) and a direct label on the max bar only.
  function trendChart(box, data) {
    box.replaceChildren();
    var W = 640, H = 180, pad = { l: 28, r: 8, t: 14, b: 22 };
    var max = Math.max(1, Math.max.apply(null, data.map(function (d) { return d.count; })));
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, class: "h-full w-full" });
    var innerW = W - pad.l - pad.r, innerH = H - pad.t - pad.b, step = innerW / data.length, bw = Math.max(4, step - 6);
    [0, 0.5, 1].forEach(function (f) {
      var y = pad.t + innerH * (1 - f);
      s.appendChild(svg("line", { x1: pad.l, x2: W - pad.r, y1: y, y2: y, class: "stroke-slate-200 dark:stroke-slate-800", "stroke-width": 1 }));
      var lab = svg("text", { x: pad.l - 6, y: y + 3, "text-anchor": "end", class: "fill-slate-400 text-[10px]" });
      lab.textContent = Math.round(max * f); s.appendChild(lab);
    });
    var maxIdx = data.reduce(function (bi, d, i) { return d.count > data[bi].count ? i : bi; }, 0);
    data.forEach(function (d, i) {
      var h = innerH * d.count / max, x = pad.l + i * step + (step - bw) / 2, y = pad.t + innerH - h;
      var g = svg("g", {});
      var hit = svg("rect", { x: pad.l + i * step, y: pad.t, width: step, height: innerH, fill: "transparent" });
      var r = Math.min(4, bw / 2, h), base = pad.t + innerH;
      if (h > 0) {
        // rounded data-end at the top, square at the baseline
        var d = "M" + x + "," + base + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
                "H" + (x + bw - r) + "Q" + (x + bw) + "," + y + " " + (x + bw) + "," + (y + r) + "V" + base + "Z";
        g.appendChild(svg("path", { d: d, class: "fill-teal-600 dark:fill-teal-400" }));
      }
      var tip = svg("title", {}); tip.textContent = d.day + ": " + d.count + " " + T.dash_conversions_unit; g.appendChild(tip);
      g.appendChild(hit);
      if (i === maxIdx && d.count > 0) {
        var lab = svg("text", { x: x + bw / 2, y: y - 3, "text-anchor": "middle", class: "fill-slate-600 text-[10px] font-medium dark:fill-slate-300" });
        lab.textContent = d.count; g.appendChild(lab);
      }
      if (i % 2 === (data.length - 1) % 2) {
        var dl = svg("text", { x: pad.l + i * step + step / 2, y: H - 6, "text-anchor": "middle", class: "fill-slate-400 text-[10px]" });
        dl.textContent = d.day.slice(5); g.appendChild(dl);
      }
      s.appendChild(g);
    });
    box.appendChild(s);
  }

  // Two-category share: one stacked bar (2px gap), legend + direct labels with values.
  function shareChart(box, byDir) {
    box.replaceChildren();
    var total = byDir.c2h + byDir.h2c;
    var bar = el("div", "flex h-3 gap-0.5 overflow-hidden rounded");
    var parts = [["c2h", "bg-teal-600 dark:bg-teal-400"], ["h2c", "bg-indigo-500 dark:bg-indigo-400"]];
    parts.forEach(function (p) {
      var seg = el("div", p[1]);
      seg.style.width = total ? (100 * byDir[p[0]] / total) + "%" : "50%";
      if (!total) seg.classList.add("opacity-20");
      seg.title = NM.dirName(p[0]) + ": " + byDir[p[0]];
      bar.appendChild(seg);
    });
    box.appendChild(bar);
    var legend = el("ul", "mt-3 space-y-1 text-sm");
    parts.forEach(function (p) {
      var li = el("li", "flex items-center gap-2");
      li.appendChild(el("span", "h-2.5 w-2.5 rounded-sm " + p[1]));
      li.appendChild(el("span", "", NM.dirName(p[0])));
      li.appendChild(el("span", "ml-auto tabular-nums text-slate-500 dark:text-slate-400",
        byDir[p[0]] + (total ? " (" + Math.round(100 * byDir[p[0]] / total) + "%)" : "")));
      legend.appendChild(li);
    });
    box.appendChild(legend);
  }

  function loadDashboard() {
    NM.api("/api/dashboard").then(function (d) {
      $("d-conversions").textContent = d.conversions;
      $("d-review").textContent = d.review_count;
      $("d-coverage").textContent = d.conversions ? d.avg_coverage + "%" : "—";
      $("d-secrets").textContent = d.secret_stripped;
      trendChart($("d-trend"), d.trend);
      shareChart($("d-share"), d.by_direction);
      var ul = $("d-lines"); ul.replaceChildren();
      ORDER.forEach(function (k) {
        var li = el("li", "flex items-center gap-2");
        li.appendChild(el("span", "h-2.5 w-2.5 rounded-full " + DOT[k]));
        li.appendChild(el("span", "", T["prov_" + k]));
        li.appendChild(el("span", "ml-auto tabular-nums font-medium", String(d.lines[k])));
        ul.appendChild(li);
      });
    }).catch(function () {});
  }

  function params() {
    var p = new URLSearchParams();
    ["q", "direction", "mode", "kind"].forEach(function (k) { var v = $("h-" + k).value; if (v) p.set(k, v); });
    return p;
  }

  function loadList() {
    var p = params();
    $("h-export").href = "/api/history/export?" + p.toString();
    p.set("limit", PAGE); p.set("offset", offset);
    NM.api("/api/history?" + p.toString()).then(function (res) {
      total = res.total;
      var body = $("h-rows"); body.replaceChildren();
      if (!res.items.length) {
        var tr = el("tr"), td = el("td", "p-8 text-center text-slate-400", T.history_empty); td.colSpan = 8; tr.appendChild(td); body.appendChild(tr);
      }
      res.items.forEach(function (r) {
        var tr = el("tr", "hover:bg-slate-50 dark:hover:bg-slate-800/40");
        tr.appendChild(el("td", "nm-td tabular-nums text-slate-400", String(r.id)));
        tr.appendChild(el("td", "nm-td whitespace-nowrap text-xs", NM.fmtDate(r.created_at)));
        var nm = el("td", "nm-td");
        nm.appendChild(el("div", "font-medium", r.hostname || r.filename || "—"));
        var sub = el("div", "text-xs text-slate-400", (r.filename && r.hostname ? r.filename + " · " : "") + (r.kind === "batch" ? T.kind_batch : T.kind_single));
        nm.appendChild(sub);
        tr.appendChild(nm);
        tr.appendChild(el("td", "nm-td whitespace-nowrap text-xs", NM.dirName(r.direction)));
        tr.appendChild(el("td", "nm-td whitespace-nowrap text-xs", NM.modeName(r.effective_mode)));
        tr.appendChild(el("td", "nm-td tabular-nums", r.coverage_percent + "%"));
        var prov = el("td", "nm-td"), wrap = el("div", "flex flex-wrap gap-1");
        [["RULE", r.count_rule], ["AI", r.count_ai], ["SYSTEM", r.count_system], ["UNCONVERTED", r.count_unconverted], ["NOT_NEEDED", r.count_not_needed]]
          .forEach(function (p) { if (p[1]) wrap.appendChild(el("span", "nm-chip " + NM.BADGE[p[0]], T["prov_" + p[0]] + " " + p[1])); });
        prov.appendChild(wrap); tr.appendChild(prov);
        var act = el("td", "nm-td whitespace-nowrap text-right");
        var view = el("a", "nm-btn px-2 py-1 text-xs", T.view); view.href = "/history/" + r.id;
        var dl = el("a", "nm-btn ml-1 px-2 py-1 text-xs", T.download_txt); dl.href = "/api/history/" + r.id + "/download";
        var del = el("button", "nm-btn-danger ml-1 px-2 py-1 text-xs", T.delete); del.type = "button";
        del.addEventListener("click", function () {
          if (!confirm(T.confirm_delete)) return;
          NM.api("/api/history/" + r.id, { method: "DELETE" }).then(function () { loadList(); loadDashboard(); });
        });
        act.appendChild(view); act.appendChild(dl); act.appendChild(del);
        tr.appendChild(act);
        body.appendChild(tr);
      });
      $("h-count").textContent = total ? (offset + 1) + "–" + Math.min(offset + PAGE, total) + " / " + total : "";
      $("h-prev").disabled = offset === 0;
      $("h-next").disabled = offset + PAGE >= total;
    }).catch(function () {});
  }

  var timer;
  $("h-q").addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(function () { offset = 0; loadList(); }, 250); });
  ["direction", "mode", "kind"].forEach(function (k) { $("h-" + k).addEventListener("change", function () { offset = 0; loadList(); }); });
  $("h-prev").addEventListener("click", function () { offset = Math.max(0, offset - PAGE); loadList(); });
  $("h-next").addEventListener("click", function () { offset += PAGE; loadList(); });
  loadDashboard();
  loadList();
})();
