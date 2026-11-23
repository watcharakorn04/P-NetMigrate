// Module 7 — topology map (rules) + optional AI explanation + 3-level advisory side by side.
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var SVG = "http://www.w3.org/2000/svg";
  var files = [], result = null;
  var VENDOR = { cisco_ios_xe: "Cisco IOS-XE", huawei_vrp: "Huawei VRP" };
  var ROLE_CHIP = { uplink: "running", access: "success", routed: "review", trunk: "review", unused: "skipped" };

  function svg(tag, attrs, text) {
    var n = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function setFiles(list) {
    files = list;
    $("topo-file-list").textContent = files.map(function (f) { return f.name; }).join(", ");
    $("topo-analyze").disabled = !files.length;
  }

  $("topo-files").addEventListener("change", function (e) { setFiles(Array.prototype.slice.call(e.target.files)); e.target.value = ""; });
  $("topo-samples").addEventListener("click", function () {
    Promise.all(["cisco", "huawei"].map(function (v) {
      return fetch("/static/samples/" + v + "_sample.txt", { cache: "no-store" }).then(function (r) { return r.blob(); })
        .then(function (b) { return new File([b], v + "_sample.txt", { type: "text/plain" }); });
    })).then(setFiles);
  });

  function drawMap(res) {
    var box = $("topo-map"); box.replaceChildren();
    var W = 640, H = 480, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 80, n = res.devices.length;
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, class: "h-full w-full" });
    var pos = res.devices.map(function (d, i) {
      var a = n === 1 ? 0 : (2 * Math.PI * i) / n - Math.PI / 2;
      return n === 1 ? { x: cx, y: cy } : { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
    });
    var pairCount = {};
    res.links.forEach(function (l) {
      var key = Math.min(l.a, l.b) + "-" + Math.max(l.a, l.b);
      var k = pairCount[key] = (pairCount[key] || 0) + 1;
      var p1 = pos[l.a], p2 = pos[l.b], off = (k - 1) * 14;
      var mx = (p1.x + p2.x) / 2 + off, my = (p1.y + p2.y) / 2 + off;
      var cls = l.kind === "l3" ? "stroke-teal-600 dark:stroke-teal-400" : l.kind === "bgp" ? "stroke-indigo-500" : "stroke-slate-500";
      var dash = l.kind === "bgp" ? "6 4" : l.kind === "description" ? "2 4" : "";
      var g = svg("g", {});
      g.appendChild(svg("path", { d: "M" + p1.x + "," + p1.y + " Q" + mx + "," + my + " " + p2.x + "," + p2.y, fill: "none", "stroke-width": 2, "stroke-dasharray": dash, class: cls }));
      var label = (l.subnet || "") + (l.protocols.length ? " · " + l.protocols.join("/") : "");
      if (label) {
        var tx = svg("text", { x: mx, y: my - 6, "text-anchor": "middle", class: "fill-slate-600 text-[11px] dark:fill-slate-300", "paint-order": "stroke", stroke: "currentColor", "stroke-width": 0 }, label);
        g.appendChild(tx);
      }
      var tip = svg("title", {}, res.devices[l.a].name + " " + (l.a_port || "") + " ⇄ " + res.devices[l.b].name + " " + (l.b_port || "") + (label ? " — " + label : ""));
      g.appendChild(tip);
      s.appendChild(g);
    });
    res.devices.forEach(function (d, i) {
      var p = pos[i], g = svg("g", {});
      g.appendChild(svg("rect", { x: p.x - 62, y: p.y - 24, width: 124, height: 48, rx: 10, "stroke-width": 2,
        class: (d.vendor === "cisco_ios_xe" ? "stroke-sky-600" : "stroke-rose-500") + " fill-white dark:fill-slate-900" }));
      g.appendChild(svg("text", { x: p.x, y: p.y - 4, "text-anchor": "middle", class: "fill-slate-800 text-[13px] font-semibold dark:fill-slate-100" }, d.name));
      g.appendChild(svg("text", { x: p.x, y: p.y + 13, "text-anchor": "middle", class: "fill-slate-500 text-[10px] dark:fill-slate-400" }, (T["role_" + d.role] || d.role)));
      g.appendChild(svg("title", {}, d.name + " — " + VENDOR[d.vendor] + " — " + (T["role_" + d.role] || d.role)));
      s.appendChild(g);
    });
    box.appendChild(s);
  }

  function deviceCard(d) {
    var c = el("div", "nm-card");
    var top = el("div", "flex items-start gap-2");
    var title = el("div");
    title.appendChild(el("div", "font-semibold", d.name));
    title.appendChild(el("div", "text-xs text-slate-500 dark:text-slate-400", VENDOR[d.vendor] + " · " + d.file));
    top.appendChild(title);
    top.appendChild(el("span", "nm-chip ml-auto bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300", T["role_" + d.role] || d.role));
    c.appendChild(top);
    c.appendChild(el("p", "mt-1 text-[11px] text-slate-400", T.topo_role_rule));
    var meta = el("div", "mt-2 flex flex-wrap gap-1");
    d.protocols.forEach(function (p) { meta.appendChild(el("span", "nm-chip bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300", p)); });
    if (d.vlans.length) meta.appendChild(el("span", "nm-chip bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300", "VLAN " + d.vlans.join(", ")));
    c.appendChild(meta);
    var ul = el("ul", "mt-3 space-y-1 text-xs");
    d.ports.forEach(function (p) {
      var li = el("li", "flex items-center gap-2");
      li.appendChild(el("span", "font-mono", p.name));
      li.appendChild(NM.chip(ROLE_CHIP[p.role], T["port_" + p.role] || p.role));
      var extra = p.ip || (p.access_vlan ? "VLAN " + p.access_vlan : "") || (p.trunk_vlans ? "VLAN " + p.trunk_vlans.join(",") : "");
      if (extra) li.appendChild(el("span", "ml-auto font-mono text-slate-400", extra));
      ul.appendChild(li);
    });
    c.appendChild(ul);
    return c;
  }

  function renderAdvisory() {
    if (!result) return;
    var d = result.devices[parseInt($("adv-device").value || "0", 10)], level = parseInt($("adv-level").value, 10);
    if (!d) return;
    ["cisco_ios_xe", "huawei_vrp"].forEach(function (v) {
      var lines = [];
      for (var lv = 1; lv <= level; lv++) lines = lines.concat(d.advisory[String(lv)][v]);
      $("adv-" + v).textContent = lines.join("\n");
    });
  }

  function render(res) {
    result = res;
    $("topo-result").classList.remove("hidden");
    drawMap(res);
    var devs = $("topo-devices"); devs.replaceChildren();
    res.devices.forEach(function (d) { devs.appendChild(deviceCard(d)); });
    var sn = $("topo-subnets"); sn.replaceChildren();
    res.subnets.forEach(function (s) {
      var tr = el("tr");
      var a = el("td", "nm-td font-mono text-xs"); a.textContent = s.network;
      if (s.shared) a.appendChild(el("span", "nm-chip ml-2 bg-teal-50 text-teal-700 ring-teal-600/20 dark:bg-teal-500/15 dark:text-teal-300", T.topo_shared));
      tr.appendChild(a);
      tr.appendChild(el("td", "nm-td text-xs", s.members.map(function (m) { return res.devices[m.device].name + " " + m.port + " (" + m.ip + ")"; }).join(" · ")));
      sn.appendChild(tr);
    });
    var vl = $("topo-vlans"); vl.replaceChildren();
    res.vlans.forEach(function (v) {
      var tr = el("tr");
      tr.appendChild(el("td", "nm-td font-mono text-xs", v.id + (v.name ? " (" + v.name + ")" : "")));
      tr.appendChild(el("td", "nm-td text-xs", v.devices.map(function (i) { return res.devices[i].name; }).join(", ")));
      vl.appendChild(tr);
    });
    var un = $("topo-unresolved"); un.replaceChildren();
    if (!res.unresolved.length) un.appendChild(el("li", "text-slate-400", T.none));
    res.unresolved.forEach(function (u) { un.appendChild(el("li", "font-mono", u.device + " " + u.port + (u.vlans.length ? " — VLAN " + u.vlans.join(",") : ""))); });
    var sel = $("adv-device"); sel.replaceChildren();
    res.devices.forEach(function (d, i) { var o = el("option", null, d.name); o.value = i; sel.appendChild(o); });
    $("topo-ai-out").classList.add("hidden");
    renderAdvisory();
    var errs = res.errors.map(function (e) { return e.name + ": " + T.topo_vendor_unknown; })
      .concat(res.skipped.map(function (s) { return s.filename + ": " + s.reason; }));
    $("topo-error").textContent = errs.join(" · ");
  }

  $("topo-analyze").addEventListener("click", function () {
    $("topo-error").textContent = "";
    var fd = new FormData();
    files.forEach(function (f) { fd.append("files", f, f.name); });
    $("topo-analyze").disabled = true;
    NM.api("/api/topology/analyze", { method: "POST", body: fd }).then(render)
      .catch(function (e) { $("topo-error").textContent = e.message; })
      .finally(function () { $("topo-analyze").disabled = !files.length; });
  });

  $("topo-ai").addEventListener("click", function () {
    if (!result) return;
    $("topo-ai").disabled = true;
    NM.api("/api/topology/describe", { method: "POST", json: { summary: result.summary, lang: window.NM_LANG || "th" } })
      .then(function (r) {
        $("topo-ai-out").classList.remove("hidden");
        $("topo-ai-text").textContent = r.text || (r.available ? T.topo_ai_failed : T.topo_ai_off);
      })
      .catch(function (e) { $("topo-error").textContent = e.message; })
      .finally(function () { $("topo-ai").disabled = false; });
  });

  $("adv-device").addEventListener("change", renderAdvisory);
  $("adv-level").addEventListener("change", renderAdvisory);
  document.querySelectorAll("[data-adv-copy]").forEach(function (b) {
    b.addEventListener("click", function () { NM.copy($("adv-" + b.getAttribute("data-adv-copy")).textContent, b); });
  });
  document.querySelectorAll("[data-adv-download]").forEach(function (b) {
    b.addEventListener("click", function () {
      var v = b.getAttribute("data-adv-download"), d = result && result.devices[parseInt($("adv-device").value || "0", 10)];
      if (!d) return;
      NM.download("advisory-" + d.name + "-L" + $("adv-level").value + "-" + (v === "cisco_ios_xe" ? "cisco" : "huawei") + ".txt", $("adv-" + v).textContent);
    });
  });
})();
