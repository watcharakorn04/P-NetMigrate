// Module 3 — device inventory CRUD with search/filter (register only, no credentials).
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var VENDOR = { cisco_ios_xe: "Cisco IOS-XE", huawei_vrp: "Huawei VRP" };
  var DEV_STATUS = { active: "success", inactive: "skipped", maintenance: "review" };

  function filterModels() {
    var v = $("inv-vendor").value;
    Array.prototype.forEach.call($("inv-model").options, function (o) {
      if (!o.value) return;
      o.hidden = o.getAttribute("data-vendor") !== v;
      if (o.hidden && o.selected) $("inv-model").value = "";
    });
  }

  function resetForm() {
    $("inv-form").reset();
    $("inv-id").value = "";
    $("inv-port").value = 22;
    $("inv-form-title").textContent = T.inv_add;
    $("inv-cancel").classList.add("hidden");
    $("inv-error").textContent = "";
    filterModels();
  }

  function edit(d) {
    $("inv-id").value = d.id;
    $("inv-name").value = d.name; $("inv-ip").value = d.ip; $("inv-vendor").value = d.vendor;
    filterModels();
    $("inv-model").value = d.model; $("inv-port").value = d.ssh_port; $("inv-os").value = d.os_version;
    $("inv-location").value = d.location; $("inv-status").value = d.status;
    $("inv-form-title").textContent = T.inv_edit + " — " + d.name;
    $("inv-cancel").classList.remove("hidden");
    $("inv-name").focus();
  }

  function load() {
    var p = new URLSearchParams();
    if ($("inv-q").value) p.set("q", $("inv-q").value);
    if ($("inv-f-vendor").value) p.set("vendor", $("inv-f-vendor").value);
    if ($("inv-f-location").value) p.set("location", $("inv-f-location").value);
    NM.api("/api/devices?" + p.toString()).then(function (res) {
      var body = $("inv-rows"); body.replaceChildren();
      if (!res.items.length) {
        var tr = el("tr"), td = el("td", "p-8 text-center text-slate-400", T.inv_empty); td.colSpan = 7; tr.appendChild(td); body.appendChild(tr);
      }
      res.items.forEach(function (d) {
        var tr = el("tr", "hover:bg-slate-50 dark:hover:bg-slate-800/40");
        tr.appendChild(el("td", "nm-td font-medium", d.name));
        tr.appendChild(el("td", "nm-td font-mono text-xs", d.ip + ":" + d.ssh_port));
        tr.appendChild(el("td", "nm-td whitespace-nowrap text-xs", VENDOR[d.vendor]));
        var m = el("td", "nm-td text-xs");
        m.appendChild(el("div", "", d.model_name || "—"));
        if (d.os_version) m.appendChild(el("div", "text-slate-400", d.os_version));
        tr.appendChild(m);
        tr.appendChild(el("td", "nm-td text-xs", d.location || "—"));
        var st = el("td", "nm-td"); st.appendChild(NM.chip(DEV_STATUS[d.status], T["dev_status_" + d.status])); tr.appendChild(st);
        var act = el("td", "nm-td whitespace-nowrap text-right");
        var e = el("button", "nm-btn px-2 py-1 text-xs", T.edit); e.type = "button"; e.addEventListener("click", function () { edit(d); });
        var del = el("button", "nm-btn-danger ml-1 px-2 py-1 text-xs", T.delete); del.type = "button";
        del.addEventListener("click", function () {
          if (!confirm(T.confirm_delete)) return;
          NM.api("/api/devices/" + d.id, { method: "DELETE" }).then(load);
        });
        act.appendChild(e); act.appendChild(del); tr.appendChild(act);
        body.appendChild(tr);
      });
    });
  }

  $("inv-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var id = $("inv-id").value;
    var data = {
      name: $("inv-name").value, ip: $("inv-ip").value, vendor: $("inv-vendor").value,
      model: $("inv-model").value, ssh_port: parseInt($("inv-port").value || "22", 10),
      os_version: $("inv-os").value, location: $("inv-location").value, status: $("inv-status").value,
    };
    NM.api(id ? "/api/devices/" + id : "/api/devices", { method: id ? "PUT" : "POST", json: data })
      .then(function () { resetForm(); load(); })
      .catch(function (e) { $("inv-error").textContent = e.message; });
  });
  $("inv-cancel").addEventListener("click", resetForm);
  $("inv-vendor").addEventListener("change", filterModels);
  var timer;
  ["inv-q", "inv-f-location"].forEach(function (i) { $(i).addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(load, 250); }); });
  $("inv-f-vendor").addEventListener("change", load);
  filterModels();
  load();
})();
