// Module 8 — hardware compatibility check (deterministic rules).
(function () {
  "use strict";
  var NM = window.NM, T = NM.T, el = NM.el, $ = function (id) { return document.getElementById(id); };
  var VERDICT_CLS = {
    ok: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200",
    renumber: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200",
    trim_unused: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950/40 dark:text-sky-200",
    incompatible: "border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200",
  };
  var ICON = { ok: "✓", renumber: "↹", trim_unused: "✂", incompatible: "✕" };
  var STATE_CHIP = { active: "success", prepared: "review", unused: "skipped" };

  function src() { return document.querySelector('input[name="hw-src"]:checked').value; }
  function tgt() { return document.querySelector('input[name="hw-tgt"]:checked').value; }
  document.querySelectorAll('input[name="hw-src"]').forEach(function (r) { r.addEventListener("change", function () {
    $("hw-conversion").classList.toggle("hidden", src() !== "history"); $("hw-text-wrap").classList.toggle("hidden", src() !== "text"); }); });
  document.querySelectorAll('input[name="hw-tgt"]').forEach(function (r) { r.addEventListener("change", function () {
    $("hw-device").classList.toggle("hidden", tgt() !== "device"); $("hw-model").classList.toggle("hidden", tgt() !== "model"); }); });

  NM.api("/api/history?limit=50").then(function (res) {
    res.items.forEach(function (r) {
      var o = el("option", null, "#" + r.id + " · " + (r.hostname || r.filename || "—") + " · " + NM.dirName(r.direction));
      o.value = r.id; $("hw-conversion").appendChild(o);
    });
    var pre = new URLSearchParams(location.search).get("conversion");
    if (pre) $("hw-conversion").value = pre;
  });
  NM.api("/api/devices").then(function (res) {
    res.items.forEach(function (d) {
      var o = el("option", null, d.name + " · " + (d.model_name || T.inv_model_none));
      o.value = d.id; o.disabled = !d.model; $("hw-device").appendChild(o);
    });
  });

  function stat(label, value) {
    var d = el("div", "nm-card p-3");
    d.appendChild(el("div", "text-xs text-slate-500 dark:text-slate-400", label));
    d.appendChild(el("div", "mt-0.5 text-xl font-semibold tabular-nums", String(value)));
    return d;
  }

  function render(r) {
    $("hw-empty").classList.add("hidden");
    $("hw-result").classList.remove("hidden");
    var v = $("hw-verdict");
    v.className = "rounded-xl border p-4 " + VERDICT_CLS[r.verdict];
    v.replaceChildren();
    var head = el("div", "flex items-center gap-3");
    head.appendChild(el("span", "grid h-9 w-9 place-items-center rounded-full bg-white/70 text-lg font-bold dark:bg-black/20", ICON[r.verdict]));
    var t = el("div");
    t.appendChild(el("div", "font-semibold", window.NM_LANG === "en" ? r.verdict_en : r.verdict_th));
    t.appendChild(el("div", "text-xs opacity-80", r.model.display + (r.device ? " · " + r.device.name : "")));
    head.appendChild(t);
    v.appendChild(head);
    var detail = [];
    if (r.out_of_range.length) detail.push(T.hw_out_of_range + ": " + r.out_of_range.join(", "));
    if (r.trim_candidates.length) detail.push(T.hw_trim + ": " + r.trim_candidates.join(", "));
    if (r.shortfall) detail.push(T.hw_shortfall + ": " + r.shortfall);
    detail.forEach(function (d) { v.appendChild(el("p", "mt-2 text-sm", d)); });
    var s = $("hw-stats"); s.replaceChildren();
    s.appendChild(stat(T.hw_capacity, r.capacity));
    s.appendChild(stat(T.hw_declared, r.declared));
    s.appendChild(stat(T.hw_state_active, r.active));
    s.appendChild(stat(T.hw_state_prepared, r.prepared));
    s.appendChild(stat(T.hw_state_unused, r.unused));
    $("hw-ranges").textContent = r.model.ranges.join(", ");
    var body = $("hw-ports"); body.replaceChildren();
    r.ports.forEach(function (p) {
      var tr = el("tr");
      tr.appendChild(el("td", "nm-td font-mono text-xs", p.name));
      var st = el("td", "nm-td"); st.appendChild(NM.chip(STATE_CHIP[p.state], T["hw_state_" + p.state])); tr.appendChild(st);
      tr.appendChild(el("td", "nm-td text-sm " + (p.exists ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"), p.exists ? "✓" : "✕ " + T.hw_not_on_model));
      body.appendChild(tr);
    });
  }

  $("hw-check").addEventListener("click", function () {
    $("hw-error").textContent = "";
    var fd = new FormData();
    if (src() === "history") {
      if (!$("hw-conversion").value) { $("hw-error").textContent = T.dep_pick_conversion; return; }
      fd.append("conversion_id", $("hw-conversion").value);
    } else {
      if (!$("hw-text").value.trim()) { $("hw-error").textContent = T.empty_input; return; }
      fd.append("config", $("hw-text").value); fd.append("vendor", $("hw-vendor").value);
    }
    if (tgt() === "device") {
      if (!$("hw-device").value) { $("hw-error").textContent = T.hw_pick_device; return; }
      fd.append("device_id", $("hw-device").value);
    } else fd.append("model", $("hw-model").value);
    NM.api("/api/hardware/check", { method: "POST", body: fd }).then(render).catch(function (e) { $("hw-error").textContent = e.message; });
  });
})();
