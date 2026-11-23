// Runs the real app/static/js/convert.js against a minimal stub DOM.
// usage: node convert_harness.js <convert.js> <prescan|convert> <wait|race>
//   wait — click the sample button, let it load, then click the action
//   race — click the action immediately, while the sample fetch is still in flight
// Exit 0 when the action request was sent with the sample text and no "empty" error is shown.
const fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
const action = process.argv[3] || "prescan";
const timing = process.argv[4] || "wait";
function node(id) {
  const n = { id, value: "", textContent: "", checked: id === "show-labels", disabled: false, files: null, style: {},
    className: "", listeners: {}, attrs: {}, childNodes: [],
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
    dispatchEvent(ev) { (this.listeners[ev.type] || []).forEach((f) => f(ev)); return true; },
    click() { this.dispatchEvent({ type: "click" }); },
    getAttribute(k) { return this.attrs[k]; }, setAttribute(k, v) { this.attrs[k] = v; },
    replaceChildren() {}, appendChild() {}, remove() {} };
  return n;
}
const nodes = {};
const byId = (id) => (nodes[id] = nodes[id] || node(id));
const sampleBtns = ["cisco", "huawei"].map((v) => { const b = node("s-" + v); b.attrs["data-sample"] = v; return b; });
global.window = { NM_I18N: { empty_input: "EMPTY", request_failed: "FAIL" }, NM_LANG: "en", NM_AI_AVAILABLE: false, isSecureContext: false };
global.Event = function (type) { this.type = type; };
global.document = {
  getElementById: byId,
  querySelectorAll: (sel) => (sel === "[data-sample]" ? sampleBtns : []),
  querySelector: () => ({ value: "rule_only" }),
  addEventListener() {}, createElement: () => node("x"), body: { appendChild() {} },
};
global.sessionStorage = { getItem: () => null, setItem() {} };
global.FormData = function () { this.d = {}; this.append = (k, v) => { this.d[k] = v; }; };
const calls = [];
global.fetch = (url, opts) => {
  calls.push({ url, body: opts && opts.body });
  if (url.includes("/static/samples/")) return Promise.resolve({ ok: true, text: () => Promise.resolve("hostname R1\nvlan 10\n") });
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ coverage_percent: 100, total_lines: 2, supported_lines: 2,
    unsupported_lines: 0, secret_stripped_count: 0, unsupported_items: [] }) });
};
eval(src);
(async () => {
  sampleBtns[0].click();
  if (timing === "wait") await new Promise((r) => setTimeout(r, 10));
  byId(action + "-btn").click();
  await new Promise((r) => setTimeout(r, 30));
  const pre = calls.find((c) => c.url === "/api/" + action);
  console.log("editor value set:", JSON.stringify(byId("editor").value.slice(0, 11)));
  console.log("direction:", byId("direction").value, "| line count:", byId("line-count").textContent);
  console.log(action + " sent:", !!pre, "| config:", pre && JSON.stringify(pre.body.d.config.slice(0, 11)), "| error:", JSON.stringify(byId("error").textContent));
  if (!pre || byId("error").textContent === "EMPTY") process.exit(1);
})();
