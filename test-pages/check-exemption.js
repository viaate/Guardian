// The practice-page exemption must not be an off switch for the web.
//
//   node test-pages/check-exemption.js
//
// Guardian skips its own practice page, which is deliberately full of scam
// wording. That exemption is keyed to a marker in the page AND to the file://
// protocol. If the protocol condition were ever dropped, any scam site could
// paste one meta tag and switch Guardian off completely.
//
// A control case runs first: the same page WITHOUT the marker must be flagged.
// Without that, a test like this passes for the wrong reason - the page simply
// not scoring - and proves nothing at all.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
process.chdir(ROOT);
const man = JSON.parse(fs.readFileSync("manifest.json", "utf8"));

let fails = 0;
const bad = (m) => { fails++; console.log("  FAIL: " + m); };
const ok = (m) => console.log("  ok   " + m);

const SCAM_TEXT =
  "Your computer is infected with a virus. Windows Defender detected malware. " +
  "Call Microsoft support now on 1-800-555-0142 immediately. " +
  "Do not turn off your computer.";

function makeEl() {
  const e = {
    children: [], style: {}, attrs: {}, _text: "", _inner: "",
    classList: { add() {}, remove() {}, contains: () => false },
    appendChild(c) { e.children.push(c); return c; },
    setAttribute() {}, getAttribute: () => null, removeAttribute() {},
    addEventListener() {}, remove() {}, contains: () => false, focus() {},
    querySelector: () => null, querySelectorAll: () => [], closest: () => null,
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 10, height: 10 }),
    get textContent() { return e._text; }, set textContent(v) { e._text = v; },
    get className() { return ""; }, set className(v) {},
    get innerText() { return e._inner; }, set innerText(v) { e._inner = v; }
  };
  return e;
}

async function run(protocol, hasMarker) {
  let flagged = false;
  const body = makeEl();
  body.innerText = SCAM_TEXT;
  const doc = {
    documentElement: makeEl(), body, head: makeEl(), title: "Virus detected",
    createElement: makeEl,
    querySelector: (sel) =>
      sel.includes("guardian-practice") && hasMarker ? { content: "1" } : null,
    querySelectorAll: () => [], addEventListener() {}, appendChild() {}
  };
  const ctx = {
    console, URL, navigator: { language: "en" }, document: doc,
    location: {
      protocol,
      hostname: protocol === "file:" ? "" : "scam-example.top",
      href: protocol + "//scam-example.top/", hash: ""
    },
    sessionStorage: { getItem: () => null, setItem() {} },
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    getComputedStyle: () => ({ visibility: "visible", display: "block", opacity: "1" }),
    ResizeObserver: function () { this.observe = () => {}; },
    MutationObserver: function () { this.observe = () => {}; this.disconnect = () => {}; },
    chrome: {
      runtime: {
        id: "x", lastError: null,
        sendMessage: (m, cb) => {
          if (m && m.type === "scamDetected") flagged = true;
          if (cb) cb(undefined);
        },
        onMessage: { addListener() {} }, getURL: (p) => "x/" + p
      },
      storage: { local: { get: async () => ({}) } }
    }
  };
  ctx.window = ctx; ctx.window.top = ctx; ctx.window.self = ctx;
  ctx.window.addEventListener = () => {};
  ctx.window.removeEventListener = () => {};
  vm.createContext(ctx);

  for (const f of man.content_scripts[0].js) {
    try {
      vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
    } catch (e) {
      bad("threw in " + f + ": " + e.message);
      return false;
    }
  }
  // The content script is an async function: it awaits a storage read before
  // it scans anything. Checking immediately reads the answer before the work.
  for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
  return flagged;
}

(async () => {
  const control = await run("https:", false);
  control
    ? ok("a scam website with no marker is flagged (the test is valid)")
    : bad("the control page was not flagged, so this test proves nothing");

  const claimed = await run("https:", true);
  claimed
    ? ok("a website claiming to be a lesson is STILL flagged")
    : bad("the marker switched Guardian off on a live website");

  const lesson = await run("file:", true);
  lesson
    ? bad("the local practice page is being covered by a warning")
    : ok("the local practice page is left alone");

  console.log(fails === 0 ? "PASS - the exemption works locally and cannot be claimed by a website"
                          : "FAIL (" + fails + ")");
  process.exit(fails === 0 ? 0 : 1);
})();
