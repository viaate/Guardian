// The remote-control-tool caution, on a site like teamviewer.com.
//
//   node test-pages/check-remote.js
//
// It used to remember nothing, so it reappeared on every page of the site and
// after every click that loaded a new one. What a person learns from a warning
// that will not stay dismissed is to click warnings away without reading them,
// which is the exact habit this caution exists to interrupt.
//
// The dismissal is exercised THROUGH THE REAL PATH. The banner handles clicks
// in the capture phase on window and calls stopImmediatePropagation, so a
// listener added to the button never runs. A first attempt at this fix added
// exactly such a listener, and a test that called it directly passed while the
// caution kept coming back in the browser.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
process.chdir(ROOT);

let fails = 0;
const bad = (m) => { fails++; console.log("  FAIL: " + m); };
const ok = (m) => console.log("  ok   " + m);

const man = JSON.parse(fs.readFileSync("manifest.json", "utf8"));

function visit(alreadyAcknowledged) {
  const appended = [];

  function makeEl(tag) {
    const e = {
      tag, children: [], attrs: {}, style: {}, _class: "", _text: "",
      classList: {
        add(c) { e._class = (e._class + " " + c).trim(); },
        remove() {},
        contains(c) { return e._class.split(/\s+/).includes(c); }
      },
      appendChild(c) { e.children.push(c); return c; },
      insertBefore(c) { e.children.push(c); return c; },
      setAttribute(k, v) { e.attrs[k] = v; },
      getAttribute(k) { return k in e.attrs ? e.attrs[k] : null; },
      removeAttribute(k) { delete e.attrs[k]; },
      addEventListener() {},
      remove() {},
      contains() { return false; },
      focus() {},
      getBoundingClientRect() { return { left: 0, top: 0, width: 10, height: 10 }; },
      // Real class matching, so guardianBuildBanner finds the actual buttons.
      querySelector(sel) {
        const want = sel.replace(/^\./, "").split(",")[0].trim();
        const walk = (n) => {
          for (const c of n.children) {
            if (c._class && c._class.split(/\s+/).includes(want)) return c;
            const found = walk(c);
            if (found) return found;
          }
          return null;
        };
        return walk(e);
      },
      querySelectorAll() { return []; },
      closest() { return null; },
      get className() { return e._class; },
      set className(v) { e._class = v; },
      get textContent() { return e._text; },
      set textContent(v) { e._text = v; },
      get innerText() { return e._text; },
      set innerText(v) { e._text = v; },
      isConnected: true
    };
    return e;
  }

  const root = makeEl("html");
  root.appendChild = (c) => { appended.push(c); return c; };
  const doc = {
    documentElement: root, body: makeEl("body"), head: makeEl("head"),
    title: "TeamViewer", createElement: makeEl,
    querySelector: () => null, querySelectorAll: () => [], addEventListener() {},
    appendChild(c) { appended.push(c); return c; }
  };

  const session = {};
  if (alreadyAcknowledged) session["guardian-remote-ok"] = "1";

  const ctx = {
    console, URL, navigator: { language: "en" }, document: doc,
    location: {
      protocol: "https:", hostname: "www.teamviewer.com",
      href: "https://www.teamviewer.com/download", hash: ""
    },
    sessionStorage: {
      getItem: (k) => (k in session ? session[k] : null),
      setItem(k, v) { session[k] = v; }
    },
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    getComputedStyle: () => ({ visibility: "visible", display: "block", opacity: "1" }),
    ResizeObserver: function () { this.observe = () => {}; },
    MutationObserver: function () { this.observe = () => {}; this.disconnect = () => {}; },
    chrome: {
      runtime: {
        id: "x", lastError: null,
        sendMessage: (m, cb) => { if (cb) cb(undefined); },
        onMessage: { addListener() {} },
        getURL: (p) => "chrome-extension://x/" + p
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
      return { count: 0, session, dismiss: null };
    }
  }

  const banner = appended[0] || null;
  const dismiss = banner ? banner.querySelector(".guardian-btn-secondary") : null;
  return { count: appended.length, session, dismiss };
}

const first = visit(false);
first.count > 0 ? ok("a first visit to teamviewer.com shows the caution")
                : bad("the caution never appeared");

if (!first.dismiss) {
  bad("the caution has no dismiss button");
} else if (typeof first.dismiss.__guardianRun !== "function") {
  bad("the dismiss button has no action attached");
} else {
  // Exactly what the banner's capture-phase click handler calls.
  try {
    first.dismiss.__guardianRun();
  } catch (e) {
    bad("dismissing threw: " + e.message);
  }
  first.session["guardian-remote-ok"] === "1"
    ? ok("pressing continue records the acknowledgement")
    : bad("pressing continue recorded nothing, so the caution will come back");
}

const later = visit(true);
later.count === 0 ? ok("later pages on the same site stay quiet")
                  : bad("the caution came back after being dismissed (" + later.count + ")");

console.log(fails === 0 ? "PASS - the remote-tool caution asks once per visit"
                        : "FAIL (" + fails + ")");
process.exit(fails === 0 ? 0 : 1);
