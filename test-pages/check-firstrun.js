// The very first minutes of a brand-new install.
//
//   node test-pages/check-firstrun.js
//
// Nothing else covers this, and it is the state every single person starts in:
// chrome.storage completely empty, no feed downloaded yet, and - on a laptop
// opened at the wrong moment - no internet either. Every set the worker keeps
// in memory is null until something fills it, and a check arriving in that
// window used to read straight through one of them.
//
// The second half runs the same messages with storage failing outright. That
// is not a hypothetical: a handler whose promise rejects never calls
// sendResponse, the message port stays open, and whoever asked waits forever.
// That is exactly what "the AI checker just loads forever" looked like from
// the outside, so every handler is required to answer even when everything
// underneath it is broken.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
let fails = 0;
const bad = (m) => { fails++; console.log("  FAIL: " + m); };
const ok = (m) => console.log("  ok   " + m);

// A promise that rejects with nothing to catch it IS the failure being hunted:
// in the worker it means sendResponse was never reached. Reported as a normal
// failure rather than a stack trace, so what broke is readable.
process.on("unhandledRejection", (e) => {
  bad("a handler rejected with nothing to catch it: " +
      String((e && e.message) || e));
});

// Every message a content script or the popup actually sends.
const MESSAGES = [
  { type: "checkUrl", href: "https://example.com/", hostname: "example.com" },
  { type: "checkHosts", urls: ["https://example.com/"] },
  { type: "checkUrlsEach", urls: ["https://example.com/a", "not a url", "javascript:1"] },
  { type: "aiCheck", title: "t", text: "x", hostname: "example.com" },
  { type: "portalStatus" },
  { type: "reportScam", hostname: "bad.example" },
  { type: "withdrawReport", hostname: "bad.example" },
  { type: "clearDismissals" },
  { type: "reportMistake", hostname: "x.example" },
  { type: "adOptOut", hostname: "x.example" },
  { type: "scamDetected", hostname: "bad.example", score: 9, text: "x", source: "website" }
];

function makeWorker({ storageFails }) {
  const store = {};
  const explode = () => { throw new Error("storage unavailable"); };
  const ctx = {
    console: { log() {}, warn() {}, error() {} },
    URL, URLSearchParams, structuredClone, AbortController,
    Promise, Date, Math, JSON, Object, Set, Map, Array, String, Number, RegExp, Error,
    setTimeout, clearTimeout, setInterval: () => 0, clearInterval() {},
    fetch: async () => { throw new Error("offline"); },
    chrome: {
      runtime: {
        id: "x", lastError: null, getURL: (p) => p,
        getPlatformInfo: (cb) => cb({}),
        onMessage: { addListener: (f) => { ctx.__msg = f; } },
        onInstalled: { addListener: (f) => { ctx.__install = f; } },
        onStartup: { addListener() {} }, onConnect: { addListener() {} }
      },
      storage: {
        local: {
          get: storageFails ? async () => explode() : async (k) => {
            const keys = Array.isArray(k) ? k : [k];
            const out = {};
            for (const n of keys) if (n in store) out[n] = store[n];
            return out;
          },
          set: storageFails ? async () => explode() : async (o) => { Object.assign(store, o); },
          remove: async () => {}
        },
        session: { get: async () => ({}), set: async () => {}, remove: async () => {} }
      },
      alarms: { create() {}, onAlarm: { addListener() {} } },
      tabs: {
        query: async () => [], sendMessage: async () => {},
        onRemoved: { addListener() {} }, onUpdated: { addListener() {} }, create() {}
      },
      action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setTitle() {} },
      notifications: { create() {}, onClicked: { addListener() {} } },
      scripting: { executeScript: async () => [] },
      webNavigation: { onCommitted: { addListener() {} } },
      declarativeNetRequest: { updateDynamicRules: async () => {} }
    }
  };
  ctx.self = ctx;
  ctx.globalThis = ctx;
  ctx.importScripts = function () {
    for (const a of arguments) {
      vm.runInContext(fs.readFileSync(path.join(ROOT, String(a)), "utf8"), ctx,
        { filename: String(a) });
    }
  };
  vm.createContext(ctx);
  vm.runInContext(fs.readFileSync(path.join(ROOT, "background.js"), "utf8"), ctx,
    { filename: "background.js" });
  return ctx;
}

// An answer, or a timeout standing in for the caller waiting forever.
function ask(ctx, msg) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; resolve({ hung: true }); }
    }, 2000);
    const kept = ctx.__msg(msg, { tab: { id: 1 }, url: "https://example.com" }, (v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ value: v });
    });
    // A handler that does not keep the port open must not be waited on.
    if (kept !== true && !settled) {
      settled = true;
      clearTimeout(timer);
      resolve({ sync: true });
    }
  });
}

(async () => {
  // --- a clean, empty, offline install ------------------------------------
  let ctx;
  try {
    ctx = makeWorker({ storageFails: false });
    ok("the worker loads with completely empty storage");
  } catch (e) {
    bad("the worker threw on load: " + e.message);
    console.log("FAIL (" + fails + ")");
    process.exit(1);
  }

  try {
    await ctx.__install();
    ok("installing with no internet does not throw");
  } catch (e) {
    bad("the install handler threw while offline: " + e.message);
  }

  for (const msg of MESSAGES) {
    const r = await ask(ctx, msg);
    if (r.hung) bad(msg.type + " never answered on a fresh install");
  }
  if (!fails) ok("all " + MESSAGES.length + " messages answer before any feed exists");

  // Nothing may be judged a scam when the blocklist is empty.
  const empty = await ask(ctx, {
    type: "checkUrl", href: "https://example.com/", hostname: "example.com"
  });
  if (empty.value && empty.value.blocked) {
    bad("an ordinary site was reported blocked with an empty blocklist");
  } else {
    ok("an ordinary site is not blocked before the feeds arrive");
  }

  // --- the same, with storage broken underneath ----------------------------
  const broken = makeWorker({ storageFails: true });
  let hung = 0;
  for (const msg of MESSAGES) {
    const r = await ask(broken, msg);
    if (r.hung) { hung++; bad(msg.type + " left the caller waiting when storage failed"); }
  }
  if (!hung) ok("every message still answers when storage fails outright");

  console.log(fails === 0
    ? "PASS - a new install works from the first second, and nothing can hang"
    : "FAIL (" + fails + ")");
  process.exit(fails === 0 ? 0 : 1);
})();
