// Structural checks on the popup and the warning banner.
//
//   node test-pages/check-ui.js
//
// These assert shape, not detection: one action button whose label and effect
// match the state of the site, a button flow that always reaches an answer,
// and warning UI that a keyboard or screen-reader user can actually use.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const read = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
const js = read("popup/popup.js");
const html = read("popup/popup.html");
const str = read("data/strings.js");
const det = read("content/detector.js");
const css = read("banner/banner.css");

let fails = 0;
const bad = (m) => { fails++; console.log("FAIL: " + m); };

// --- the popup's single action button ---------------------------------------
const buttons = (html.match(/<button/g) || []).length;
if (buttons !== 2) bad("expected 2 buttons (the check + one action), found " + buttons);
if (html.includes("quiet-undo")) bad("a second action button is back");

for (const [name, frag] of [
  ["state helper", "async function guardianSiteState"],
  ["quiet label", "popup_quiet_undo"],
  ["reported label", "popup_report_undo"],
  ["neutral label", 'guardianT("popup_report")'],
  ["quiet undo clears the dismissal", 'type: "clearDismissals"'],
  ["reported undo WITHDRAWS the report", 'type: "withdrawReport"'],
  ["neutral action reports", 'type: "reportScam"']
]) if (!js.includes(frag)) bad("missing " + name);

// Withdrawing a report must not also record a dismissal, or undoing a report
// leaves the site quieter than one that was never reported.
const reportedBranch = js.slice(js.indexOf('if (siteState === "reported")'),
                                js.indexOf('await chrome.runtime.sendMessage({ type: "reportScam"'));
if (reportedBranch.includes('"reportMistake"')) {
  bad("withdrawing a report still records a dismissal");
}

// --- the button always answers ---------------------------------------------
const handler = js.slice(js.indexOf("checkBtn.addEventListener"), js.indexOf("// Report this page as a scam"));
if (!handler.includes("const direct = await guardianCollectDirect")) bad("does not read the page directly");
// In the MAIN flow (after the trusted-host branch, which legitimately asks the
// page first) the direct read must come before the content-script question.
const mainFlow = handler.slice(handler.indexOf("// Reported-scam blocklist."));
if (mainFlow.indexOf("guardianCollectDirect") > mainFlow.indexOf("guardianAskPage")) {
  bad("asks the content script before reading the page");
}
if (!handler.includes("} catch (e) {")) bad("no outer catch: an error leaves the button spinning");
if (/sendMessage\([^)]*,\s*async \(/.test(handler)) bad("an async callback outside the try/catch");
if ((handler.match(/return (showAnswer|verdict)\(/g) || []).length < 8) bad("some path may not answer");
if (!js.includes("const WARNINGS = new Set")) bad("the quiet state is not limited to warnings");

// A trusted host must still be asked about before being called safe: Gmail is
// on the trusted list and the open message is the whole question.
const allowBranch = handler.slice(handler.indexOf("guardianIsAllowlisted(host)"));
if (!allowBranch.slice(0, 400).includes("guardianAskPage")) {
  bad("a trusted host answers OK without looking at the page");
}

// guardianAskPage must never hang or throw
const ask = js.slice(js.indexOf("function guardianAskPage"), js.indexOf("async function guardianCollectDirect"));
if (!ask.includes("setTimeout")) bad("guardianAskPage can hang on a dead tab");
if (!ask.includes("try {")) bad("guardianAskPage can throw on a stale context");

// --- the warning banner is usable without a mouse --------------------------
for (const [name, frag] of [
  ["dialog role", 'setAttribute("role", "dialog")'],
  ["modal semantics", 'aria-modal'],
  ["labelled by its heading", "aria-labelledby"],
  ["focus moved into the warning", ".focus("],
  ["keyboard is kept inside", '"Tab"']
]) if (!det.includes(frag)) bad("warning banner: missing " + name);

// ...and readable when the text is large or the screen is small
if (!/\.guardian-banner\s*{[^}]*overflow-y:\s*auto/s.test(css)) {
  bad("warning banner cannot scroll: on a small screen the exit button is unreachable");
}

// --- strings exist in both languages ---------------------------------------
const ctx = { console, navigator: { language: "en" } };
vm.createContext(ctx);
vm.runInContext(str + "\nglobalThis.EN=GUARDIAN_STRINGS.en;globalThis.ES=GUARDIAN_STRINGS.es;", ctx, { filename: "s.js" });
for (const m of js.match(/guardianT\(\s*"([a-z0-9_]+)"/g) || []) {
  const k = m.match(/"([a-z0-9_]+)"/)[1];
  if (!k.endsWith("_") && !(k in ctx.EN)) bad("popup uses a missing string: " + k);
}

// Per-press state must be cleared, or one page's findings appear under the
// next page's answer.
const press = js.slice(js.indexOf("checkBtn.addEventListener"), js.indexOf("async function guardianDoReportAction"));
if (!/guardianAnswerSignals = \[\]/.test(press)) bad("findings are not cleared between presses");
if (!/guardianCantReason = ""/.test(press)) bad("the failure reason is not cleared between presses");

console.log(fails === 0 ? "PASS - popup and warning UI are structurally sound"
                        : "FAIL (" + fails + ")");
process.exit(fails === 0 ? 0 : 1);
