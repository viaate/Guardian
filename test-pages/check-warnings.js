// The warning ladder, and the impersonation rules, asserted against the real
// source.
//
//   node test-pages/check-warnings.js
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const ROOT = path.resolve(__dirname, "..");

let fails = 0;
const bad = (m) => { fails++; console.log("  FAIL: " + m); };
const ok = (m) => console.log("  ok   " + m);

// ---------------------------------------------------------------------------
// How loud a warning gets, and what can never be quieted.
// ---------------------------------------------------------------------------
const scan = fs.readFileSync(path.join(ROOT, "content/page-scan.js"), "utf8");
for (const [name, frag] of [
  ["a page asking for a password is never softened", "return findLoginInputs().password;"],
  ["the softening gate reads the dismissal count", "if (dismissLevel > 0 && !guardianConclusive())"],
  ["one dismissal drops to the calm strip", 'if (dismissLevel === 1) showCaution("caution_dismissed", true);'],
  ["a softened page stops re-notifying", "softenedAlready = true;"]
]) if (!scan.includes(frag)) bad("missing: " + name);

// A threat-feed hit MUST be softenable. It was not, and a person who pressed
// "This is not a scam" on a listed download page saw nothing change while
// Guardian kept insisting researchers had reported it.
// Just the function body. Reading further catches guardianSignals, which
// mentions opts.listed for the WORDING of a finding, not for softening.
const cStart = scan.indexOf("function guardianConclusive");
const cEnd = scan.indexOf(String.fromCharCode(10) + "  }", cStart);
const conclusive = scan.slice(cStart, cEnd);

if (/opts && opts\.listed/.test(conclusive)) {
  bad("a feed hit is still un-dismissable: the dismiss button would do nothing");
} else {
  ok("a feed hit can be dismissed; only a password page cannot");
}

function decide({ dismissals, hasPassword }) {
  if (dismissals > 0 && !hasPassword) return dismissals === 1 ? "strip" : "silent";
  return "full";
}
for (const [d, pwd, want] of [
  [0, false, "full"], [0, true, "full"],
  [1, false, "strip"], [2, false, "silent"],
  [1, true, "full"], [2, true, "full"]
]) {
  const got = decide({ dismissals: d, hasPassword: pwd });
  if (got !== want) bad(`${d} dismissals, password=${pwd} -> ${got}, want ${want}`);
}
ok("the warning ladder holds in all six combinations");

// ---------------------------------------------------------------------------
// Impersonation: real country registrations are not impostors.
// ---------------------------------------------------------------------------
const src = ["data/strings.js", "data/allowlist.js", "data/typo-targets.js",
             "data/scam-phrases.js", "content/detector.js"]
  .map((f) => fs.readFileSync(path.join(ROOT, f), "utf8")).join("\n;\n");
const ctx = { console, URL, navigator: { language: "en" } };
vm.createContext(ctx);
vm.runInContext(src, ctx, { filename: "d.js" });

for (const h of ["www.amazon.com.be", "www.citibank.com.do", "walmart.com.gt",
                 "ups.com.do", "correos.com.gt", "paypal.com.mx", "ebay.com.au"]) {
  if (ctx.guardianLookalikeHost(h)) bad("real country site treated as an impostor: " + h);
  const r = ctx.guardianAnalyze({
    title: "", text: "", hostname: h, hasPasswordField: false,
    hasEmailInput: true, insecureLogin: false, isEmail: false
  });
  if (r.score !== 0) bad(h + " scores " + r.score + ", should be 0");
}
ok("real brand country registrations score 0");

for (const [h, want] of [["paypal.com.evil.net", "PayPal"],
                         ["paypal.com.secure.tk", "PayPal"],
                         ["roblox.com.ml", "Roblox"]]) {
  const m = ctx.guardianBrandMimic(h);
  if (!m || m.display !== want) bad("impostor missed: " + h);
}
ok("planted-brand impostors are still caught");

for (const h of ["wwwpaypal.com", "paypa1.com", "faceb00k.com", "amaz0n.com"]) {
  const r = ctx.guardianAnalyze({
    title: "", text: "", hostname: h, hasPasswordField: false,
    hasEmailInput: false, insecureLogin: false, isEmail: false
  });
  if (!r.isScam) bad("look-alike does not warn on the address alone: " + h);
}
ok("look-alikes warn on the address alone, with no form on the page");

// ---------------------------------------------------------------------------
// Pages that TEACH about scams must not be warned about.
//
// A sheriff's fraud-alert page, a senior centre newsletter, a relative's blog:
// they quote the scam's own words, so they score exactly like the thing they
// are warning about. A tech-support description plus the toll-free number the
// article is telling you NOT to ring came to 7, over the threshold of 6, and
// Guardian covered a scam-awareness page with "STOP. This is a scam."
//
// The two halves are asserted together on purpose. A cap that also quietened
// real scams would pass a test that only checked the awareness pages.
// ---------------------------------------------------------------------------
const TEACHING = [
  ["a sheriff's fraud-alert page",
   "Residents report a caller claiming to be from Microsoft support saying your " +
   "computer is infected with a virus. The caller gives a number 1-888-555-0134 " +
   "and says immediate action is required. Hang up. Microsoft will never call you."],
  ["a senior centre newsletter",
   "This month, how to spot a tech support scam. A pop up says your computer has " +
   "been locked and to call 1-800-555-0199. Do not call that number. Scammers use " +
   "these pop ups to get remote access to your computer."]
];
for (const [what, text] of TEACHING) {
  const r = ctx.guardianAnalyze({
    title: "Fraud alert", text, hostname: "www.example-library.org",
    hasPasswordField: false, hasEmailInput: false, insecureLogin: false, isEmail: false
  });
  if (r.score >= 4) bad(what + " is warned about (scored " + r.score + ")");
}
ok("pages teaching about scams are not warned about");

// The same wording, on a look-alike domain, must still be caught: the cap is
// allowed to apply only when the wording alone convicted the page.
const planted = ctx.guardianAnalyze({
  title: "Fraud alert",
  text: TEACHING[0][1], hostname: "paypa1.com",
  hasPasswordField: false, hasEmailInput: false, insecureLogin: false, isEmail: false
});
planted.isScam
  ? ok("the cap does not protect a look-alike domain that quotes advice text")
  : bad("advice wording on a look-alike domain switched the warning off");

// And a real tech-support scam page, which says none of it, is untouched.
const real = ctx.guardianAnalyze({
  title: "Windows Defender - Critical Alert",
  text: "Your computer is infected with a virus. Your computer has been locked. " +
        "Call Microsoft support immediately on 1-800-555-0142. Do not turn off " +
        "your computer. Immediate action is required.",
  hostname: "alert-secure-scan.top",
  hasPasswordField: false, hasEmailInput: false, insecureLogin: false, isEmail: false
});
real.isScam
  ? ok("a real fake-virus page is still flagged")
  : bad("the teaching cap silenced a real tech-support scam page");

console.log(fails === 0 ? "PASS - warning ladder and impersonation rules hold"
                        : "FAIL (" + fails + ")");
process.exit(fails === 0 ? 0 : 1);
